//! A library for running a USB/IP server

use futures::stream::StreamExt;
use log::*;
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use rusb::*;
use std::any::Any;
use std::collections::{HashMap, VecDeque};
use std::io::Result;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

pub mod cdc;
mod consts;
mod device;
mod endpoint;
pub mod hid;
mod host;
mod interface;
mod setup;
mod util;
pub use consts::*;
pub use device::*;
pub use endpoint::*;
pub use host::*;
pub use interface::*;
pub use setup::*;
pub use util::*;

/// Main struct of a USB/IP server
pub struct UsbIpServer {
    devices: Vec<UsbDevice>,
}

impl UsbIpServer {
    /// Create a [UsbIpServer] with simulated devices
    pub fn new_simulated(devices: Vec<UsbDevice>) -> Self {
        Self { devices }
    }

    /// Create a [UsbIpServer] exposing devices in the host, and redirect all USB transfers to them using libusb
    pub fn new_from_host() -> Self {
        let mut devices = vec![];
        if let Ok(list) = rusb::devices() {
            for dev in list.iter() {
                let handle = Arc::new(Mutex::new(dev.open().unwrap()));
                let desc = dev.device_descriptor().unwrap();
                let cfg = dev.active_config_descriptor().unwrap();
                let mut interfaces = vec![];
                handle
                    .lock()
                    .unwrap()
                    .set_auto_detach_kernel_driver(true)
                    .ok();
                for intf in cfg.interfaces() {
                    // ignore alternate settings
                    let intf_desc = intf.descriptors().next().unwrap();
                    handle
                        .lock()
                        .unwrap()
                        .claim_interface(intf_desc.interface_number())
                        .ok();
                    let mut endpoints = vec![];

                    for ep_desc in intf_desc.endpoint_descriptors() {
                        endpoints.push(UsbEndpoint {
                            address: ep_desc.address(),
                            attributes: ep_desc.transfer_type() as u8,
                            max_packet_size: ep_desc.max_packet_size(),
                            interval: ep_desc.interval(),
                        });
                    }

                    let handler =
                        Arc::new(Mutex::new(Box::new(UsbHostHandler::new(handle.clone()))
                            as Box<dyn UsbInterfaceHandler + Send>));
                    interfaces.push(UsbInterface {
                        interface_class: intf_desc.class_code(),
                        interface_subclass: intf_desc.sub_class_code(),
                        interface_protocol: intf_desc.protocol_code(),
                        endpoints,
                        string_interface: intf_desc.description_string_index().unwrap_or(0),
                        class_specific_descriptor: Vec::from(intf_desc.extra().unwrap_or(&[])),
                        handler,
                    });
                }
                let mut device = UsbDevice {
                    path: format!(
                        "/sys/bus/{}/{}/{}",
                        dev.bus_number(),
                        dev.address(),
                        dev.port_number()
                    ),
                    bus_id: format!(
                        "{}-{}-{}",
                        dev.bus_number(),
                        dev.address(),
                        dev.port_number()
                    ),
                    bus_num: dev.bus_number() as u32,
                    dev_num: dev.port_number() as u32,
                    speed: dev.speed() as u32,
                    vendor_id: desc.vendor_id(),
                    product_id: desc.product_id(),
                    device_class: desc.class_code(),
                    device_subclass: desc.sub_class_code(),
                    device_protocol: desc.protocol_code(),
                    configuration_value: cfg.number(),
                    num_configurations: desc.num_configurations(),
                    ep0_in: UsbEndpoint {
                        address: 0x80,
                        attributes: EndpointAttributes::Control as u8,
                        max_packet_size: desc.max_packet_size() as u16,
                        interval: 0,
                    },
                    ep0_out: UsbEndpoint {
                        address: 0x00,
                        attributes: EndpointAttributes::Control as u8,
                        max_packet_size: desc.max_packet_size() as u16,
                        interval: 0,
                    },
                    interfaces,
                    ..UsbDevice::default()
                };

                // set strings
                if let Some(index) = desc.manufacturer_string_index() {
                    device.string_manufacturer = device.new_string(
                        &handle
                            .lock()
                            .unwrap()
                            .read_string_descriptor_ascii(index)
                            .unwrap(),
                    )
                }
                if let Some(index) = desc.product_string_index() {
                    device.string_product = device.new_string(
                        &handle
                            .lock()
                            .unwrap()
                            .read_string_descriptor_ascii(index)
                            .unwrap(),
                    )
                }
                if let Some(index) = desc.serial_number_string_index() {
                    device.string_serial = device.new_string(
                        &handle
                            .lock()
                            .unwrap()
                            .read_string_descriptor_ascii(index)
                            .unwrap(),
                    )
                }
                devices.push(device);
            }
        }
        Self { devices }
    }
}

async fn handler<T: AsyncReadExt + AsyncWriteExt + Unpin>(
    mut socket: &mut T,
    server: Arc<UsbIpServer>,
) -> Result<()> {
    let mut current_import_device = None;
    loop {
        let mut command = [0u8; 4];
        socket.read_exact(&mut command).await?;
        match command {
            [0x01, 0x11, 0x80, 0x05] => {
                debug!("Got OP_REQ_DEVLIST");
                let _status = socket.read_u32().await?;

                // OP_REP_DEVLIST
                socket.write_u32(0x01110005).await?;
                socket.write_u32(0).await?;
                socket.write_u32(server.devices.len() as u32).await?;
                for dev in &server.devices {
                    dev.write_dev_with_interfaces(&mut socket).await?;
                }
                debug!("Sent OP_REP_DEVLIST");
            }
            [0x01, 0x11, 0x80, 0x03] => {
                debug!("Got OP_REQ_IMPORT");
                let _status = socket.read_u32().await?;
                let mut bus_id = [0u8; 32];
                socket.read_exact(&mut bus_id).await?;
                current_import_device = None;
                for device in &server.devices {
                    let mut expected = device.bus_id.as_bytes().to_vec();
                    expected.resize(32, 0);
                    if expected == bus_id {
                        current_import_device = Some(device);
                        info!("Found device {:?}", device.path);
                        break;
                    }
                }

                // OP_REP_IMPORT
                debug!("Sent OP_REP_IMPORT");
                socket.write_u32(0x01110003).await?;
                if let Some(dev) = current_import_device {
                    socket.write_u32(0).await?;
                    dev.write_dev(&mut socket).await?;
                } else {
                    socket.write_u32(1).await?;
                }
            }
            [0x00, 0x00, 0x00, 0x01] => {
                debug!("Got USBIP_CMD_SUBMIT");
                let seq_num = socket.read_u32().await?;
                let dev_id = socket.read_u32().await?;
                let direction = socket.read_u32().await?;
                let ep = socket.read_u32().await?;
                let _transfer_flags = socket.read_u32().await?;
                let transfer_buffer_length = socket.read_u32().await?;
                let _start_frame = socket.read_u32().await?;
                let _number_of_packets = socket.read_u32().await?;
                let _interval = socket.read_u32().await?;
                let mut setup = [0u8; 8];
                socket.read_exact(&mut setup).await?;
                let device = current_import_device.unwrap();
                let real_ep = if direction == 0 { ep } else { ep | 0x80 };
                let (usb_ep, intf) = device.find_ep(real_ep as u8).unwrap();
                debug!("->Endpoint {:02x?}", usb_ep);
                debug!("->Setup {:02x?}", setup);
                let resp = device
                    .handle_urb(socket, usb_ep, intf, transfer_buffer_length, setup)
                    .await?;
                debug!("<-Resp {:02x?}", resp);

                // USBIP_RET_USBMIT
                // command
                socket.write_u32(0x3).await?;
                socket.write_u32(seq_num).await?;
                socket.write_u32(dev_id).await?;
                socket.write_u32(direction).await?;
                socket.write_u32(ep).await?;
                // status
                socket.write_u32(0).await?;
                // actual length
                socket.write_u32(resp.len() as u32).await?;
                // start frame
                socket.write_u32(0).await?;
                // number of packets
                socket.write_u32(0).await?;
                // error count
                socket.write_u32(0).await?;
                // setup
                socket.write_all(&setup).await?;
                // data
                socket.write_all(&resp).await?;
            }
            [0x00, 0x00, 0x00, 0x02] => {
                debug!("Got USBIP_CMD_UNLINK");
            }
            _ => warn!("Got unknown command {:?}", command),
        }
    }
}

/// Spawn a USB/IP server at `addr` using [TcpListener]
pub async fn server(addr: SocketAddr, server: UsbIpServer) {
    let mut listener = TcpListener::bind(addr).await.expect("bind to addr");

    let server = async move {
        let usbip_server = Arc::new(server);
        let mut incoming = listener.incoming();
        while let Some(socket_res) = incoming.next().await {
            match socket_res {
                Ok(mut socket) => {
                    info!("Got connection from {:?}", socket.peer_addr());
                    let new_server = usbip_server.clone();
                    tokio::spawn(async move {
                        let res = handler(&mut socket, new_server).await;
                        info!("Handler ended with {:?}", res);
                    });
                }
                Err(err) => {
                    warn!("Got error {:?}", err);
                }
            }
        }
    };

    server.await
}

#[cfg(test)]
mod test {
    use super::*;

    #[tokio::test]
    async fn req_empty_devlist() {
        let server = UsbIpServer { devices: vec![] };

        // OP_REQ_DEVLIST
        let mut mock_socket = MockSocket::new(vec![0x01, 0x11, 0x80, 0x05, 0x00, 0x00, 0x00, 0x00]);
        handler(&mut mock_socket, Arc::new(server)).await.ok();
        // OP_REP_DEVLIST
        assert_eq!(
            mock_socket.output,
            [0x01, 0x11, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        );
    }

    #[tokio::test]
    async fn req_sample_devlist() {
        let intf_handler = Arc::new(Mutex::new(
            Box::new(cdc::UsbCdcAcmHandler::new()) as Box<dyn UsbInterfaceHandler + Send>
        ));
        let server = UsbIpServer {
            devices: vec![UsbDevice::new(0).with_interface(
                ClassCode::CDC as u8,
                cdc::CDC_ACM_SUBCLASS,
                0x00,
                "Test CDC ACM",
                cdc::UsbCdcAcmHandler::endpoints(),
                intf_handler.clone(),
            )],
        };

        // OP_REQ_DEVLIST
        let mut mock_socket = MockSocket::new(vec![0x01, 0x11, 0x80, 0x05, 0x00, 0x00, 0x00, 0x00]);
        handler(&mut mock_socket, Arc::new(server)).await.ok();
        // OP_REP_DEVLIST
        // header: 0xC
        // device: 0x138
        // interface: 4 * 0x1
        assert_eq!(mock_socket.output.len(), 0xC + 0x138 + 4 * 0x1);
    }

    #[tokio::test]
    async fn req_import() {
        let intf_handler = Arc::new(Mutex::new(
            Box::new(cdc::UsbCdcAcmHandler::new()) as Box<dyn UsbInterfaceHandler + Send>
        ));
        let server = UsbIpServer {
            devices: vec![UsbDevice::new(0).with_interface(
                ClassCode::CDC as u8,
                cdc::CDC_ACM_SUBCLASS,
                0x00,
                "Test CDC ACM",
                cdc::UsbCdcAcmHandler::endpoints(),
                intf_handler.clone(),
            )],
        };

        // OP_REQ_IMPORT
        let mut req = vec![0x01, 0x11, 0x80, 0x03, 0x00, 0x00, 0x00, 0x00];
        let mut path = "0".as_bytes().to_vec();
        path.resize(32, 0);
        req.extend(path);
        let mut mock_socket = MockSocket::new(req);
        handler(&mut mock_socket, Arc::new(server)).await.ok();
        // OP_REQ_IMPORT
        assert_eq!(mock_socket.output.len(), 0x140);
    }

    #[tokio::test]
    async fn req_import_get_device_desc() {
        let intf_handler = Arc::new(Mutex::new(
            Box::new(cdc::UsbCdcAcmHandler::new()) as Box<dyn UsbInterfaceHandler + Send>
        ));
        let server = UsbIpServer {
            devices: vec![UsbDevice::new(0).with_interface(
                ClassCode::CDC as u8,
                cdc::CDC_ACM_SUBCLASS,
                0x00,
                "Test CDC ACM",
                cdc::UsbCdcAcmHandler::endpoints(),
                intf_handler.clone(),
            )],
        };

        // OP_REQ_IMPORT
        let mut req = vec![0x01, 0x11, 0x80, 0x03, 0x00, 0x00, 0x00, 0x00];
        let mut path = "0".as_bytes().to_vec();
        path.resize(32, 0);
        req.extend(path);
        // USBIP_CMD_SUBMIT
        req.extend(vec![
            0x00, 0x00, 0x00, 0x01, // command
            0x00, 0x00, 0x00, 0x01, // seq num
            0x00, 0x00, 0x00, 0x00, // dev id
            0x00, 0x00, 0x00, 0x01, // IN
            0x00, 0x00, 0x00, 0x00, // ep 0
            0x00, 0x00, 0x00, 0x00, // transfer flags
            0x00, 0x00, 0x00, 0x00, // transfer buffer length
            0x00, 0x00, 0x00, 0x00, // start frame
            0x00, 0x00, 0x00, 0x00, // number of packets
            0x00, 0x00, 0x00, 0x00, // interval
            0x80, 0x06, 0x00, 0x01, 0x00, 0x00, 0x40, 0x00, // GetDescriptor to Device
        ]);
        let mut mock_socket = MockSocket::new(req);
        handler(&mut mock_socket, Arc::new(server)).await.ok();
        // OP_REQ_IMPORT + USBIP_CMD_SUBMIT + Device Descriptor
        assert_eq!(mock_socket.output.len(), 0x140 + 0x30 + 0x12);
    }
}
