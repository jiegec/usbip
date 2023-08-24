//! A library for running a USB/IP server

use log::*;
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use rusb::*;
use std::any::Any;
use std::collections::{HashMap, VecDeque};
use std::io::{ErrorKind, Result};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::sync::RwLock;

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
#[derive(Default)]
pub struct UsbIpServer {
    available_devices: RwLock<Vec<UsbDevice>>,
    used_devices: RwLock<HashMap<String, UsbDevice>>,
}

impl UsbIpServer {
    /// Create a [UsbIpServer] with simulated devices
    pub fn new_simulated(devices: Vec<UsbDevice>) -> Self {
        Self {
            available_devices: RwLock::new(devices),
            used_devices: RwLock::new(HashMap::new()),
        }
    }

    fn with_devices(device_list: Vec<Device<GlobalContext>>) -> Vec<UsbDevice> {
        let mut devices = vec![];

        for dev in device_list {
            let open_device = match dev.open() {
                Ok(dev) => dev,
                Err(err) => {
                    warn!("Impossible to share {:?}: {}", dev, err);
                    continue;
                }
            };
            let handle = Arc::new(Mutex::new(open_device));
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
                    .set_auto_detach_kernel_driver(true)
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

                let handler = Arc::new(Mutex::new(Box::new(UsbHostInterfaceHandler::new(
                    handle.clone(),
                ))
                    as Box<dyn UsbInterfaceHandler + Send>));
                interfaces.push(UsbInterface {
                    interface_class: intf_desc.class_code(),
                    interface_subclass: intf_desc.sub_class_code(),
                    interface_protocol: intf_desc.protocol_code(),
                    endpoints,
                    string_interface: intf_desc.description_string_index().unwrap_or(0),
                    class_specific_descriptor: Vec::from(intf_desc.extra()),
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
                device_bcd: desc.device_version().into(),
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
                device_handler: Some(Arc::new(Mutex::new(Box::new(UsbHostDeviceHandler::new(
                    handle.clone(),
                ))))),
                usb_version: desc.usb_version().into(),
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
        devices
    }

    /// Create a [UsbIpServer] exposing devices in the host, and redirect all USB transfers to them using libusb
    pub fn new_from_host() -> Self {
        match rusb::devices() {
            Ok(list) => {
                let mut devs = vec![];
                for d in list.iter() {
                    devs.push(d)
                }
                Self {
                    available_devices: RwLock::new(Self::with_devices(devs)),
                    ..Default::default()
                }
            }
            Err(_) => Default::default(),
        }
    }

    pub fn new_from_host_with_filter<F>(filter: F) -> Self
    where
        F: FnMut(&Device<GlobalContext>) -> bool,
    {
        match rusb::devices() {
            Ok(list) => {
                let mut devs = vec![];
                for d in list.iter().filter(filter) {
                    devs.push(d)
                }
                Self {
                    available_devices: RwLock::new(Self::with_devices(devs)),
                    ..Default::default()
                }
            }
            Err(_) => Default::default(),
        }
    }

    pub async fn add_device(&self, device: UsbDevice) {
        self.available_devices.write().await.push(device);
    }

    pub async fn remove_device(&self, bus_id: &str) -> Result<()> {
        let mut available_devices = self.available_devices.write().await;

        if let Some(device) = available_devices.iter().position(|d| d.bus_id == bus_id) {
            available_devices.remove(device);
            Ok(())
        } else if let Some(device) = self
            .used_devices
            .read()
            .await
            .values()
            .find(|d| d.bus_id == bus_id)
        {
            Err(std::io::Error::new(
                ErrorKind::Other,
                format!("Device {} is in use", device.bus_id),
            ))
        } else {
            Err(std::io::Error::new(
                ErrorKind::NotFound,
                format!("Device {} not found", bus_id),
            ))
        }
    }
}

pub async fn handler<T: AsyncReadExt + AsyncWriteExt + Unpin>(
    mut socket: &mut T,
    server: Arc<UsbIpServer>,
) -> Result<()> {
    let mut current_import_device_id: Option<String> = None;
    loop {
        let mut command = [0u8; 4];
        if let Err(err) = socket.read_exact(&mut command).await {
            if let Some(dev_id) = current_import_device_id {
                let mut used_devices = server.used_devices.write().await;
                let mut available_devices = server.available_devices.write().await;
                match used_devices.remove(&dev_id) {
                    Some(dev) => available_devices.push(dev),
                    None => unreachable!(),
                }
            }

            if err.kind() == ErrorKind::UnexpectedEof {
                info!("Remote closed the connection");
                return Ok(());
            } else {
                return Err(err);
            }
        }

        let used_devices = server.used_devices.read().await;
        let mut current_import_device = current_import_device_id
            .clone()
            .and_then(|ref id| used_devices.get(id));

        match command {
            [0x01, 0x11, 0x80, 0x05] => {
                trace!("Got OP_REQ_DEVLIST");
                let _status = socket.read_u32().await?;

                let devices = server.available_devices.read().await;

                // OP_REP_DEVLIST
                socket.write_u32(0x01110005).await?;
                socket.write_u32(0).await?;
                socket.write_u32(devices.len() as u32).await?;
                for dev in devices.iter() {
                    dev.write_dev_with_interfaces(&mut socket).await?;
                }
                trace!("Sent OP_REP_DEVLIST");
            }
            [0x01, 0x11, 0x80, 0x03] => {
                trace!("Got OP_REQ_IMPORT");
                let _status = socket.read_u32().await?;
                let mut bus_id = [0u8; 32];
                socket.read_exact(&mut bus_id).await?;

                current_import_device_id = None;
                current_import_device = None;
                std::mem::drop(used_devices);

                let mut used_devices = server.used_devices.write().await;
                let mut available_devices = server.available_devices.write().await;
                for (i, dev) in available_devices.iter().enumerate() {
                    let mut expected = dev.bus_id.as_bytes().to_vec();
                    expected.resize(32, 0);
                    if expected == bus_id {
                        let dev = available_devices.remove(i);
                        let dev_id = dev.bus_id.clone();
                        used_devices.insert(dev.bus_id.clone(), dev);
                        current_import_device_id = dev_id.clone().into();
                        current_import_device = Some(used_devices.get(&dev_id).unwrap());
                        break;
                    }
                }

                // OP_REP_IMPORT
                trace!("Sent OP_REP_IMPORT");
                socket.write_u32(0x01110003).await?;
                if let Some(dev) = current_import_device {
                    socket.write_u32(0).await?;
                    dev.write_dev(&mut socket).await?;
                } else {
                    socket.write_u32(1).await?;
                }
            }
            [0x00, 0x00, 0x00, 0x01] => {
                trace!("Got USBIP_CMD_SUBMIT");
                let seq_num = socket.read_u32().await?;
                let _dev_id = socket.read_u32().await?;
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

                let out = direction == 0;
                let real_ep = if out { ep } else { ep | 0x80 };
                // read request data from socket for OUT
                let out_data = if out {
                    let mut data = vec![0u8; transfer_buffer_length as usize];
                    socket.read_exact(&mut data).await?;
                    data
                } else {
                    vec![]
                };

                let (usb_ep, intf) = device.find_ep(real_ep as u8).unwrap();
                trace!("->Endpoint {:02x?}", usb_ep);
                trace!("->Setup {:02x?}", setup);
                trace!("->Request {:02x?}", out_data);
                let resp = device
                    .handle_urb(
                        usb_ep,
                        intf,
                        transfer_buffer_length,
                        SetupPacket::parse(&setup),
                        &out_data,
                    )
                    .await?;

                if out {
                    trace!("<-Resp {:02x?}", resp);
                } else {
                    trace!("<-Wrote {}", out_data.len());
                }

                // USBIP_RET_SUBMIT
                // command
                socket.write_u32(0x3).await?;
                socket.write_u32(seq_num).await?;
                socket.write_u32(0).await?;
                socket.write_u32(0).await?;
                socket.write_u32(0).await?;
                // status
                socket.write_u32(0).await?;

                let actual_length = if out {
                    // In the out endpoint case, the actual_length field should be
                    // same as the data length received in the original URB transaction.
                    // No data bytes are sent
                    transfer_buffer_length
                } else {
                    resp.len() as u32
                };
                // actual_length
                socket.write_u32(actual_length).await?;

                // start frame
                socket.write_u32(0).await?;
                // number of packets
                socket.write_u32(0).await?;
                // error count
                socket.write_u32(0).await?;
                // padding
                let padding = [0u8; 8];
                socket.write_all(&padding).await?;
                // data
                if !out {
                    socket.write_all(&resp).await?;
                }
            }
            [0x00, 0x00, 0x00, 0x02] => {
                trace!("Got USBIP_CMD_UNLINK");
                let seq_num = socket.read_u32().await?;
                let _dev_id = socket.read_u32().await?;
                let _direction = socket.read_u32().await?;
                let _ep = socket.read_u32().await?;
                let _seq_num_submit = socket.read_u32().await?;
                // 24 bytes of struct padding
                let mut padding = [0u8; 6 * 4];
                socket.read_exact(&mut padding).await?;

                std::mem::drop(used_devices);

                let mut used_devices = server.used_devices.write().await;
                let mut available_devices = server.available_devices.write().await;

                let dev = match current_import_device_id
                    .clone()
                    .and_then(|ref k| used_devices.remove(k))
                {
                    Some(dev) => dev,
                    None => unreachable!(),
                };

                available_devices.push(dev);
                current_import_device_id = None;

                // USBIP_RET_UNLINK
                // command
                socket.write_u32(0x4).await?;
                socket.write_u32(seq_num).await?;
                socket.write_u32(0).await?;
                socket.write_u32(0).await?;
                socket.write_u32(0).await?;
                // status
                socket.write_u32(0).await?;
                socket.write_all(&padding).await?;
            }
            _ => warn!("Got unknown command {:?}", command),
        }
    }
}

/// Spawn a USB/IP server at `addr` using [TcpListener]
pub async fn server(addr: SocketAddr, server: Arc<UsbIpServer>) {
    let listener = TcpListener::bind(addr).await.expect("bind to addr");

    let server = async move {
        loop {
            match listener.accept().await {
                Ok((mut socket, _addr)) => {
                    info!("Got connection from {:?}", socket.peer_addr());
                    let new_server = server.clone();
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
    use tokio::{net::TcpStream, task::JoinSet};

    use super::*;
    use crate::util::tests::*;

    fn new_server_with_single_device() -> UsbIpServer {
        UsbIpServer::new_simulated(vec![UsbDevice::new(0).with_interface(
            ClassCode::CDC as u8,
            cdc::CDC_ACM_SUBCLASS,
            0x00,
            "Test CDC ACM",
            cdc::UsbCdcAcmHandler::endpoints(),
            Arc::new(Mutex::new(
                Box::new(cdc::UsbCdcAcmHandler::new()) as Box<dyn UsbInterfaceHandler + Send>
            )),
        )])
    }

    fn op_req_import(bus_id: u32) -> Vec<u8> {
        let mut req = vec![0x01, 0x11, 0x80, 0x03, 0x00, 0x00, 0x00, 0x00];
        let mut path = bus_id.to_string().as_bytes().to_vec();
        path.resize(32, 0);
        req.extend(path);
        req
    }

    async fn attach_device(connection: &mut TcpStream, bus_id: u32) -> u32 {
        let req = op_req_import(bus_id);
        connection.write_all(req.as_slice()).await.unwrap();
        connection.read_u32().await.unwrap();
        let result = connection.read_u32().await.unwrap();
        if result == 0 {
            connection.read_exact(&mut vec![0; 0x138]).await.unwrap();
        }
        result
    }

    #[tokio::test]
    async fn req_empty_devlist() {
        let server = UsbIpServer::new_simulated(vec![]);

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
        let server = new_server_with_single_device();
        // OP_REQ_DEVLIST
        let mut mock_socket = MockSocket::new(vec![0x01, 0x11, 0x80, 0x05, 0x00, 0x00, 0x00, 0x00]);
        handler(&mut mock_socket, Arc::new(server)).await.ok();
        // OP_REP_DEVLIST
        // header: 0xC
        // device: 0x138
        // interface: 4 * 0x1
        assert_eq!(mock_socket.output.len(), 0xC + 0x138 + 4);
    }

    #[tokio::test]
    async fn req_import() {
        let server = new_server_with_single_device();

        // OP_REQ_IMPORT
        let req = op_req_import(0);
        let mut mock_socket = MockSocket::new(req);
        handler(&mut mock_socket, Arc::new(server)).await.ok();
        // OP_REQ_IMPORT
        assert_eq!(mock_socket.output.len(), 0x140);
    }

    #[tokio::test]
    async fn add_and_remove_10_devices() {
        let server_ = Arc::new(UsbIpServer::new_simulated(vec![]));
        let addr = get_free_address().await;
        tokio::spawn(server(addr, server_.clone()));

        let mut join_set = JoinSet::new();
        let devices = (0..10).map(UsbDevice::new).collect::<Vec<_>>();

        for device in devices.iter() {
            let new_server = server_.clone();
            let new_device = device.clone();
            join_set.spawn(async move {
                new_server.add_device(new_device).await;
            });
        }

        for device in devices.iter() {
            let new_server = server_.clone();
            let new_device = device.clone();
            join_set.spawn(async move {
                new_server.remove_device(&new_device.bus_id).await.unwrap();
            });
        }

        while join_set.join_next().await.is_some() {}

        let device_len = server_.clone().available_devices.read().await.len();

        assert_eq!(device_len, 0);
    }

    #[tokio::test]
    async fn send_usb_traffic_while_adding_and_removing_devices() {
        let server_ = Arc::new(new_server_with_single_device());

        let addr = get_free_address().await;
        tokio::spawn(server(addr, server_.clone()));

        let cmd_loop_handle = tokio::spawn(async move {
            let mut connection = poll_connect(addr).await;
            let result = attach_device(&mut connection, 0).await;
            assert_eq!(result, 0);

            let cdc_loopback_bulk_cmd = vec![
                0x00, 0x00, 0x00, 0x01, // command
                0x00, 0x00, 0x00, 0x01, // seq num
                0x00, 0x00, 0x00, 0x00, // dev id
                0x00, 0x00, 0x00, 0x00, // OUT
                0x00, 0x00, 0x00, 0x02, // ep 2
                0x00, 0x00, 0x00, 0x00, // transfer flags
                0x00, 0x00, 0x00, 0x08, // transfer buffer length 8
                0x00, 0x00, 0x00, 0x00, // start frame
                0x00, 0x00, 0x00, 0x00, // number of packets
                0x00, 0x00, 0x00, 0x00, // interval
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Empty setup packet
                0x01, 0x02, 0x03, 0x04, // data
                0x05, 0x06, 0x07, 0x08, // data
            ];
            loop {
                connection
                    .write_all(cdc_loopback_bulk_cmd.as_slice())
                    .await
                    .unwrap();
                let mut result = vec![0; 4 * 12];
                connection.read_exact(&mut result).await.unwrap();
            }
        });

        let add_and_remove_device_handle = tokio::spawn(async move {
            let mut join_set = JoinSet::new();
            let devices = (1..4).map(UsbDevice::new).collect::<Vec<_>>();

            loop {
                for device in devices.iter() {
                    let new_server = server_.clone();
                    let new_device = device.clone();
                    join_set.spawn(async move {
                        new_server.add_device(new_device).await;
                    });
                }

                for device in devices.iter() {
                    let new_server = server_.clone();
                    let new_device = device.clone();
                    join_set.spawn(async move {
                        new_server.remove_device(&new_device.bus_id).await.unwrap();
                    });
                }
                while join_set.join_next().await.is_some() {}
                tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;
            }
        });

        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        cmd_loop_handle.abort();
        add_and_remove_device_handle.abort();
    }

    #[tokio::test]
    async fn only_single_connection_allowed_to_device() {
        let server_ = Arc::new(new_server_with_single_device());

        let addr = get_free_address().await;
        tokio::spawn(server(addr, server_.clone()));

        let mut first_connection = poll_connect(addr).await;
        let mut second_connection = TcpStream::connect(addr).await.unwrap();

        let result = attach_device(&mut first_connection, 0).await;
        assert_eq!(result, 0);

        let result = attach_device(&mut second_connection, 0).await;
        assert_eq!(result, 1);
    }

    #[tokio::test]
    async fn device_gets_released_on_cmd_unlink() {
        let server_ = Arc::new(new_server_with_single_device());

        let addr = get_free_address().await;
        tokio::spawn(server(addr, server_.clone()));

        let mut connection = poll_connect(addr).await;

        let result = attach_device(&mut connection, 0).await;
        assert_eq!(result, 0);

        let unlink_req = vec![
            0x00, 0x00, 0x00, 0x02, // cmd
            0x00, 0x00, 0x00, 0x01, // seq_num
            0x00, 0x00, 0x00, 0x00, // dev_id
            0x00, 0x00, 0x00, 0x00, // direction
            0x00, 0x00, 0x00, 0x00, // ep
            0x00, 0x00, 0x00, 0x00, // seq_num_submit
            0x00, 0x00, 0x00, 0x00, // padding
            0x00, 0x00, 0x00, 0x00, // padding
            0x00, 0x00, 0x00, 0x00, // padding
            0x00, 0x00, 0x00, 0x00, // padding
            0x00, 0x00, 0x00, 0x00, // padding
            0x00, 0x00, 0x00, 0x00, // padding
        ];
        connection.write_all(unlink_req.as_slice()).await.unwrap();
        connection.read_exact(&mut [0; 4 * 5]).await.unwrap();
        let result = connection.read_u32().await.unwrap();
        connection.read_exact(&mut [0; 4 * 6]).await.unwrap();
        assert_eq!(result, 0);

        let result = attach_device(&mut connection, 0).await;
        assert_eq!(result, 0);
    }

    #[tokio::test]
    async fn device_gets_released_on_closed_socket() {
        let server_ = Arc::new(new_server_with_single_device());

        let addr = get_free_address().await;
        tokio::spawn(server(addr, server_.clone()));

        let mut connection = poll_connect(addr).await;
        let result = attach_device(&mut connection, 0).await;
        assert_eq!(result, 0);

        std::mem::drop(connection);

        let mut connection = TcpStream::connect(addr).await.unwrap();
        let result = attach_device(&mut connection, 0).await;
        assert_eq!(result, 0);
    }

    #[tokio::test]
    async fn req_import_get_device_desc() {
        let server = new_server_with_single_device();

        // OP_REQ_IMPORT
        let mut req = op_req_import(0);
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
