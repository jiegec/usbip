mod async_server;
mod sync_server;

use crate::{
    usbip_protocol::{UsbIpCommand, UsbIpResponse, USBIP_RET_SUBMIT, USBIP_RET_UNLINK},
    EndpointAttributes, SetupPacket, UsbDevice, UsbEndpoint, UsbHostDeviceHandler,
    UsbHostInterfaceHandler, UsbInterface, UsbInterfaceHandler,
};

use async_trait::async_trait;
use log::{info, trace, warn};
use rusb::{Device, GlobalContext};

use std::{
    collections::HashMap,
    io::{ErrorKind, Result},
    net::SocketAddr,
    sync::{Arc, Mutex},
};
use tokio::{io::AsyncReadExt, io::AsyncWriteExt, net::TcpListener, sync::RwLock};

pub use async_server::*;
pub use sync_server::*;

/// A USB/IP server.
///
/// A server that can host USB devices and expose them to clients,
/// using the USB/IP protocol.
#[async_trait]
pub trait UsbIpServer: Send + Clone {
    /// Create a [UsbIpServer] with simulated devices
    fn new_simulated(devices: Vec<UsbDevice>) -> Self;

    /// Create a [UsbIpServer] exposing devices in the host, and redirect all USB transfers to them using libusb
    fn new_from_host() -> Self {
        Self::new_from_host_with_filter(|_| true)
    }

    // TODO: This is actually a default impl if Default is implemented for
    //       UsbIpServer. However, RFC 1210 is not stable yet. When it is,
    //       it would be nice to provide a specialized impl here.

    /// Create a [UsbIpServer] exposing a filtered set of devices in the host, and redirect all USB transfers to them using libusb
    ///
    /// Similar to [new_from_host], but only devices that pass the filter will be exposed.
    fn new_from_host_with_filter<F>(filter: F) -> Self
    where
        F: FnMut(&Device<GlobalContext>) -> bool;

    /// Add a [UsbDevice] to the servers available devices
    async fn add_device(&self, device: UsbDevice);

    /// Remove a [UsbDevice] from the server
    ///
    /// This function will return an error if the device cannot
    /// be identified by its `bus_id`, or if the device is currently
    /// attached to a client.
    async fn remove_device(&self, bus_id: &str) -> Result<()>;

    /// Internal per-device server loop.
    /// 
    /// This is usually called by [serve] for every new connection-device pair,
    /// and is responsible for forwarding USB packets between the socket and device.
    async fn handler<S>(self, socket: S) -> Result<()>
    where
        S: AsyncReadExt + AsyncWriteExt + Unpin + Send;

    // Spawn a USB/IP server at `addr` using [TcpListener]
    //
    // This will host a USB/IP endpoint at the `addr`,
    // and spawn a `handler` for every new connection.
    async fn serve(self, addr: SocketAddr);
}

fn get_list_of_real_devices(device_list: Vec<Device<GlobalContext>>) -> Vec<UsbDevice> {
    let mut devices = vec![];

    for dev in device_list {
        let open_device = match dev.open() {
            Ok(dev) => dev,
            Err(err) => {
                warn!("Impossible to share {:?}: {}, ignoring device", dev, err);
                continue;
            }
        };
        let desc = match dev.device_descriptor() {
            Ok(desc) => desc,
            Err(err) => {
                warn!(
                    "Impossible to get device descriptor for {:?}: {}, ignoring device",
                    dev, err
                );
                continue;
            }
        };
        let cfg = match dev.active_config_descriptor() {
            Ok(desc) => desc,
            Err(err) => {
                warn!(
                    "Impossible to get config descriptor for {:?}: {}, ignoring device",
                    dev, err
                );
                continue;
            }
        };

        let handle = Arc::new(Mutex::new(open_device));
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

            let handler = Arc::new(Mutex::new(
                Box::new(UsbHostInterfaceHandler::new(handle.clone()))
                    as Box<dyn UsbInterfaceHandler + Send>,
            ));
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