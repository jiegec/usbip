//! A library for running a USB/IP server

use log::*;
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use nusb::MaybeFuture;
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
use usbip_protocol::UsbIpCommand;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

pub mod cdc;
mod consts;
mod device;
mod endpoint;
pub mod hid;
mod host;
mod interface;
mod setup;
pub mod usbip_protocol;
mod util;
pub use consts::*;
pub use device::*;
pub use endpoint::*;
pub use host::*;
pub use interface::*;
pub use setup::*;
pub use util::*;

use crate::usbip_protocol::{USBIP_RET_SUBMIT, USBIP_RET_UNLINK, UsbIpHeaderBasic, UsbIpResponse};

/// Main struct of a USB/IP server
#[derive(Default, Debug)]
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

    /// Create a [UsbIpServer] with Vec<[nusb::DeviceInfo]> for sharing host devices
    pub fn with_nusb_devices(nusb_device_infos: Vec<nusb::DeviceInfo>) -> Vec<UsbDevice> {
        let mut devices = vec![];
        for device_info in nusb_device_infos {
            let dev = match device_info.open().wait() {
                Ok(dev) => dev,
                Err(err) => {
                    warn!("Impossible to open device {device_info:?}: {err}, ignoring device",);
                    continue;
                }
            };
            let cfg = match dev.active_configuration() {
                Ok(cfg) => cfg,
                Err(err) => {
                    warn!(
                        "Impossible to get active configuration {device_info:?}: {err}, ignoring device",
                    );
                    continue;
                }
            };
            let mut interfaces = vec![];
            for intf in cfg.interfaces() {
                // ignore alternate settings
                let intf_num = intf.interface_number();
                let intf = dev.claim_interface(intf_num).wait().unwrap();
                let alt_setting = intf.descriptors().next().unwrap();
                let mut endpoints = vec![];

                for ep_desc in alt_setting.endpoints() {
                    endpoints.push(UsbEndpoint {
                        address: ep_desc.address(),
                        attributes: ep_desc.transfer_type() as u8,
                        max_packet_size: ep_desc.max_packet_size() as u16,
                        interval: ep_desc.interval(),
                    });
                }

                let handler = Arc::new(Mutex::new(Box::new(NusbUsbHostInterfaceHandler::new(
                    Arc::new(Mutex::new(intf.clone())),
                ))
                    as Box<dyn UsbInterfaceHandler + Send>));
                interfaces.push(UsbInterface {
                    interface_class: alt_setting.class(),
                    interface_subclass: alt_setting.subclass(),
                    interface_protocol: alt_setting.protocol(),
                    endpoints,
                    string_interface: alt_setting.string_index().map(|nz| nz.get()).unwrap_or(0),
                    class_specific_descriptor: Vec::new(),
                    handler,
                });
            }

            // Platform-specific bus number (Linux-only)
            let bus_num_val: u32;
            #[cfg(target_os = "linux")]
            {
                bus_num_val = device_info.busnum() as u32;
            }
            #[cfg(not(target_os = "linux"))]
            {
                bus_num_val = 0;
            }

            let device_address = device_info.device_address();

            let mut device = UsbDevice {
                path: format!("/sys/bus/{}/{}/{}", bus_num_val, device_address, 0),
                bus_id: format!("{}-{}-{}", bus_num_val, device_address, 0),
                bus_num: bus_num_val,
                dev_num: 0,
                speed: device_info.speed().unwrap() as u32,
                vendor_id: device_info.vendor_id(),
                product_id: device_info.product_id(),
                device_class: device_info.class(),
                device_subclass: device_info.subclass(),
                device_protocol: device_info.protocol(),
                device_bcd: device_info.device_version().into(),
                configuration_value: cfg.configuration_value(),
                num_configurations: dev.configurations().count() as u8,
                ep0_in: UsbEndpoint {
                    address: 0x80,
                    attributes: EndpointAttributes::Control as u8,
                    max_packet_size: 16,
                    interval: 0,
                },
                ep0_out: UsbEndpoint {
                    address: 0x00,
                    attributes: EndpointAttributes::Control as u8,
                    max_packet_size: 16,
                    interval: 0,
                },
                interfaces,
                device_handler: Some(Arc::new(Mutex::new(Box::new(
                    NusbUsbHostDeviceHandler::new(Arc::new(Mutex::new(dev))),
                )))),
                ..UsbDevice::default()
            };

            // set strings
            if let Some(s) = device_info.manufacturer_string() {
                device.string_manufacturer = device.new_string(s)
            }
            if let Some(s) = device_info.product_string() {
                device.string_product = device.new_string(s)
            }
            if let Some(s) = device_info.serial_number() {
                device.string_serial = device.new_string(s)
            }
            devices.push(device);
        }
        devices
    }

    /// Create a [UsbIpServer] with Vec<[rusb::DeviceHandle]> for sharing host devices
    pub fn with_rusb_device_handles(
        device_handles: Vec<DeviceHandle<GlobalContext>>,
    ) -> Vec<UsbDevice> {
        let mut devices = vec![];
        for open_device in device_handles {
            let dev = open_device.device();
            let desc = match dev.device_descriptor() {
                Ok(desc) => desc,
                Err(err) => {
                    warn!(
                        "Impossible to get device descriptor for {dev:?}: {err}, ignoring device",
                    );
                    continue;
                }
            };
            let cfg = match dev.active_config_descriptor() {
                Ok(desc) => desc,
                Err(err) => {
                    warn!(
                        "Impossible to get config descriptor for {dev:?}: {err}, ignoring device",
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

                let handler = Arc::new(Mutex::new(Box::new(RusbUsbHostInterfaceHandler::new(
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
                device_handler: Some(Arc::new(Mutex::new(Box::new(
                    RusbUsbHostDeviceHandler::new(handle.clone()),
                )))),
                usb_version: desc.usb_version().into(),
                ..UsbDevice::default()
            };

            // set strings
            //
            // Devices are not required to respond successfully to a string descriptor
            // read (some transiently NAK it, some don't implement the language ID we
            // ask for). A failure here used to be treated as fatal via .unwrap(), which
            // crashed enumeration - and with it every other device - instead of just
            // leaving that one string unset.
            if let Some(index) = desc.manufacturer_string_index() {
                match handle.lock().unwrap().read_string_descriptor_ascii(index) {
                    Ok(s) => device.string_manufacturer = device.new_string(&s),
                    Err(err) => warn!(
                        "[{:04x}:{:04x} {}] failed to read manufacturer string descriptor (index={index}): {err}",
                        device.vendor_id, device.product_id, device.bus_id
                    ),
                }
            }
            if let Some(index) = desc.product_string_index() {
                match handle.lock().unwrap().read_string_descriptor_ascii(index) {
                    Ok(s) => device.string_product = device.new_string(&s),
                    Err(err) => warn!(
                        "[{:04x}:{:04x} {}] failed to read product string descriptor (index={index}): {err}",
                        device.vendor_id, device.product_id, device.bus_id
                    ),
                }
            }
            if let Some(index) = desc.serial_number_string_index() {
                match handle.lock().unwrap().read_string_descriptor_ascii(index) {
                    Ok(s) => device.string_serial = device.new_string(&s),
                    Err(err) => warn!(
                        "[{:04x}:{:04x} {}] failed to read serial number string descriptor (index={index}): {err}",
                        device.vendor_id, device.product_id, device.bus_id
                    ),
                }
            }
            devices.push(device);
        }
        devices
    }

    fn with_rusb_devices(device_list: Vec<Device<GlobalContext>>) -> Vec<UsbDevice> {
        let mut device_handles = vec![];

        for dev in device_list {
            let open_device = match dev.open() {
                Ok(dev) => dev,
                Err(err) => {
                    warn!("Impossible to share {dev:?}: {err}, ignoring device");
                    continue;
                }
            };
            device_handles.push(open_device);
        }
        Self::with_rusb_device_handles(device_handles)
    }

    /// Create a [UsbIpServer] exposing devices in the host, and redirect all USB transfers to them using libusb
    pub fn new_from_host() -> Self {
        Self::new_from_host_with_filter(|_| true)
    }

    /// Create a [UsbIpServer] exposing filtered devices in the host, and redirect all USB transfers to them using libusb
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
                    available_devices: RwLock::new(Self::with_rusb_devices(devs)),
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
            Err(std::io::Error::other(format!(
                "Device {} is in use",
                device.bus_id
            )))
        } else {
            Err(std::io::Error::new(
                ErrorKind::NotFound,
                format!("Device {bus_id} not found"),
            ))
        }
    }
}

/// Maximum number of concurrent deferred (pending) interrupt IN transfers per
/// connection. Beyond this, new interrupt IN URBs are completed immediately
/// instead of being deferred, so a misbehaving client cannot drive unbounded
/// task growth (potential DoS).
const MAX_PENDING_DEFERRED: usize = 64;

/// Send a deferred (pending) completion response and drop it from the pending map.
async fn send_deferred_response<W: AsyncWriteExt + Unpin>(
    res: UsbIpResponse,
    writer: &mut W,
    pending: &mut HashMap<u32, tokio::task::JoinHandle<()>>,
) -> Result<()> {
    if let UsbIpResponse::UsbIpRetSubmit { header, .. } = &res {
        // Only send a completion if this seqnum is still pending. If a
        // USBIP_CMD_UNLINK already removed it, the client cancelled this URB
        // and we must not complete it (otherwise we would respond to a URB the
        // client explicitly unlinked).
        if pending.remove(&header.seqnum).is_none() {
            trace!(
                "Dropped deferred USB/IP response for unlinked seqnum {}",
                header.seqnum
            );
            return Ok(());
        }
    }
    res.write_to_socket(writer).await?;
    trace!("Sent deferred USB/IP response");
    Ok(())
}

async fn handle_submit(
    device: &UsbDevice,
    header: &UsbIpHeaderBasic,
    real_ep: u32,
    out: bool,
    transfer_buffer_length: u32,
    setup: [u8; 8],
    data: &[u8],
) -> UsbIpResponse {
    match device.find_ep(real_ep as u8) {
        None => {
            warn!("Endpoint {real_ep:02x?} not found");
            UsbIpResponse::usbip_ret_submit_fail(header)
        }
        Some((ep, intf)) => {
            trace!("->Endpoint {ep:02x?}");
            trace!("->Setup {setup:02x?}");
            trace!("->Request {data:02x?}");
            let resp = device
                .handle_urb(
                    ep,
                    intf,
                    transfer_buffer_length,
                    SetupPacket::parse(&setup),
                    data,
                )
                .await;

            match resp {
                Ok(resp) => {
                    if out {
                        trace!("<-Wrote {}", data.len());
                    } else {
                        trace!("<-Resp {resp:02x?}");
                    }
                    let actual_length = if out {
                        debug_assert!(
                            resp.is_empty(),
                            "OUT transfer should return empty response buffer"
                        );
                        data.len() as u32
                    } else {
                        resp.len() as u32
                    };
                    UsbIpResponse::usbip_ret_submit_success(
                        header,
                        0,
                        0,
                        actual_length,
                        resp,
                        vec![],
                    )
                }
                Err(err) => {
                    warn!("Error handling URB: {err}");
                    UsbIpResponse::usbip_ret_submit_fail(header)
                }
            }
        }
    }
}

pub async fn handler<T: AsyncReadExt + AsyncWriteExt + Unpin>(
    socket: &mut T,
    server: Arc<UsbIpServer>,
) -> Result<()> {
    let (mut reader, mut writer) = tokio::io::split(socket);
    let (delayed_tx, mut delayed_rx) = tokio::sync::mpsc::channel::<UsbIpResponse>(64);
    // Deferred (pending) interrupt IN transfers keyed by seqnum. The completion
    // is sent later, once the device handler produces data (issue #63).
    let mut pending: HashMap<u32, tokio::task::JoinHandle<()>> = HashMap::new();
    let mut current_import_device_id: Option<String> = None;
    loop {
        // Send any deferred responses that are already ready before waiting for
        // the next command. This keeps the reader from being cancelled
        // mid-command when a deferred response arrives.
        while let Ok(res) = delayed_rx.try_recv() {
            send_deferred_response(res, &mut writer, &mut pending).await?;
        }

        let command = tokio::select! {
            command = UsbIpCommand::read_from_socket(&mut reader) => command,
            delayed_response = delayed_rx.recv() => {
                if let Some(res) = delayed_response {
                    send_deferred_response(res, &mut writer, &mut pending).await?;
                }
                continue;
            }
        };
        if let Err(err) = command {
            if let Some(dev_id) = current_import_device_id {
                let mut used_devices = server.used_devices.write().await;
                let mut available_devices = server.available_devices.write().await;
                match used_devices.remove(&dev_id) {
                    Some(dev) => available_devices.push(dev),
                    None => unreachable!(),
                }
            }

            // Cancel any deferred transfers that are still pending.
            for (_, task) in pending.drain() {
                task.abort();
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

        match command.unwrap() {
            UsbIpCommand::OpReqDevlist { .. } => {
                trace!("Got OP_REQ_DEVLIST");
                let devices = server.available_devices.read().await;

                // OP_REP_DEVLIST
                UsbIpResponse::op_rep_devlist(&devices)
                    .write_to_socket(&mut writer)
                    .await?;
                trace!("Sent OP_REP_DEVLIST");
            }
            UsbIpCommand::OpReqImport { busid, .. } => {
                trace!("Got OP_REQ_IMPORT");

                current_import_device_id = None;
                current_import_device = None;
                std::mem::drop(used_devices);

                let mut used_devices = server.used_devices.write().await;
                let mut available_devices = server.available_devices.write().await;
                let busid_compare =
                    &busid[..busid.iter().position(|&x| x == 0).unwrap_or(busid.len())];
                for (i, dev) in available_devices.iter().enumerate() {
                    if busid_compare == dev.bus_id.as_bytes() {
                        let dev = available_devices.remove(i);
                        let dev_id = dev.bus_id.clone();
                        used_devices.insert(dev.bus_id.clone(), dev);
                        current_import_device_id = dev_id.clone().into();
                        current_import_device = Some(used_devices.get(&dev_id).unwrap());
                        break;
                    }
                }

                let res = if let Some(dev) = current_import_device {
                    UsbIpResponse::op_rep_import_success(dev)
                } else {
                    UsbIpResponse::op_rep_import_fail()
                };
                res.write_to_socket(&mut writer).await?;
                trace!("Sent OP_REP_IMPORT");
            }
            UsbIpCommand::UsbIpCmdSubmit {
                mut header,
                transfer_buffer_length,
                setup,
                data,
                ..
            } => {
                trace!("Got USBIP_CMD_SUBMIT");
                let device = current_import_device.unwrap();

                let out = header.direction == 0;
                let real_ep = if out { header.ep } else { header.ep | 0x80 };

                header.command = USBIP_RET_SUBMIT.into();

                // For interrupt IN endpoints whose handler exposes a
                // "data available" Notify, defer the completion until real data
                // is available instead of replying with an empty buffer. This
                // avoids flooding clients (e.g. usbip-win2) that poll at a very
                // high rate (issue #63).
                let notify = if !out {
                    device.find_ep(real_ep as u8).and_then(|(ep, intf)| {
                        let intf = intf?;
                        if ep.direction() == Direction::In
                            && ep.attributes == EndpointAttributes::Interrupt as u8
                        {
                            intf.handler.lock().unwrap().pending_notify()
                        } else {
                            None
                        }
                    })
                } else {
                    None
                };

                if let Some(notify) = notify {
                    // Bound the number of concurrent deferred transfers so a
                    // misbehaving client cannot drive unbounded task growth
                    // (potential DoS). When the cap is reached, fall through and
                    // complete the URB immediately instead of deferring.
                    if pending.len() < MAX_PENDING_DEFERRED {
                        // Defer: spawn a task that waits for the handler to
                        // signal data. The response is queued to the writer
                        // (via the response channel) only once there is
                        // actually data to send.
                        let device = device.clone();
                        let header2 = header.clone();
                        let tx = delayed_tx.clone();
                        let task = tokio::spawn(async move {
                            loop {
                                let res = handle_submit(
                                    &device,
                                    &header2,
                                    real_ep,
                                    out,
                                    transfer_buffer_length,
                                    setup,
                                    &data,
                                )
                                .await;
                                let should_send = match &res {
                                    UsbIpResponse::UsbIpRetSubmit {
                                        status,
                                        actual_length,
                                        transfer_buffer,
                                        ..
                                    } => {
                                        *status != 0
                                            || *actual_length > 0
                                            || !transfer_buffer.is_empty()
                                    }
                                    _ => true,
                                };
                                if should_send {
                                    let _ = tx.send(res).await;
                                    break;
                                }
                                notify.notified().await;
                            }
                        });
                        // If the client reuses a seqnum, abort the replaced task
                        // so it cannot later emit a response that no longer
                        // matches the pending map.
                        if let Some(old) = pending.remove(&header.seqnum) {
                            old.abort();
                        }
                        pending.insert(header.seqnum, task);
                        trace!("Deferred USBIP_CMD_SUBMIT (seqnum {})", header.seqnum);
                        continue;
                    }
                    trace!("Deferred URB cap reached, completing immediately");
                }
                let res = handle_submit(
                    device,
                    &header,
                    real_ep,
                    out,
                    transfer_buffer_length,
                    setup,
                    &data,
                )
                .await;
                res.write_to_socket(&mut writer).await?;
                trace!("Sent USBIP_RET_SUBMIT");
            }
            UsbIpCommand::UsbIpCmdUnlink {
                mut header,
                unlink_seqnum,
            } => {
                trace!("Got USBIP_CMD_UNLINK for {unlink_seqnum:10x?}");

                header.command = USBIP_RET_UNLINK.into();

                // Cancel a still-pending deferred transfer, if any.
                if let Some(task) = pending.remove(&unlink_seqnum) {
                    task.abort();
                }

                let res = UsbIpResponse::usbip_ret_unlink_success(&header);
                res.write_to_socket(&mut writer).await?;
                trace!("Sent USBIP_RET_UNLINK");
            }
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
                        info!("Handler ended with {res:?}");
                    });
                }
                Err(err) => {
                    warn!("Got error {err:?}");
                }
            }
        }
    };

    server.await
}

#[cfg(test)]
mod tests {
    use tokio::sync::Notify;
    use tokio::{net::TcpStream, task::JoinSet};

    use super::*;
    use crate::{
        usbip_protocol::{USBIP_CMD_SUBMIT, UsbIpHeaderBasic},
        util::tests::*,
    };

    const SINGLE_DEVICE_BUSID: &str = "0-0-0";

    /// A test handler that opts into the deferred interrupt IN behaviour
    /// (issue #63): it stays silent until `push_event` is called.
    #[derive(Debug)]
    struct TestInterruptHandler {
        data: Option<Vec<u8>>,
        notify: Arc<Notify>,
    }

    impl TestInterruptHandler {
        fn new() -> Self {
            Self {
                data: None,
                notify: Arc::new(Notify::new()),
            }
        }

        fn push_event(&mut self, event: Vec<u8>) {
            self.data = Some(event);
            // notify_one stores a permit when no task is waiting yet (so the
            // deferred task cannot miss the signal), and wakes exactly one
            // waiter (one event completes one URB).
            self.notify.notify_one();
        }
    }

    impl UsbInterfaceHandler for TestInterruptHandler {
        fn get_class_specific_descriptor(&self) -> Vec<u8> {
            vec![]
        }

        fn handle_urb(
            &mut self,
            _interface: &UsbInterface,
            _ep: UsbEndpoint,
            _transfer_buffer_length: u32,
            _setup: SetupPacket,
            _req: &[u8],
        ) -> Result<Vec<u8>> {
            Ok(self.data.take().unwrap_or_default())
        }

        fn pending_notify(&self) -> Option<Arc<Notify>> {
            Some(self.notify.clone())
        }

        fn as_any(&mut self) -> &mut dyn Any {
            self
        }
    }

    fn new_server_with_single_device() -> UsbIpServer {
        UsbIpServer::new_simulated(vec![UsbDevice::new(0).with_interface(
            ClassCode::CDC as u8,
            cdc::CDC_ACM_SUBCLASS,
            0x00,
            Some("Test CDC ACM"),
            cdc::UsbCdcAcmHandler::endpoints(),
            Arc::new(Mutex::new(
                Box::new(cdc::UsbCdcAcmHandler::new()) as Box<dyn UsbInterfaceHandler + Send>
            )),
        )])
    }

    fn op_req_import(busid: &str) -> Vec<u8> {
        let mut busid = busid.to_string().as_bytes().to_vec();
        busid.resize(32, 0);
        UsbIpCommand::OpReqImport {
            status: 0,
            busid: busid.try_into().unwrap(),
        }
        .to_bytes()
    }

    async fn attach_device(connection: &mut TcpStream, busid: &str) -> u32 {
        let req = op_req_import(busid);
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
        setup_test_logger();
        let server = UsbIpServer::new_simulated(vec![]);
        let req = UsbIpCommand::OpReqDevlist { status: 0 };

        let mut mock_socket = MockSocket::new(req.to_bytes());
        handler(&mut mock_socket, Arc::new(server)).await.ok();

        assert_eq!(
            mock_socket.output,
            UsbIpResponse::op_rep_devlist(&[]).to_bytes(),
        );
    }

    #[tokio::test]
    async fn req_sample_devlist() {
        setup_test_logger();
        let server = new_server_with_single_device();
        let req = UsbIpCommand::OpReqDevlist { status: 0 };

        let mut mock_socket = MockSocket::new(req.to_bytes());
        handler(&mut mock_socket, Arc::new(server)).await.ok();

        // OP_REP_DEVLIST
        // header: 0xC
        // device: 0x138
        // interface: 4 * 0x1
        assert_eq!(mock_socket.output.len(), 0xC + 0x138 + 4);
    }

    #[tokio::test]
    async fn req_import() {
        setup_test_logger();
        let server = new_server_with_single_device();

        // OP_REQ_IMPORT
        let req = op_req_import(SINGLE_DEVICE_BUSID);
        let mut mock_socket = MockSocket::new(req);
        handler(&mut mock_socket, Arc::new(server)).await.ok();
        // OP_REQ_IMPORT
        assert_eq!(mock_socket.output.len(), 0x140);
    }

    #[tokio::test]
    async fn add_and_remove_10_devices() {
        setup_test_logger();
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
        setup_test_logger();
        let server_ = Arc::new(new_server_with_single_device());

        let addr = get_free_address().await;
        tokio::spawn(server(addr, server_.clone()));

        let cmd_loop_handle = tokio::spawn(async move {
            let mut connection = poll_connect(addr).await;
            let result = attach_device(&mut connection, SINGLE_DEVICE_BUSID).await;
            assert_eq!(result, 0);

            let cdc_loopback_bulk_cmd = UsbIpCommand::UsbIpCmdSubmit {
                header: usbip_protocol::UsbIpHeaderBasic {
                    command: USBIP_CMD_SUBMIT.into(),
                    seqnum: 1,
                    devid: 0,
                    direction: 0, // OUT
                    ep: 2,
                },
                transfer_flags: 0,
                transfer_buffer_length: 8,
                start_frame: 0,
                number_of_packets: 0,
                interval: 0,
                setup: [0; 8],
                data: vec![1, 2, 3, 4, 5, 6, 7, 8],
                iso_packet_descriptor: vec![],
            };

            loop {
                connection
                    .write_all(cdc_loopback_bulk_cmd.to_bytes().as_slice())
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
        setup_test_logger();
        let server_ = Arc::new(new_server_with_single_device());

        let addr = get_free_address().await;
        tokio::spawn(server(addr, server_.clone()));

        let mut first_connection = poll_connect(addr).await;
        let mut second_connection = TcpStream::connect(addr).await.unwrap();

        let result = attach_device(&mut first_connection, SINGLE_DEVICE_BUSID).await;
        assert_eq!(result, 0);

        let result = attach_device(&mut second_connection, SINGLE_DEVICE_BUSID).await;
        assert_eq!(result, 1);
    }

    #[tokio::test]
    async fn device_gets_released_on_closed_socket() {
        setup_test_logger();
        let server_ = Arc::new(new_server_with_single_device());

        let addr = get_free_address().await;
        tokio::spawn(server(addr, server_.clone()));

        let mut connection = poll_connect(addr).await;
        let result = attach_device(&mut connection, SINGLE_DEVICE_BUSID).await;
        assert_eq!(result, 0);

        std::mem::drop(connection);

        let mut connection = TcpStream::connect(addr).await.unwrap();
        let result = attach_device(&mut connection, SINGLE_DEVICE_BUSID).await;
        assert_eq!(result, 0);
    }

    #[tokio::test]
    async fn req_import_get_device_desc() {
        setup_test_logger();
        let server = new_server_with_single_device();

        let mut req = op_req_import(SINGLE_DEVICE_BUSID);
        req.extend(
            UsbIpCommand::UsbIpCmdSubmit {
                header: UsbIpHeaderBasic {
                    command: USBIP_CMD_SUBMIT.into(),
                    seqnum: 1,
                    devid: 0,
                    direction: 1, // IN
                    ep: 0,
                },
                transfer_flags: 0,
                transfer_buffer_length: 0,
                start_frame: 0,
                number_of_packets: 0,
                interval: 0,
                // GetDescriptor to Device
                setup: [0x80, 0x06, 0x00, 0x01, 0x00, 0x00, 0x40, 0x00],
                data: vec![],
                iso_packet_descriptor: vec![],
            }
            .to_bytes(),
        );

        let mut mock_socket = MockSocket::new(req);
        handler(&mut mock_socket, Arc::new(server)).await.ok();
        // OP_REQ_IMPORT + USBIP_CMD_SUBMIT + Device Descriptor
        assert_eq!(mock_socket.output.len(), 0x140 + 0x30 + 0x12);
    }

    #[tokio::test]
    async fn interrupt_in_defers_until_data_available() {
        setup_test_logger();
        let interrupt_handler = Arc::new(Mutex::new(
            Box::new(TestInterruptHandler::new()) as Box<dyn UsbInterfaceHandler + Send>
        ));
        let device = UsbDevice::new(0).with_interface(
            ClassCode::HID as u8,
            0x00,
            0x00,
            Some("Test interrupt IN"),
            vec![UsbEndpoint {
                address: 0x81, // IN
                attributes: EndpointAttributes::Interrupt as u8,
                max_packet_size: 0x08,
                interval: 10,
            }],
            interrupt_handler.clone(),
        );
        let server_ = Arc::new(UsbIpServer::new_simulated(vec![device]));

        let addr = get_free_address().await;
        tokio::spawn(server(addr, server_.clone()));

        let mut connection = poll_connect(addr).await;
        let result = attach_device(&mut connection, SINGLE_DEVICE_BUSID).await;
        assert_eq!(result, 0);

        // Submit an interrupt IN URB (direction IN, endpoint 0x81).
        let submit = UsbIpCommand::UsbIpCmdSubmit {
            header: usbip_protocol::UsbIpHeaderBasic {
                command: usbip_protocol::USBIP_CMD_SUBMIT.into(),
                seqnum: 1,
                devid: 0,
                direction: 1, // IN
                ep: 1,        // 0x81 after | 0x80
            },
            transfer_flags: 0,
            transfer_buffer_length: 8,
            start_frame: 0,
            number_of_packets: 0,
            interval: 0,
            setup: [0; 8],
            data: vec![],
            iso_packet_descriptor: vec![],
        };
        connection
            .write_all(submit.to_bytes().as_slice())
            .await
            .unwrap();

        // No data yet: the interrupt IN transfer must remain pending, so the
        // server should NOT send a completion.
        {
            let timed_out = tokio::time::timeout(
                std::time::Duration::from_millis(200),
                connection.read_exact(&mut [0u8; 48]),
            )
            .await;
            assert!(
                timed_out.is_err(),
                "interrupt IN should be deferred until data is available"
            );
        }

        // Now signal a data event and let the server know there is data.
        {
            let mut h = interrupt_handler.lock().unwrap();
            h.as_any()
                .downcast_mut::<TestInterruptHandler>()
                .unwrap()
                .push_event(vec![0x01]);
        }

        // The server should now complete the pending URB with the event.
        let mut header_buf = [0u8; 48];
        connection.read_exact(&mut header_buf).await.unwrap();
        let command = u32::from_be_bytes(header_buf[0..4].try_into().unwrap());
        assert_eq!(command, usbip_protocol::USBIP_RET_SUBMIT.into());
        let seqnum = u32::from_be_bytes(header_buf[4..8].try_into().unwrap());
        assert_eq!(seqnum, 1);
        let actual_length = u32::from_be_bytes(header_buf[24..28].try_into().unwrap()) as usize;
        assert_eq!(actual_length, 1);
        let mut data = vec![0u8; actual_length];
        connection.read_exact(&mut data).await.unwrap();
        assert_eq!(data, vec![0x01]);
    }

    #[tokio::test]
    async fn interrupt_in_stays_pending_across_multiple_polls() {
        setup_test_logger();
        let interrupt_handler = Arc::new(Mutex::new(
            Box::new(TestInterruptHandler::new()) as Box<dyn UsbInterfaceHandler + Send>
        ));
        let device = UsbDevice::new(0).with_interface(
            ClassCode::HID as u8,
            0x00,
            0x00,
            Some("Test interrupt IN"),
            vec![UsbEndpoint {
                address: 0x81, // IN
                attributes: EndpointAttributes::Interrupt as u8,
                max_packet_size: 0x08,
                interval: 10,
            }],
            interrupt_handler.clone(),
        );
        let server_ = Arc::new(UsbIpServer::new_simulated(vec![device]));

        let addr = get_free_address().await;
        tokio::spawn(server(addr, server_.clone()));

        let mut connection = poll_connect(addr).await;
        let result = attach_device(&mut connection, SINGLE_DEVICE_BUSID).await;
        assert_eq!(result, 0);

        // Fire several interrupt IN polls in quick succession. Because there is
        // no data yet, none of them should be completed, so the client never
        // gets flooded with empty completions.
        for seqnum in 1..=5 {
            let submit = UsbIpCommand::UsbIpCmdSubmit {
                header: usbip_protocol::UsbIpHeaderBasic {
                    command: usbip_protocol::USBIP_CMD_SUBMIT.into(),
                    seqnum,
                    devid: 0,
                    direction: 1, // IN
                    ep: 1,        // 0x81 after | 0x80
                },
                transfer_flags: 0,
                transfer_buffer_length: 8,
                start_frame: 0,
                number_of_packets: 0,
                interval: 0,
                setup: [0; 8],
                data: vec![],
                iso_packet_descriptor: vec![],
            };
            connection
                .write_all(submit.to_bytes().as_slice())
                .await
                .unwrap();
        }

        // No data yet: none of the polls should have been answered.
        {
            let timed_out = tokio::time::timeout(
                std::time::Duration::from_millis(200),
                connection.read_exact(&mut [0u8; 48]),
            )
            .await;
            assert!(
                timed_out.is_err(),
                "no interrupt IN should complete while there is no data"
            );
        }

        // Signal a single event: exactly ONE of the queued URBs should complete
        // with the event (the rest stay pending for subsequent events).
        {
            let mut h = interrupt_handler.lock().unwrap();
            h.as_any()
                .downcast_mut::<TestInterruptHandler>()
                .unwrap()
                .push_event(vec![0x01]);
        }

        let mut header_buf = [0u8; 48];
        connection.read_exact(&mut header_buf).await.unwrap();
        let seqnum = u32::from_be_bytes(header_buf[4..8].try_into().unwrap());
        assert!((1..=5).contains(&seqnum));
        let actual_length = u32::from_be_bytes(header_buf[24..28].try_into().unwrap()) as usize;
        assert_eq!(actual_length, 1);
        let mut data = vec![0u8; actual_length];
        connection.read_exact(&mut data).await.unwrap();
        assert_eq!(data, vec![0x01]);
    }

    #[tokio::test]
    async fn interrupt_in_unlink_drops_deferred_response() {
        setup_test_logger();
        let interrupt_handler = Arc::new(Mutex::new(
            Box::new(TestInterruptHandler::new()) as Box<dyn UsbInterfaceHandler + Send>
        ));
        let device = UsbDevice::new(0).with_interface(
            ClassCode::HID as u8,
            0x00,
            0x00,
            Some("Test interrupt IN"),
            vec![UsbEndpoint {
                address: 0x81, // IN
                attributes: EndpointAttributes::Interrupt as u8,
                max_packet_size: 0x08,
                interval: 10,
            }],
            interrupt_handler.clone(),
        );
        let server_ = Arc::new(UsbIpServer::new_simulated(vec![device]));

        let addr = get_free_address().await;
        tokio::spawn(server(addr, server_.clone()));

        let mut connection = poll_connect(addr).await;
        let result = attach_device(&mut connection, SINGLE_DEVICE_BUSID).await;
        assert_eq!(result, 0);

        // Submit an interrupt IN URB (seqnum 1); it is deferred.
        let submit = UsbIpCommand::UsbIpCmdSubmit {
            header: usbip_protocol::UsbIpHeaderBasic {
                command: usbip_protocol::USBIP_CMD_SUBMIT.into(),
                seqnum: 1,
                devid: 0,
                direction: 1, // IN
                ep: 1,        // 0x81 after | 0x80
            },
            transfer_flags: 0,
            transfer_buffer_length: 8,
            start_frame: 0,
            number_of_packets: 0,
            interval: 0,
            setup: [0; 8],
            data: vec![],
            iso_packet_descriptor: vec![],
        };
        connection
            .write_all(submit.to_bytes().as_slice())
            .await
            .unwrap();

        // Unlink seqnum 1: the pending transfer must be cancelled.
        let unlink = UsbIpCommand::UsbIpCmdUnlink {
            header: usbip_protocol::UsbIpHeaderBasic {
                command: usbip_protocol::USBIP_CMD_UNLINK.into(),
                seqnum: 2,
                devid: 0,
                direction: 0,
                ep: 0,
            },
            unlink_seqnum: 1,
        };
        connection
            .write_all(unlink.to_bytes().as_slice())
            .await
            .unwrap();

        // We only expect the USBIP_RET_UNLINK, not a USBIP_RET_SUBMIT.
        let mut header_buf = [0u8; 48];
        connection.read_exact(&mut header_buf).await.unwrap();
        let command = u32::from_be_bytes(header_buf[0..4].try_into().unwrap());
        assert_eq!(command, usbip_protocol::USBIP_RET_UNLINK.into());

        // Even though data now becomes available, the cancelled URB must NOT be
        // completed with a deferred response.
        {
            let mut h = interrupt_handler.lock().unwrap();
            h.as_any()
                .downcast_mut::<TestInterruptHandler>()
                .unwrap()
                .push_event(vec![0x01]);
        }
        let timed_out = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            connection.read_exact(&mut [0u8; 48]),
        )
        .await;
        assert!(
            timed_out.is_err(),
            "an unlinked URB must not be completed with a deferred response"
        );
    }

    #[tokio::test]
    async fn interrupt_in_reused_seqnum_aborts_previous_task() {
        setup_test_logger();
        let interrupt_handler = Arc::new(Mutex::new(
            Box::new(TestInterruptHandler::new()) as Box<dyn UsbInterfaceHandler + Send>
        ));
        let device = UsbDevice::new(0).with_interface(
            ClassCode::HID as u8,
            0x00,
            0x00,
            Some("Test interrupt IN"),
            vec![UsbEndpoint {
                address: 0x81, // IN
                attributes: EndpointAttributes::Interrupt as u8,
                max_packet_size: 0x08,
                interval: 10,
            }],
            interrupt_handler.clone(),
        );
        let server_ = Arc::new(UsbIpServer::new_simulated(vec![device]));

        let addr = get_free_address().await;
        tokio::spawn(server(addr, server_.clone()));

        let mut connection = poll_connect(addr).await;
        let result = attach_device(&mut connection, SINGLE_DEVICE_BUSID).await;
        assert_eq!(result, 0);

        // Submit the same seqnum (1) twice. The second occurrence should abort
        // the deferred task from the first, so only one completion is possible.
        for _ in 0..2 {
            let submit = UsbIpCommand::UsbIpCmdSubmit {
                header: usbip_protocol::UsbIpHeaderBasic {
                    command: usbip_protocol::USBIP_CMD_SUBMIT.into(),
                    seqnum: 1,
                    devid: 0,
                    direction: 1, // IN
                    ep: 1,        // 0x81 after | 0x80
                },
                transfer_flags: 0,
                transfer_buffer_length: 8,
                start_frame: 0,
                number_of_packets: 0,
                interval: 0,
                setup: [0; 8],
                data: vec![],
                iso_packet_descriptor: vec![],
            };
            connection
                .write_all(submit.to_bytes().as_slice())
                .await
                .unwrap();
        }

        // A single event should complete exactly one (the replacement) URB.
        {
            let mut h = interrupt_handler.lock().unwrap();
            h.as_any()
                .downcast_mut::<TestInterruptHandler>()
                .unwrap()
                .push_event(vec![0x01]);
        }

        let mut header_buf = [0u8; 48];
        connection.read_exact(&mut header_buf).await.unwrap();
        let seqnum = u32::from_be_bytes(header_buf[4..8].try_into().unwrap());
        assert_eq!(seqnum, 1);
        let actual_length = u32::from_be_bytes(header_buf[24..28].try_into().unwrap()) as usize;
        let mut data = vec![0u8; actual_length];
        connection.read_exact(&mut data).await.unwrap();
        assert_eq!(data, vec![0x01]);

        // The replaced task must not emit a second completion.
        let timed_out = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            connection.read_exact(&mut [0u8; 48]),
        )
        .await;
        assert!(
            timed_out.is_err(),
            "a reused seqnum must not produce a second completion"
        );
    }

    #[tokio::test]
    async fn interrupt_in_pending_cap_limits_concurrency() {
        setup_test_logger();
        let interrupt_handler = Arc::new(Mutex::new(
            Box::new(TestInterruptHandler::new()) as Box<dyn UsbInterfaceHandler + Send>
        ));
        let device = UsbDevice::new(0).with_interface(
            ClassCode::HID as u8,
            0x00,
            0x00,
            Some("Test interrupt IN"),
            vec![UsbEndpoint {
                address: 0x81, // IN
                attributes: EndpointAttributes::Interrupt as u8,
                max_packet_size: 0x08,
                interval: 10,
            }],
            interrupt_handler.clone(),
        );
        let server_ = Arc::new(UsbIpServer::new_simulated(vec![device]));

        let addr = get_free_address().await;
        tokio::spawn(server(addr, server_.clone()));

        let mut connection = poll_connect(addr).await;
        let result = attach_device(&mut connection, SINGLE_DEVICE_BUSID).await;
        assert_eq!(result, 0);

        // Submit more URBs than the cap. The first MAX_PENDING_DEFERRED are
        // deferred; the overflow URB is completed immediately (empty buffer).
        let total = (MAX_PENDING_DEFERRED + 1) as u32;
        for seqnum in 1..=total {
            let submit = UsbIpCommand::UsbIpCmdSubmit {
                header: usbip_protocol::UsbIpHeaderBasic {
                    command: usbip_protocol::USBIP_CMD_SUBMIT.into(),
                    seqnum,
                    devid: 0,
                    direction: 1, // IN
                    ep: 1,        // 0x81 after | 0x80
                },
                transfer_flags: 0,
                transfer_buffer_length: 8,
                start_frame: 0,
                number_of_packets: 0,
                interval: 0,
                setup: [0; 8],
                data: vec![],
                iso_packet_descriptor: vec![],
            };
            connection
                .write_all(submit.to_bytes().as_slice())
                .await
                .unwrap();
        }

        // Exactly one completion: the overflow URB, answered immediately.
        let mut header_buf = [0u8; 48];
        connection.read_exact(&mut header_buf).await.unwrap();
        let seqnum = u32::from_be_bytes(header_buf[4..8].try_into().unwrap());
        assert_eq!(seqnum, total);
        let actual_length = u32::from_be_bytes(header_buf[24..28].try_into().unwrap()) as usize;
        assert_eq!(actual_length, 0);

        // The capped/deferred URBs still have no data, so no more responses.
        let timed_out = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            connection.read_exact(&mut [0u8; 48]),
        )
        .await;
        assert!(
            timed_out.is_err(),
            "capped deferred URBs should remain pending"
        );
    }
}
