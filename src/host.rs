//! Host USB
use super::*;
use nusb::MaybeFuture;

/// A handler to pass requests to interface of a rusb USB device of the host
#[derive(Clone, Debug)]
pub struct RusbUsbHostInterfaceHandler {
    handle: Arc<Mutex<DeviceHandle<GlobalContext>>>,
}

impl RusbUsbHostInterfaceHandler {
    pub fn new(handle: Arc<Mutex<DeviceHandle<GlobalContext>>>) -> Self {
        Self { handle }
    }
}

impl UsbInterfaceHandler for RusbUsbHostInterfaceHandler {
    fn handle_urb(
        &mut self,
        _interface: &UsbInterface,
        ep: UsbEndpoint,
        transfer_buffer_length: u32,
        setup: SetupPacket,
        req: &[u8],
    ) -> Result<Vec<u8>> {
        debug!("To host device: ep={ep:?} setup={setup:?} req={req:?}",);
        let mut buffer = vec![0u8; transfer_buffer_length as usize];
        let timeout = std::time::Duration::new(1, 0);
        let handle = self.handle.lock().unwrap();
        if ep.attributes == EndpointAttributes::Control as u8 {
            // control
            if let Direction::In = ep.direction() {
                // control in
                if let Ok(len) = handle.read_control(
                    setup.request_type,
                    setup.request,
                    setup.value,
                    setup.index,
                    &mut buffer,
                    timeout,
                ) {
                    return Ok(Vec::from(&buffer[..len]));
                }
            } else {
                // control out
                handle
                    .write_control(
                        setup.request_type,
                        setup.request,
                        setup.value,
                        setup.index,
                        req,
                        timeout,
                    )
                    .ok();
            }
        } else if ep.attributes == EndpointAttributes::Interrupt as u8 {
            // interrupt
            if let Direction::In = ep.direction() {
                // interrupt in
                if let Ok(len) = handle.read_interrupt(ep.address, &mut buffer, timeout) {
                    info!("intr in {:?}", &buffer[..len]);
                    return Ok(Vec::from(&buffer[..len]));
                }
            } else {
                // interrupt out
                handle.write_interrupt(ep.address, req, timeout).ok();
            }
        } else if ep.attributes == EndpointAttributes::Bulk as u8 {
            // bulk
            if let Direction::In = ep.direction() {
                // bulk in
                if let Ok(len) = handle.read_bulk(ep.address, &mut buffer, timeout) {
                    return Ok(Vec::from(&buffer[..len]));
                }
            } else {
                // bulk out
                handle.write_bulk(ep.address, req, timeout).ok();
            }
        }
        Ok(vec![])
    }

    fn get_class_specific_descriptor(&self) -> Vec<u8> {
        vec![]
    }

    fn as_any(&mut self) -> &mut dyn Any {
        self
    }
}

/// A handler to pass requests to device of a rusb USB device of the host
#[derive(Clone, Debug)]
pub struct RusbUsbHostDeviceHandler {
    handle: Arc<Mutex<DeviceHandle<GlobalContext>>>,
}

impl RusbUsbHostDeviceHandler {
    pub fn new(handle: Arc<Mutex<DeviceHandle<GlobalContext>>>) -> Self {
        Self { handle }
    }
}

impl UsbDeviceHandler for RusbUsbHostDeviceHandler {
    fn handle_urb(
        &mut self,
        transfer_buffer_length: u32,
        setup: SetupPacket,
        req: &[u8],
    ) -> Result<Vec<u8>> {
        debug!("To host device: setup={setup:?} req={req:?}");
        let mut buffer = vec![0u8; transfer_buffer_length as usize];
        let timeout = std::time::Duration::new(1, 0);
        let handle = self.handle.lock().unwrap();
        // control
        if setup.request_type & 0x80 == 0 {
            // control out
            handle
                .write_control(
                    setup.request_type,
                    setup.request,
                    setup.value,
                    setup.index,
                    req,
                    timeout,
                )
                .ok();
        } else {
            // control in
            if let Ok(len) = handle.read_control(
                setup.request_type,
                setup.request,
                setup.value,
                setup.index,
                &mut buffer,
                timeout,
            ) {
                return Ok(Vec::from(&buffer[..len]));
            }
        }
        Ok(vec![])
    }

    fn as_any(&mut self) -> &mut dyn Any {
        self
    }
}

/// A handler to pass requests to interface of a nusb USB device of the host
#[derive(Clone)]
pub struct NusbUsbHostInterfaceHandler {
    handle: Arc<Mutex<nusb::Interface>>,
}

impl std::fmt::Debug for NusbUsbHostInterfaceHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NusbUsbHostInterfaceHandler")
            .field("handle", &"Opaque")
            .finish()
    }
}

impl NusbUsbHostInterfaceHandler {
    pub fn new(handle: Arc<Mutex<nusb::Interface>>) -> Self {
        Self { handle }
    }
}

impl UsbInterfaceHandler for NusbUsbHostInterfaceHandler {
    fn handle_urb(
        &mut self,
        _interface: &UsbInterface,
        ep: UsbEndpoint,
        transfer_buffer_length: u32,
        setup: SetupPacket,
        req: &[u8],
    ) -> Result<Vec<u8>> {
        debug!("To host device: ep={ep:?} setup={setup:?} req={req:?}",);
        let timeout = std::time::Duration::new(1, 0);
        let handle = self.handle.lock().unwrap();
        if ep.attributes == EndpointAttributes::Control as u8 {
            // control
            if let Direction::In = ep.direction() {
                // control in
                let control_in = nusb::transfer::ControlIn {
                    control_type: match (setup.request_type >> 5) & 0b11 {
                        0 => nusb::transfer::ControlType::Standard,
                        1 => nusb::transfer::ControlType::Class,
                        2 => nusb::transfer::ControlType::Vendor,
                        _ => unimplemented!(),
                    },
                    recipient: match setup.request_type & 0b11111 {
                        0 => nusb::transfer::Recipient::Device,
                        1 => nusb::transfer::Recipient::Interface,
                        2 => nusb::transfer::Recipient::Endpoint,
                        3 => nusb::transfer::Recipient::Other,
                        _ => unimplemented!(),
                    },
                    request: setup.request,
                    value: setup.value,
                    index: setup.index,
                    length: transfer_buffer_length as u16,
                };
                if let Ok(data) = handle.control_in(control_in, timeout).wait() {
                    return Ok(data);
                }
            } else {
                // control out
                let control_out = nusb::transfer::ControlOut {
                    control_type: match (setup.request_type >> 5) & 0b11 {
                        0 => nusb::transfer::ControlType::Standard,
                        1 => nusb::transfer::ControlType::Class,
                        2 => nusb::transfer::ControlType::Vendor,
                        _ => unimplemented!(),
                    },
                    recipient: match setup.request_type & 0b11111 {
                        0 => nusb::transfer::Recipient::Device,
                        1 => nusb::transfer::Recipient::Interface,
                        2 => nusb::transfer::Recipient::Endpoint,
                        3 => nusb::transfer::Recipient::Other,
                        _ => unimplemented!(),
                    },
                    request: setup.request,
                    value: setup.value,
                    index: setup.index,
                    data: req,
                };
                handle.control_out(control_out, timeout).wait().ok();
            }
        } else if ep.attributes == EndpointAttributes::Interrupt as u8 {
            // interrupt
            if let Direction::In = ep.direction() {
                // interrupt in
                let mut endpoint = handle
                    .endpoint::<nusb::transfer::Interrupt, nusb::transfer::In>(ep.address)
                    .map_err(|e| {
                        std::io::Error::other(format!("Failed to open interrupt endpoint: {}", e))
                    })?;
                let buffer = endpoint.allocate(transfer_buffer_length as usize);
                let completion = endpoint.transfer_blocking(buffer, timeout);
                if completion.status.is_ok() {
                    return Ok(completion.buffer.to_vec());
                }
            } else {
                // interrupt out
                let mut endpoint = handle
                    .endpoint::<nusb::transfer::Interrupt, nusb::transfer::Out>(ep.address)
                    .map_err(|e| {
                        std::io::Error::other(format!("Failed to open interrupt endpoint: {}", e))
                    })?;
                if !req.is_empty() {
                    let mut buffer = endpoint.allocate(req.len());
                    buffer.copy_from_slice(req);
                    endpoint.transfer_blocking(buffer, timeout);
                }
            }
        } else if ep.attributes == EndpointAttributes::Bulk as u8 {
            // bulk
            if let Direction::In = ep.direction() {
                // bulk in
                let mut endpoint = handle
                    .endpoint::<nusb::transfer::Bulk, nusb::transfer::In>(ep.address)
                    .map_err(|e| {
                        std::io::Error::other(format!("Failed to open bulk endpoint: {}", e))
                    })?;
                let buffer = endpoint.allocate(transfer_buffer_length as usize);
                let completion = endpoint.transfer_blocking(buffer, timeout);
                if completion.status.is_ok() {
                    return Ok(completion.buffer.to_vec());
                }
            } else {
                // bulk out
                let mut endpoint = handle
                    .endpoint::<nusb::transfer::Bulk, nusb::transfer::Out>(ep.address)
                    .map_err(|e| {
                        std::io::Error::other(format!("Failed to open bulk endpoint: {}", e))
                    })?;
                if !req.is_empty() {
                    let mut buffer = endpoint.allocate(req.len());
                    buffer.copy_from_slice(req);
                    endpoint.transfer_blocking(buffer, timeout);
                }
            }
        }
        Ok(vec![])
    }

    fn get_class_specific_descriptor(&self) -> Vec<u8> {
        vec![]
    }

    fn as_any(&mut self) -> &mut dyn Any {
        self
    }
}

/// A handler to pass requests to device of a nusb USB device of the host
#[derive(Clone)]
pub struct NusbUsbHostDeviceHandler {
    handle: Arc<Mutex<nusb::Device>>,
}

impl std::fmt::Debug for NusbUsbHostDeviceHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NusbUsbHostDeviceHandler")
            .field("handle", &"Opaque")
            .finish()
    }
}

impl NusbUsbHostDeviceHandler {
    pub fn new(handle: Arc<Mutex<nusb::Device>>) -> Self {
        Self { handle }
    }
}

impl UsbDeviceHandler for NusbUsbHostDeviceHandler {
    fn handle_urb(
        &mut self,
        transfer_buffer_length: u32,
        setup: SetupPacket,
        req: &[u8],
    ) -> Result<Vec<u8>> {
        debug!("To host device: setup={setup:?} req={req:?}");
        let timeout = std::time::Duration::new(1, 0);
        let handle = self.handle.lock().unwrap();
        // control
        if cfg!(not(target_os = "windows")) {
            if setup.request_type & 0x80 == 0 {
                // control out
                #[cfg(not(target_os = "windows"))]
                {
                    let control_out = nusb::transfer::ControlOut {
                        control_type: match (setup.request_type >> 5) & 0b11 {
                            0 => nusb::transfer::ControlType::Standard,
                            1 => nusb::transfer::ControlType::Class,
                            2 => nusb::transfer::ControlType::Vendor,
                            _ => unimplemented!(),
                        },
                        recipient: match setup.request_type & 0b11111 {
                            0 => nusb::transfer::Recipient::Device,
                            1 => nusb::transfer::Recipient::Interface,
                            2 => nusb::transfer::Recipient::Endpoint,
                            3 => nusb::transfer::Recipient::Other,
                            _ => unimplemented!(),
                        },
                        request: setup.request,
                        value: setup.value,
                        index: setup.index,
                        data: req,
                    };
                    handle.control_out(control_out, timeout).wait().ok();
                }
            } else {
                // control in
                #[cfg(not(target_os = "windows"))]
                {
                    let control_in = nusb::transfer::ControlIn {
                        control_type: match (setup.request_type >> 5) & 0b11 {
                            0 => nusb::transfer::ControlType::Standard,
                            1 => nusb::transfer::ControlType::Class,
                            2 => nusb::transfer::ControlType::Vendor,
                            _ => unimplemented!(),
                        },
                        recipient: match setup.request_type & 0b11111 {
                            0 => nusb::transfer::Recipient::Device,
                            1 => nusb::transfer::Recipient::Interface,
                            2 => nusb::transfer::Recipient::Endpoint,
                            3 => nusb::transfer::Recipient::Other,
                            _ => unimplemented!(),
                        },
                        request: setup.request,
                        value: setup.value,
                        index: setup.index,
                        length: transfer_buffer_length as u16,
                    };
                    if let Ok(data) = handle.control_in(control_in, timeout).wait() {
                        return Ok(data);
                    }
                }
            }
        } else {
            warn!("Not supported in windows")
        }
        Ok(vec![])
    }

    fn as_any(&mut self) -> &mut dyn Any {
        self
    }
}
