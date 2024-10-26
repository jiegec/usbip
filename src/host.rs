//! Host USB
use super::*;

/// A handler to pass requests to a rusb USB device of the host
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
        debug!(
            "To host device: ep={:?} setup={:?} req={:?}",
            ep, setup, req
        );
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

/// A handler to pass requests to a USB device of the host
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
        debug!("To host device: setup={:?} req={:?}", setup, req);
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

/// A handler to pass requests to a rusb USB device of the host
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
        debug!(
            "To host device: ep={:?} setup={:?} req={:?}",
            ep, setup, req
        );
        let mut buffer = vec![0u8; transfer_buffer_length as usize];
        let timeout = std::time::Duration::new(1, 0);
        let handle = self.handle.lock().unwrap();
        let control = nusb::transfer::Control {
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
        };
        if ep.attributes == EndpointAttributes::Control as u8 {
            // control
            if let Direction::In = ep.direction() {
                // control in
                if let Ok(len) = handle.control_in_blocking(control, &mut buffer, timeout) {
                    return Ok(Vec::from(&buffer[..len]));
                }
            } else {
                // control out
                handle.control_out_blocking(control, req, timeout).ok();
            }
        } else if ep.attributes == EndpointAttributes::Interrupt as u8 {
            // interrupt
            todo!("Missing blocking api for interrupt transfer in nusb")
        } else if ep.attributes == EndpointAttributes::Bulk as u8 {
            // bulk
            todo!("Missing blocking api for bulk transfer in nusb")
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

/// A handler to pass requests to a USB device of the host
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
        debug!("To host device: setup={:?} req={:?}", setup, req);
        let mut buffer = vec![0u8; transfer_buffer_length as usize];
        let timeout = std::time::Duration::new(1, 0);
        let handle = self.handle.lock().unwrap();
        let control = nusb::transfer::Control {
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
        };
        // control
        if setup.request_type & 0x80 == 0 {
            // control out
            handle.control_out_blocking(control, req, timeout).ok();
        } else {
            // control in
            if let Ok(len) = handle.control_in_blocking(control, &mut buffer, timeout) {
                return Ok(Vec::from(&buffer[..len]));
            }
        }
        Ok(vec![])
    }

    fn as_any(&mut self) -> &mut dyn Any {
        self
    }
}
