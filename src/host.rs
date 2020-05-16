//! Host USB
use super::*;

/// A handler of a CDC ACM
#[derive(Clone)]
pub struct UsbHostHandler {
    handle: Arc<DeviceHandle<GlobalContext>>,
}

impl UsbHostHandler {
    pub fn new(handle: Arc<DeviceHandle<GlobalContext>>) -> Self {
        Self { handle }
    }
}

impl UsbInterfaceHandler for UsbHostHandler {
    fn handle_urb(
        &mut self,
        interface: &UsbInterface,
        ep: UsbEndpoint,
        setup: SetupPacket,
        req: &[u8],
    ) -> Result<Vec<u8>> {
        use StandardRequest::*;
        debug!(
            "To host device: ep={:?} setup={:?} req={:?}",
            ep, setup, req
        );
        let mut buffer = [0u8; 1024];
        let timeout = std::time::Duration::new(1, 0);
        if ep.attributes == EndpointAttributes::Control as u8 {
            // control
            if let Direction::In = ep.direction() {
                // control in
                let len = self
                    .handle
                    .read_control(
                        setup.request_type,
                        setup.request,
                        setup.value,
                        setup.index,
                        &mut buffer,
                        timeout,
                    )
                    .unwrap();
                return Ok(Vec::from(&buffer[..len]));
            }
        } else if ep.attributes == EndpointAttributes::Interrupt as u8 {
            // interrupt
            if let Direction::In = ep.direction() {
                // interrupt in
                if let Ok(len) = self.handle.read_interrupt(ep.address, &mut buffer, timeout) {
                    return Ok(Vec::from(&buffer[..len]));
                }
            }
        }
        Ok(vec![])
    }

    fn get_class_specific_descriptor(&self) -> Vec<u8> {
        return vec![];
    }

    fn as_any(&mut self) -> &mut dyn Any {
        self
    }
}
