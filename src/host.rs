//! Host USB
use super::*;

/// A handler of a CDC ACM
#[derive(Clone)]
pub struct UsbHostHandler {}

impl UsbHostHandler {
    pub fn new() -> Self {
        Self {}
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
        Ok(vec![])
    }

    fn get_class_specific_descriptor(&self) -> Vec<u8> {
        return vec![];
    }

    fn as_any(&mut self) -> &mut dyn Any {
        self
    }
}
