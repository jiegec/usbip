//! CDC
use super::*;

/// A handler of a CDC ACM
#[derive(Clone)]
pub struct UsbCDCACMHandler {}

pub const CDC_ACM_SUBCLASS: u8 = 0x02;

impl UsbCDCACMHandler {
    pub fn new() -> Self {
        Self {}
    }
}

impl UsbInterfaceHandler for UsbCDCACMHandler {
    fn handle_urb(
        &mut self,
        interface: &UsbInterface,
        ep: UsbEndpoint,
        setup: SetupPacket,
        req: &[u8],
    ) -> Result<Vec<u8>> {
        use StandardRequest::*;
        if ep.attributes == EndpointAttributes::Interrupt as u8 {
            // interrupt
            if let Direction::In = ep.direction() {
                // interrupt in
                return Ok(vec![]);
            }
        } else {
            // bulk
            if let Direction::Out = ep.direction() {
                // bulk out
                info!("Got bulk out: {}", String::from_utf8_lossy(&req));
                return Ok(vec![]);
            } else {
                return Ok(vec![]);
            }
        }
        Ok(vec![])
    }

    fn get_class_specific_descriptor(&self) -> Vec<u8> {
        return vec![
            // Header
            0x05, // bFunctionLength
            0x24, // CS_INTERFACE
            0x00, // Header
            0x10, 0x01, // CDC 1.2
            // ACM
            0x04, // bFunctionLength
            0x24, // CS_INTERFACE
            0x02, // ACM
            0x00, // Capabilities
        ];
    }

    fn as_any(&mut self) -> &mut dyn Any {
        self
    }
}
