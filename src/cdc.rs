//! Implement CDC(Communications) device
use super::*;

/// A handler of a CDC ACM(Abstract Control Model)
#[derive(Clone)]
pub struct UsbCdcAcmHandler {
    pub tx_buffer: Vec<u8>,
}

impl Default for UsbCdcAcmHandler {
    fn default() -> Self {
        Self::new()
    }
}

/// Sub class code for CDC ACM
pub const CDC_ACM_SUBCLASS: u8 = 0x02;

impl UsbCdcAcmHandler {
    pub fn new() -> Self {
        Self { tx_buffer: vec![] }
    }

    pub fn endpoints() -> Vec<UsbEndpoint> {
        vec![
            // state notification
            UsbEndpoint {
                address: 0x81,                                   // IN
                attributes: EndpointAttributes::Interrupt as u8, // Interrupt
                max_packet_size: 0x08,                           // 8 bytes
                interval: 10,
            },
            // bulk in
            UsbEndpoint {
                address: 0x82,                              // IN
                attributes: EndpointAttributes::Bulk as u8, // Bulk
                max_packet_size: 512,                       // 512 bytes
                interval: 0,
            },
            // bulk out
            UsbEndpoint {
                address: 0x02,                              // OUT
                attributes: EndpointAttributes::Bulk as u8, // Bulk
                max_packet_size: 512,                       // 512 bytes
                interval: 0,
            },
        ]
    }
}

impl UsbInterfaceHandler for UsbCdcAcmHandler {
    fn handle_urb(
        &mut self,
        _interface: &UsbInterface,
        ep: UsbEndpoint,
        _transfer_buffer_length: u32,
        _setup: SetupPacket,
        req: &[u8],
    ) -> Result<Vec<u8>> {
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
                info!(
                    "Got bulk out: {:?} \"{}\"",
                    req,
                    String::from_utf8_lossy(req)
                );
                return Ok(vec![]);
            } else {
                // bulk in
                // TODO: handle max packet size
                let resp = self.tx_buffer.clone();
                self.tx_buffer.clear();
                return Ok(resp);
            }
        }
        Ok(vec![])
    }

    fn get_class_specific_descriptor(&self) -> Vec<u8> {
        vec![
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
        ]
    }

    fn as_any(&mut self) -> &mut dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use crate::util::tests::*;

    use super::*;

    #[test]
    fn desc_verify() {
        setup_test_logger();
        let handler = UsbCdcAcmHandler::new();
        verify_descriptor(&handler.get_class_specific_descriptor());
    }
}
