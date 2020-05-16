use super::*;

#[derive(Clone)]
pub struct UsbHidHandler {
    pub report_descriptor: Vec<u8>,
}

impl UsbHidHandler {
    pub fn new_keyboard() -> Self {
        Self {
            report_descriptor: vec![
                0x05, 0x01, // Usage Page (Generic Desktop)
                0x09, 0x06, // Usage (Keyboard)
                0xA1, 0x01, // Collection (Application)
                0x05, 0x07, // Key Codes
                0x19, 0xE0, // Usage Min
                0x29, 0xE7, // Usage Max
                0x15, 0x00, // Logic Min
                0x25, 0x01, // Logic Max
                0x75, 0x01, // Report Size (1)
                0x95, 0x08, // Report Count (8)
                0x81, 0x02, // Input
                0x95, 0x01, // Report Count
                0x75, 0x08, // Report Size
                0x81, 0x01, // Input
                0x95, 0x05, // Report Count
                0x75, 0x01, // Report Size
                0x05, 0x08, // Usage Page
                0x19, 0x01, // Usage Min
                0x29, 0x05, // Usage Max
                0x91, 0x02, // Output
                0x95, 0x01, // Report Count
                0x75, 0x03, // Report Size,
                0x91, 0x01, // Output
                0x95, 0x06, // Report Count
                0x75, 0x08, // Report Size
                0x15, 0x00, // Logic Min
                0x25, 0x65, // Logic Max
                0x05, 0x07, // Usage Page
                0x19, 0x00, // Usage Min
                0x29, 0x65, // Usage Max
                0x81, 0x00, // Input (Data, Array)
                0xC0, // End collection
            ],
        }
    }
}

impl UsbInterfaceHandler for UsbHidHandler {
    fn handle_urb(
        &mut self,
        interface: &UsbInterface,
        ep: UsbEndpoint,
        setup: SetupPacket,
        req: &[u8],
    ) -> Result<Vec<u8>> {
        use StandardRequest::*;
        if ep.is_ep0() {
            // control transfers
            match (setup.request_type, FromPrimitive::from_u8(setup.request)) {
                (0b10000001, Some(GetDescriptor)) => {
                    // high byte: type
                    match FromPrimitive::from_u16(setup.value >> 8) {
                        Some(HidDescriptorType::Report) => {
                            return Ok(self.report_descriptor.clone());
                        }
                        _ => unimplemented!("hid descriptor {:?}", setup),
                    }
                }
                _ => unimplemented!("hid request {:?}", setup),
            }
        } else {
            // interrupt transfer
        }
        Ok(vec![])
    }

    fn get_class_specific_descriptor(&self) -> Vec<u8> {
        return vec![
            0x09,                         // bLength
            HidDescriptorType::Hid as u8, // bDescriptorType: HID
            0x11,
            0x01,                            // bcdHID 1.11
            0x00,                            // bCountryCode
            0x01,                            // bNumDescriptors
            HidDescriptorType::Report as u8, // bDescriptorType[0] HID
            self.report_descriptor.len() as u8,
            (self.report_descriptor.len() >> 8) as u8, // wDescriptorLength[0]
        ];
    }
}

#[derive(Copy, Clone, Debug, FromPrimitive)]
pub enum HidDescriptorType {
    Hid = 0x21,
    Report = 0x22,
    Physical = 0x23,
}
