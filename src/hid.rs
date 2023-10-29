//! Implement HID device
use super::*;

// reference:
// HID 1.11: https://www.usb.org/sites/default/files/documents/hid1_11.pdf
// HID Usage Tables 1.12: https://www.usb.org/sites/default/files/documents/hut1_12v2.pdf

#[derive(Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
enum UsbHidKeyboardHandlerState {
    Idle,
    KeyDown,
}

/// A handler of a HID keyboard
#[derive(Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct UsbHidKeyboardHandler {
    pub report_descriptor: Vec<u8>,
    pub pending_key_events: VecDeque<UsbHidKeyboardReport>,
    state: UsbHidKeyboardHandlerState,
}

/// A report of a HID keyboard
///
/// For definition of key codes, see [HID Usage Tables](https://www.usb.org/sites/default/files/documents/hut1_12v2.pdf)
#[derive(Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct UsbHidKeyboardReport {
    /// Key modifier
    pub modifier: u8,
    /// Key code
    pub keys: [u8; 6],
}

impl UsbHidKeyboardReport {
    pub fn from_ascii(ascii: u8) -> UsbHidKeyboardReport {
        // TODO: casing
        let key = match ascii {
            b'a'..=b'z' => ascii - b'a' + 4,
            b'1'..=b'9' => ascii - b'1' + 30,
            b'0' => 39,
            b'\r' | b'\n' => 40,
            _ => unimplemented!("Unrecognized ascii {}", ascii),
        };
        UsbHidKeyboardReport {
            modifier: 0,
            keys: [key, 0, 0, 0, 0, 0],
        }
    }
}

impl UsbHidKeyboardHandler {
    pub fn new_keyboard() -> Self {
        Self {
            pending_key_events: VecDeque::new(),
            state: UsbHidKeyboardHandlerState::Idle,
            report_descriptor: vec![
                0x05, 0x01, // Usage Page (Generic Desktop)
                0x09, 0x06, // Usage (Keyboard)
                0xA1, 0x01, // Collection (Application)
                // Modifier
                0x05, 0x07, // Key Codes
                0x19, 0xE0, // Usage Min
                0x29, 0xE7, // Usage Max
                0x15, 0x00, // Logic Min
                0x25, 0x01, // Logic Max
                0x75, 0x01, // Report Size (1)
                0x95, 0x08, // Report Count (8)
                0x81, 0x02, // Input
                // Reserved
                0x95, 0x01, // Report Count (1)
                0x75, 0x08, // Report Size (8)
                0x81, 0x01, // Input
                // key codes
                0x95, 0x06, // Report Count (6)
                0x75, 0x08, // Report Size (8)
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

impl UsbInterfaceHandler for UsbHidKeyboardHandler {
    fn handle_urb(
        &mut self,
        _interface: &UsbInterface,
        ep: UsbEndpoint,
        _transfer_buffer_length: u32,
        setup: SetupPacket,
        _req: &[u8],
    ) -> Result<Vec<u8>> {
        if ep.is_ep0() {
            // control transfers
            match (setup.request_type, setup.request) {
                (0b10000001, 0x06) => {
                    // GET_DESCRIPTOR
                    // high byte: type
                    match FromPrimitive::from_u16(setup.value >> 8) {
                        Some(HidDescriptorType::Report) => {
                            return Ok(self.report_descriptor.clone());
                        }
                        _ => unimplemented!("hid descriptor {:?}", setup),
                    }
                }
                (0b00100001, 0x0A) => {
                    // SET_IDLE
                    return Ok(vec![]);
                }
                _ => unimplemented!("hid request {:?}", setup),
            }
        } else {
            // interrupt transfer
            if let Direction::In = ep.direction() {
                // interrupt in
                match self.state {
                    UsbHidKeyboardHandlerState::Idle => {
                        if let Some(report) = self.pending_key_events.pop_front() {
                            let mut resp = vec![report.modifier, 0];
                            resp.extend_from_slice(&report.keys);
                            info!("HID key down");
                            self.state = UsbHidKeyboardHandlerState::KeyDown;
                            return Ok(resp);
                        }
                    }
                    UsbHidKeyboardHandlerState::KeyDown => {
                        let resp = vec![0; 6];
                        info!("HID key up");
                        self.state = UsbHidKeyboardHandlerState::Idle;
                        return Ok(resp);
                    }
                }
            }
        }
        Ok(vec![])
    }

    fn get_class_specific_descriptor(&self) -> Vec<u8> {
        vec![
            0x09,                         // bLength
            HidDescriptorType::Hid as u8, // bDescriptorType: HID
            0x11,
            0x01,                            // bcdHID 1.11
            0x00,                            // bCountryCode
            0x01,                            // bNumDescriptors
            HidDescriptorType::Report as u8, // bDescriptorType[0] HID
            self.report_descriptor.len() as u8,
            (self.report_descriptor.len() >> 8) as u8, // wDescriptorLength[0]
        ]
    }

    fn as_any(&mut self) -> &mut dyn Any {
        self
    }
}

/// A list of defined HID descriptor type
#[derive(Copy, Clone, Debug, FromPrimitive)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum HidDescriptorType {
    Hid = 0x21,
    Report = 0x22,
    Physical = 0x23,
}

#[cfg(test)]
mod tests {
    use crate::util::tests::*;

    use super::*;

    #[test]
    fn desc_verify() {
        setup_test_logger();
        let handler = UsbHidKeyboardHandler::new_keyboard();
        verify_descriptor(&handler.get_class_specific_descriptor());
    }
}
