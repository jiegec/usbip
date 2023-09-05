use super::*;

/// Parse the SETUP packet of control transfers
#[derive(Clone, Copy, Debug, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SetupPacket {
    /// bmRequestType
    pub request_type: u8,
    /// bRequest
    pub request: u8,
    /// wValue
    pub value: u16,
    /// wIndex
    pub index: u16,
    /// wLength
    pub length: u16,
}

impl SetupPacket {
    /// Parse a [SetupPacket] from raw setup packet
    pub fn parse(setup: &[u8; 8]) -> SetupPacket {
        SetupPacket {
            request_type: setup[0],
            request: setup[1],
            value: (setup[3] as u16) << 8 | (setup[2] as u16),
            index: (setup[5] as u16) << 8 | (setup[4] as u16),
            length: (setup[7] as u16) << 8 | (setup[6] as u16),
        }
    }
}
