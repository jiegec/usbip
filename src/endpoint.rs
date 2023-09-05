use super::*;

/// Represent a USB endpoint
#[derive(Clone, Copy, Debug, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct UsbEndpoint {
    /// bEndpointAddress
    pub address: u8,
    /// bmAttributes
    pub attributes: u8,
    /// wMaxPacketSize
    pub max_packet_size: u16,
    /// bInterval
    pub interval: u8,
}

impl UsbEndpoint {
    /// Get direction from MSB of address
    pub fn direction(&self) -> Direction {
        if self.address & 0x80 != 0 {
            Direction::In
        } else {
            Direction::Out
        }
    }

    /// Whether this is endpoint zero
    pub fn is_ep0(&self) -> bool {
        self.address & 0x7F == 0
    }
}
