use super::*;

#[derive(Clone, Copy, Debug, Default)]
pub struct UsbEndpoint {
    pub address: u8,
    pub attributes: u8,
    pub max_packet_size: u16,
    pub interval: u8,
}

impl UsbEndpoint {
    pub(crate) fn direction(&self) -> Direction {
        if self.address & 0x80 != 0 {
            Direction::In
        } else {
            Direction::Out
        }
    }

    pub fn is_ep0(&self) -> bool {
        self.address & 0x7F == 0
    }
}
