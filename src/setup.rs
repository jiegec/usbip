use super::*;

#[derive(Clone, Copy, Debug, Default)]
pub struct SetupPacket {
    pub request_type: u8,
    pub request: u8,
    pub value: u16,
    pub index: u16,
    pub length: u16,
}

impl SetupPacket {
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
