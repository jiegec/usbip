use super::*;

#[derive(Clone, Debug, Default)]
pub struct UsbInterface {
    pub interface_class: u8,
    pub interface_subclass: u8,
    pub interface_protocol: u8,
    pub endpoints: Vec<UsbEndpoint>,
}
