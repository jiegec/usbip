use super::*;

#[derive(Clone)]
pub struct UsbInterface {
    pub interface_class: u8,
    pub interface_subclass: u8,
    pub interface_protocol: u8,
    pub endpoints: Vec<UsbEndpoint>,
    pub string_interface: u8,
    pub class_specific_descriptor: Vec<u8>,
    pub handler: Arc<Mutex<Box<dyn UsbInterfaceHandler + Send>>>,
}

pub trait UsbInterfaceHandler {
    fn get_class_specific_descriptor(&self) -> Vec<u8>;

    fn handle_urb(
        &mut self,
        interface: &UsbInterface,
        ep: UsbEndpoint,
        setup: SetupPacket,
        req: &[u8],
    ) -> Result<Vec<u8>>;

    fn as_any(&mut self) -> &mut dyn Any;
}
