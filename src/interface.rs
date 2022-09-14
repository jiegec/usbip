use super::*;

/// Represent a USB interface
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

/// A handler of a custom usb interface
pub trait UsbInterfaceHandler {
    /// Return the class specific descriptor which is inserted between interface descriptor and endpoint descriptor
    fn get_class_specific_descriptor(&self) -> Vec<u8>;

    /// Handle a URB(USB Request Block) targeting at this interface
    ///
    /// Can be one of: control transfer to ep0 or other types of transfer to its endpoint
    fn handle_urb(
        &mut self,
        interface: &UsbInterface,
        ep: UsbEndpoint,
        setup: SetupPacket,
        req: &[u8],
    ) -> Result<Vec<u8>>;

    /// Helper to downcast to actual struct
    ///
    /// Please implement it as:
    /// ```ignore
    /// fn as_any(&mut self) -> &mut dyn Any {
    ///     self
    /// }
    /// ```
    fn as_any(&mut self) -> &mut dyn Any;
}
