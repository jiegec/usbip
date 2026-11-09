use super::*;

/// Represent a USB interface
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct UsbInterface {
    pub interface_class: u8,
    pub interface_subclass: u8,
    pub interface_protocol: u8,
    pub endpoints: Vec<UsbEndpoint>,
    /// Extra descriptors that follow each endpoint descriptor, aligned with
    /// `endpoints`.
    ///
    /// These carry class- or speed-specific endpoint descriptors such as the UAS
    /// Pipe Usage descriptor and the SuperSpeed Endpoint Companion. Host
    /// passthrough copies them verbatim from the real device; for simulated
    /// devices the list may be empty.
    pub endpoint_extra: Vec<Vec<u8>>,
    pub string_interface: u8,
    pub class_specific_descriptor: Vec<u8>,

    #[cfg_attr(feature = "serde", serde(skip))]
    pub handler: Arc<Mutex<Box<dyn UsbInterfaceHandler + Send>>>,
}

/// A handler of a custom usb interface
pub trait UsbInterfaceHandler: std::fmt::Debug {
    /// Return the class specific descriptor which is inserted between interface descriptor and endpoint descriptor
    fn get_class_specific_descriptor(&self) -> Vec<u8>;

    /// Handle a URB(USB Request Block) targeting at this interface
    ///
    /// Can be one of: control transfer to ep0 or other types of transfer to its endpoint.
    /// The resulting data should not exceed `transfer_buffer_length`.
    fn handle_urb(
        &mut self,
        interface: &UsbInterface,
        ep: UsbEndpoint,
        transfer_buffer_length: u32,
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
