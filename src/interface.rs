use super::*;
use tokio::sync::Notify;

/// Represent a USB interface
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct UsbInterface {
    pub interface_class: u8,
    pub interface_subclass: u8,
    pub interface_protocol: u8,
    pub endpoints: Vec<UsbEndpoint>,
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

    /// Gets a `Notify` that is signaled whenever the device has new data to
    /// report on an interrupt IN endpoint.
    ///
    /// When this returns `Some`, an interrupt IN URB that produces no data is
    /// kept **pending** by the server instead of being answered immediately
    /// with an empty buffer. The URB is completed as soon as the handler
    /// produces data and signals this `Notify`. This avoids a flood of empty
    /// completions when clients (e.g. `usbip-win2`) poll the endpoint at a very
    /// high rate (issue #63).
    ///
    /// The implementation should signal the `Notify` with
    /// [`Notify::notify_one`](tokio::sync::Notify::notify_one) — not
    /// `notify_waiters()` — so that a signal is not lost if it arrives while
    /// the server task is between checking for data and awaiting
    /// [`Notify::notified`](tokio::sync::Notify::notified), and so that a
    /// single event completes a single pending URB.
    ///
    /// Return `None` to keep the previous behaviour of answering interface URBs
    /// immediately (possibly with an empty buffer).
    fn pending_notify(&self) -> Option<Arc<Notify>> {
        None
    }

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
