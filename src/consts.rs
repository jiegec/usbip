use super::*;

/// A list of known USB speeds
#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum UsbSpeed {
    Unknown = 0x0,
    Low,
    Full,
    High,
    Wireless,
    Super,
    SuperPlus,
}

/// A list of defined USB class codes
// https://www.usb.org/defined-class-codes
#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ClassCode {
    SeeInterface = 0,
    Audio,
    CDC,
    HID,
    Physical = 0x05,
    Image,
    Printer,
    MassStorage,
    Hub,
    CDCData,
    SmartCard,
    ContentSecurity = 0x0D,
    Video,
    PersonalHealthcare,
    AudioVideo,
    Billboard,
    TypeCBridge,
    Diagnostic = 0xDC,
    WirelessController = 0xE0,
    Misc = 0xEF,
    ApplicationSpecific = 0xFE,
    VendorSpecific = 0xFF,
}

/// A list of defined USB endpoint attributes
#[derive(Copy, Clone, Debug, FromPrimitive)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum EndpointAttributes {
    Control = 0,
    Isochronous,
    Bulk,
    Interrupt,
}

/// USB endpoint direction: IN or OUT
/// Already exists in rusb crate
pub use rusb::Direction;

/// Emulated max packet size of EP0
pub const EP0_MAX_PACKET_SIZE: u16 = 64;

/// A list of defined USB standard requests
/// from USB 2.0 standard Table 9.4. Standard Request Codes
#[derive(Copy, Clone, Debug, FromPrimitive)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum StandardRequest {
    GetStatus = 0,
    ClearFeature = 1,
    SetFeature = 3,
    SetAddress = 5,
    GetDescriptor = 6,
    SetDescriptor = 7,
    GetConfiguration = 8,
    SetConfiguration = 9,
    GetInterface = 10,
    SetInterface = 11,
    SynchFrame = 12,
}

/// A list of defined USB descriptor types
/// from USB 2.0 standard Table 9.5. Descriptor Types
#[derive(Copy, Clone, Debug, FromPrimitive)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum DescriptorType {
    Device = 1,
    Configuration = 2,
    String = 3,
    Interface = 4,
    Endpoint = 5,
    DeviceQualifier = 6,
    OtherSpeedConfiguration = 7,
    InterfacePower = 8,
    OTG = 9,
    Debug = 0xA,
    InterfaceAssociation = 0xB,
    BOS = 0xF,
}
