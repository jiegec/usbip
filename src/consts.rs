use super::*;

#[derive(Copy, Clone, Debug)]
pub enum UsbSpeed {
    Unknown = 0x0,
    Low,
    Full,
    High,
    Wireless,
    Super,
    SuperPlus,
}

// https://www.usb.org/defined-class-codes
#[derive(Copy, Clone, Debug)]
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

#[derive(Copy, Clone, Debug, FromPrimitive)]
pub enum EndpointAttributes {
    Control = 0,
    Isochronous,
    Bulk,
    Interrupt,
}

#[derive(Copy, Clone, Debug)]
pub enum Direction {
    In,
    Out,
}

pub const EP0_MAX_PACKET_SIZE: u16 = 64;

#[derive(Copy, Clone, Debug, FromPrimitive)]
pub enum StandardRequest {
    GetStatus = 0,
    ClearFeature = 1,
    SetFeature = 3,
    GetDescriptor = 6,
    SetDescriptor = 7,
    GetConfiguration = 8,
    SetConfiguration = 9,
    GetInterface = 0xA,
    SetInterface = 0x11,
    SynthFrame = 0x12,
}

#[derive(Copy, Clone, Debug, FromPrimitive)]
pub enum DescriptorType {
    Device = 1,
    Configuration = 2,
    String = 3,
    Interface = 4,
    BOS = 0xF,
}
