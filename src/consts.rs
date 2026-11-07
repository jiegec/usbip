use super::*;

/// A list of known USB speeds
///
/// The discriminants mirror `enum usb_device_speed` in the Linux kernel
/// (`include/uapi/linux/usb/ch9.h`), because the value is sent verbatim to the
/// client in the device list and interpreted there as that enum.
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

// The host backends number their speed enums differently from Linux (nusb starts
// at `Low = 0` and has neither `Unknown` nor `Wireless`; libusb has no `Wireless`,
// so its `Super`/`SuperPlus` are one lower), hence the explicit mapping instead of
// `as u32`. Both enums are `#[non_exhaustive]`, so unknown future speeds fall back
// to `Unknown` rather than being misreported.
impl From<nusb::Speed> for UsbSpeed {
    fn from(speed: nusb::Speed) -> Self {
        match speed {
            nusb::Speed::Low => UsbSpeed::Low,
            nusb::Speed::Full => UsbSpeed::Full,
            nusb::Speed::High => UsbSpeed::High,
            nusb::Speed::Super => UsbSpeed::Super,
            nusb::Speed::SuperPlus => UsbSpeed::SuperPlus,
            _ => UsbSpeed::Unknown,
        }
    }
}

impl From<rusb::Speed> for UsbSpeed {
    fn from(speed: rusb::Speed) -> Self {
        match speed {
            rusb::Speed::Unknown => UsbSpeed::Unknown,
            rusb::Speed::Low => UsbSpeed::Low,
            rusb::Speed::Full => UsbSpeed::Full,
            rusb::Speed::High => UsbSpeed::High,
            rusb::Speed::Super => UsbSpeed::Super,
            rusb::Speed::SuperPlus => UsbSpeed::SuperPlus,
            _ => UsbSpeed::Unknown,
        }
    }
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
/// Re-exported from rusb for public API compatibility
#[allow(unused_imports)]
pub use rusb::Direction;

/// Emulated max packet size of EP0
///
/// This is `bMaxPacketSize0` of the device descriptor as a raw byte. For
/// SuperSpeed and above that field is an exponent, i.e. `9` means 512 bytes
/// (USB 3.2 §9.6.1), so host passthrough paths copy it from the device descriptor
/// instead of using this constant.
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
    /// DEVICE
    Device = 1,
    /// CONFIGURATION
    Configuration = 2,
    /// STRING
    String = 3,
    /// INTERFACE
    Interface = 4,
    /// ENDPOINT
    Endpoint = 5,
    /// DEVICE_QUALIFIER
    DeviceQualifier = 6,
    /// OTHER_SPEED_CONFIGURATION
    OtherSpeedConfiguration = 7,
    /// INTERFACE_POINTER
    InterfacePower = 8,
    /// OTG
    OTG = 9,
    /// DEBUG
    Debug = 0xA,
    /// INTERFACE_ASSOCIATION
    InterfaceAssociation = 0xB,
    /// BOS
    BOS = 0xF,
    // DEVICE CAPABILITY
    DeviceCapability = 0x10,
    /// SUPERSPEED_USB_ENDPOINT_COMPANION
    SuperspeedUsbEndpointCompanion = 0x30,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The speed reported to the client is `enum usb_device_speed`, so every host
    /// backend speed has to be mapped explicitly instead of cast.
    #[test]
    fn test_host_speeds_map_to_usb_speed() {
        let nusb_cases = [
            (nusb::Speed::Low, UsbSpeed::Low),
            (nusb::Speed::Full, UsbSpeed::Full),
            (nusb::Speed::High, UsbSpeed::High),
            (nusb::Speed::Super, UsbSpeed::Super),
            (nusb::Speed::SuperPlus, UsbSpeed::SuperPlus),
        ];
        for (speed, expected) in nusb_cases {
            assert_eq!(
                UsbSpeed::from(speed) as u32,
                expected as u32,
                "nusb {speed:?}"
            );
        }

        let rusb_cases = [
            (rusb::Speed::Unknown, UsbSpeed::Unknown),
            (rusb::Speed::Low, UsbSpeed::Low),
            (rusb::Speed::Full, UsbSpeed::Full),
            (rusb::Speed::High, UsbSpeed::High),
            (rusb::Speed::Super, UsbSpeed::Super),
            (rusb::Speed::SuperPlus, UsbSpeed::SuperPlus),
        ];
        for (speed, expected) in rusb_cases {
            assert_eq!(
                UsbSpeed::from(speed) as u32,
                expected as u32,
                "rusb {speed:?}"
            );
        }
    }
}
