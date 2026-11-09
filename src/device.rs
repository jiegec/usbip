use super::*;
use rusb::Version as rusbVersion;

#[derive(Clone, Default, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Version {
    pub major: u8,
    pub minor: u8,
    pub patch: u8,
}

impl From<rusbVersion> for Version {
    fn from(value: rusbVersion) -> Self {
        Self {
            major: value.major(),
            minor: value.minor(),
            patch: value.sub_minor(),
        }
    }
}

impl From<Version> for rusbVersion {
    fn from(val: Version) -> Self {
        rusbVersion(val.major, val.minor, val.patch)
    }
}

/// bcdDevice
impl From<u16> for Version {
    fn from(value: u16) -> Self {
        Self {
            major: (value >> 8) as u8,
            minor: ((value >> 4) & 0xF) as u8,
            patch: (value & 0xF) as u8,
        }
    }
}

impl Version {
    /// Little-endian BCD encoding of the version, as used by `bcdUSB` and
    /// `bcdDevice`.
    ///
    /// The fields are decimal digits (see [`From<u16>`] and [`rusb::Version`]):
    /// `major.minor.patch`, so the low byte is `(minor << 4) | patch`.
    fn bcd(&self) -> [u8; 2] {
        [((self.minor & 0xF) << 4) | (self.patch & 0xF), self.major]
    }
}

/// Represent a USB device
#[derive(Clone, Default, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct UsbDevice {
    pub path: String,
    pub bus_id: String,
    pub bus_num: u32,
    pub dev_num: u32,
    /// One of [`UsbSpeed`]'s values; prefer [`UsbDevice::set_speed`], which also
    /// updates the ep0 max packet size
    pub speed: u32,
    pub vendor_id: u16,
    pub product_id: u16,
    pub device_bcd: Version,
    pub device_class: u8,
    pub device_subclass: u8,
    pub device_protocol: u8,
    pub configuration_value: u8,
    pub num_configurations: u8,
    pub interfaces: Vec<UsbInterface>,

    #[cfg_attr(feature = "serde", serde(skip))]
    pub device_handler: Option<Arc<Mutex<Box<dyn UsbDeviceHandler + Send>>>>,

    pub usb_version: Version,

    /// Raw BOS descriptor of the device, if it provides one.
    ///
    /// The BOS descriptor and its capabilities (e.g. the SuperSpeed USB device
    /// capability with U1/U2 exit latencies) are passed through verbatim for
    /// host passthrough devices; empty for simulated devices.
    pub bos: Vec<u8>,

    // ep0 endpoints; `max_packet_size` holds `bMaxPacketSize0` as a raw
    // descriptor byte, see [EP0_MAX_PACKET_SIZE]
    pub(crate) ep0_in: UsbEndpoint,
    pub(crate) ep0_out: UsbEndpoint,
    // strings
    pub(crate) string_pool: HashMap<u8, String>,
    pub(crate) string_configuration: u8,
    pub(crate) string_manufacturer: u8,
    pub(crate) string_product: u8,
    pub(crate) string_serial: u8,
}

impl UsbDevice {
    pub fn new(index: u32) -> Self {
        let mut res = Self {
            path: "/sys/bus/0/0/0".to_string(),
            bus_id: "0-0-0".to_string(),
            dev_num: index,
            speed: UsbSpeed::High as u32,
            ep0_in: UsbEndpoint {
                address: 0x80,
                attributes: EndpointAttributes::Control as u8,
                max_packet_size: EP0_MAX_PACKET_SIZE,
                interval: 0,
            },
            ep0_out: UsbEndpoint {
                address: 0x00,
                attributes: EndpointAttributes::Control as u8,
                max_packet_size: EP0_MAX_PACKET_SIZE,
                interval: 0,
            },
            // configured by default
            configuration_value: 1,
            num_configurations: 1,
            ..Self::default()
        };
        res.string_configuration = res.new_string("Default Configuration");
        res.string_manufacturer = res.new_string("Manufacturer");
        res.string_product = res.new_string("Product");
        res.string_serial = res.new_string("Serial");
        res
    }

    /// Returns the old value, if present.
    pub fn set_configuration_name(&mut self, name: &str) -> Option<String> {
        let old = (self.string_configuration != 0)
            .then(|| self.string_pool.remove(&self.string_configuration))
            .flatten();
        self.string_configuration = self.new_string(name);
        old
    }

    /// Unset configuration name and returns the old value, if present.
    pub fn unset_configuration_name(&mut self) -> Option<String> {
        let old = (self.string_configuration != 0)
            .then(|| self.string_pool.remove(&self.string_configuration))
            .flatten();
        self.string_configuration = 0;
        old
    }

    /// Returns the old value, if present.
    pub fn set_serial_number(&mut self, name: &str) -> Option<String> {
        let old = (self.string_serial != 0)
            .then(|| self.string_pool.remove(&self.string_serial))
            .flatten();
        self.string_serial = self.new_string(name);
        old
    }

    /// Unset serial number and returns the old value, if present.
    pub fn unset_serial_number(&mut self) -> Option<String> {
        let old = (self.string_serial != 0)
            .then(|| self.string_pool.remove(&self.string_serial))
            .flatten();
        self.string_serial = 0;
        old
    }

    /// Returns the old value, if present.
    pub fn set_product_name(&mut self, name: &str) -> Option<String> {
        let old = (self.string_product != 0)
            .then(|| self.string_pool.remove(&self.string_product))
            .flatten();
        self.string_product = self.new_string(name);
        old
    }

    /// Unset product name and returns the old value, if present.
    pub fn unset_product_name(&mut self) -> Option<String> {
        let old = (self.string_product != 0)
            .then(|| self.string_pool.remove(&self.string_product))
            .flatten();
        self.string_product = 0;
        old
    }

    /// Returns the old value, if present.
    pub fn set_manufacturer_name(&mut self, name: &str) -> Option<String> {
        let old = (self.string_manufacturer != 0)
            .then(|| self.string_pool.remove(&self.string_manufacturer))
            .flatten();
        self.string_manufacturer = self.new_string(name);
        old
    }

    /// Unset manufacturer name and returns the old value, if present.
    pub fn unset_manufacturer_name(&mut self) -> Option<String> {
        let old = (self.string_manufacturer != 0)
            .then(|| self.string_pool.remove(&self.string_manufacturer))
            .flatten();
        self.string_manufacturer = 0;
        old
    }

    pub fn with_interface(
        mut self,
        interface_class: u8,
        interface_subclass: u8,
        interface_protocol: u8,
        name: Option<&str>,
        endpoints: Vec<UsbEndpoint>,
        handler: Arc<Mutex<Box<dyn UsbInterfaceHandler + Send>>>,
    ) -> Self {
        let string_interface = name.map(|name| self.new_string(name)).unwrap_or(0);
        let class_specific_descriptor = handler.lock().unwrap().get_class_specific_descriptor();
        self.interfaces.push(UsbInterface {
            interface_class,
            interface_subclass,
            interface_protocol,
            endpoints,
            endpoint_extra: Vec::new(),
            string_interface,
            class_specific_descriptor,
            handler,
        });
        self
    }

    pub fn with_device_handler(
        mut self,
        handler: Arc<Mutex<Box<dyn UsbDeviceHandler + Send>>>,
    ) -> Self {
        self.device_handler = Some(handler);
        self
    }

    /// Set the USB speed, keeping the ep0 max packet size in sync.
    ///
    /// Prefer this over assigning [`UsbDevice::speed`] directly: `bMaxPacketSize0`
    /// depends on the speed (8 at low speed, 64 at full/high speed, and the
    /// exponent 9 - meaning 512 bytes - at SuperSpeed and above, USB 3.2 §9.6.1),
    /// and a mismatch makes the device fail to enumerate on the client.
    pub fn set_speed(&mut self, speed: UsbSpeed) {
        self.speed = speed as u32;
        let max_packet_size_0 = match speed {
            UsbSpeed::Low => 8,
            UsbSpeed::Full | UsbSpeed::High => 64,
            // exponent, not a size: 2^9 == 512 bytes
            UsbSpeed::Super | UsbSpeed::SuperPlus => 9,
            UsbSpeed::Unknown | UsbSpeed::Wireless => EP0_MAX_PACKET_SIZE,
        };
        self.ep0_in.max_packet_size = max_packet_size_0;
        self.ep0_out.max_packet_size = max_packet_size_0;
    }

    /// `bMaxPacketSize0` of the device qualifier descriptor, which describes the
    /// device operating at high speed. At SuperSpeed and above the device
    /// descriptor carries the exponent 9 instead, which is not a size and must not
    /// be reported here (USB 2.0 §5.5.3 requires 64 at high speed).
    fn qualifier_max_packet_size_0(&self) -> u8 {
        if self.speed >= UsbSpeed::Super as u32 {
            64
        } else {
            self.ep0_in.max_packet_size as u8
        }
    }

    pub(crate) fn new_string(&mut self, s: &str) -> u8 {
        for i in 1.. {
            if let std::collections::hash_map::Entry::Vacant(e) = self.string_pool.entry(i) {
                e.insert(s.to_string());
                return i;
            }
        }
        panic!("string poll exhausted")
    }

    pub(crate) fn find_ep(&self, ep: u8) -> Option<(UsbEndpoint, Option<&UsbInterface>)> {
        if ep == self.ep0_in.address {
            Some((self.ep0_in, None))
        } else if ep == self.ep0_out.address {
            Some((self.ep0_out, None))
        } else {
            for intf in &self.interfaces {
                for endpoint in &intf.endpoints {
                    if endpoint.address == ep {
                        return Some((*endpoint, Some(intf)));
                    }
                }
            }
            None
        }
    }

    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(312);

        let mut path = self.path.as_bytes().to_vec();
        debug_assert!(path.len() <= 256);
        path.resize(256, 0);
        result.extend_from_slice(path.as_slice());

        let mut bus_id = self.bus_id.as_bytes().to_vec();
        debug_assert!(bus_id.len() <= 32);
        bus_id.resize(32, 0);
        result.extend_from_slice(bus_id.as_slice());

        result.extend_from_slice(&self.bus_num.to_be_bytes());
        result.extend_from_slice(&self.dev_num.to_be_bytes());
        result.extend_from_slice(&self.speed.to_be_bytes());
        result.extend_from_slice(&self.vendor_id.to_be_bytes());
        result.extend_from_slice(&self.product_id.to_be_bytes());
        result.push(self.device_bcd.major);
        result.push(self.device_bcd.minor);
        result.push(self.device_class);
        result.push(self.device_subclass);
        result.push(self.device_protocol);
        result.push(self.configuration_value);
        result.push(self.num_configurations);
        result.push(self.interfaces.len() as u8);

        result
    }

    pub(crate) fn to_bytes_with_interfaces(&self) -> Vec<u8> {
        let mut result = self.to_bytes();
        result.reserve(4 * self.interfaces.len());

        for intf in &self.interfaces {
            result.push(intf.interface_class);
            result.push(intf.interface_subclass);
            result.push(intf.interface_protocol);
            result.push(0); // padding
        }

        result
    }

    pub(crate) async fn handle_urb(
        &self,
        ep: UsbEndpoint,
        intf: Option<&UsbInterface>,
        transfer_buffer_length: u32,
        setup_packet: SetupPacket,
        out_data: &[u8],
    ) -> Result<Vec<u8>> {
        use DescriptorType::*;
        use Direction::*;
        use EndpointAttributes::*;
        use StandardRequest::*;

        match (FromPrimitive::from_u8(ep.attributes), ep.direction()) {
            (Some(Control), In) => {
                // control in
                debug!("Control IN setup={setup_packet:x?}");
                match (
                    setup_packet.request_type,
                    FromPrimitive::from_u8(setup_packet.request),
                ) {
                    (0b10000000, Some(GetDescriptor)) => {
                        // high byte: type
                        match FromPrimitive::from_u16(setup_packet.value >> 8) {
                            Some(Device) => {
                                debug!("Get device descriptor");
                                // Standard Device Descriptor
                                let usb_version = self.usb_version.bcd();
                                let device_bcd = self.device_bcd.bcd();
                                let mut desc = vec![
                                    0x12,         // bLength
                                    Device as u8, // bDescriptorType: Device
                                    usb_version[0],
                                    usb_version[1],                    // bcdUSB
                                    self.device_class,                 // bDeviceClass
                                    self.device_subclass,              // bDeviceSubClass
                                    self.device_protocol,              // bDeviceProtocol
                                    self.ep0_in.max_packet_size as u8, // bMaxPacketSize0
                                    self.vendor_id as u8,              // idVendor
                                    (self.vendor_id >> 8) as u8,
                                    self.product_id as u8, // idProduct
                                    (self.product_id >> 8) as u8,
                                    device_bcd[0],
                                    device_bcd[1],            // bcdDevice
                                    self.string_manufacturer, // iManufacturer
                                    self.string_product,      // iProduct
                                    self.string_serial,       // iSerial
                                    self.num_configurations,  // bNumConfigurations
                                ];

                                // requested len too short: wLength < real length
                                if setup_packet.length < desc.len() as u16 {
                                    desc.resize(setup_packet.length as usize, 0);
                                }
                                Ok(desc)
                            }
                            Some(BOS) => {
                                debug!("Get BOS descriptor");
                                let mut desc = if self.bos.is_empty() {
                                    vec![
                                        0x05,      // bLength
                                        BOS as u8, // bDescriptorType: BOS
                                        0x05, 0x00, // wTotalLength
                                        0x00, // bNumCapabilities
                                    ]
                                } else {
                                    self.bos.clone()
                                };

                                // requested len too short: wLength < real length
                                if setup_packet.length < desc.len() as u16 {
                                    desc.resize(setup_packet.length as usize, 0);
                                }
                                Ok(desc)
                            }
                            Some(Configuration) => {
                                debug!("Get configuration descriptor");
                                // Standard Configuration Descriptor
                                let mut desc = vec![
                                    0x09,                // bLength
                                    Configuration as u8, // bDescriptorType: Configuration
                                    0x00,
                                    0x00, // wTotalLength: to be filled below
                                    self.interfaces.len() as u8, // bNumInterfaces
                                    self.configuration_value, // bConfigurationValue
                                    self.string_configuration, // iConfiguration
                                    0x80, // bmAttributes: Bus Powered
                                    0x32, // bMaxPower: 100mA
                                ];
                                for (i, intf) in self.interfaces.iter().enumerate() {
                                    let mut intf_desc = vec![
                                        0x09,                       // bLength
                                        Interface as u8,            // bDescriptorType: Interface
                                        i as u8,                    // bInterfaceNum
                                        0x00,                       // bAlternateSettings
                                        intf.endpoints.len() as u8, // bNumEndpoints
                                        intf.interface_class,       // bInterfaceClass
                                        intf.interface_subclass,    // bInterfaceSubClass
                                        intf.interface_protocol,    // bInterfaceProtocol
                                        intf.string_interface,      //iInterface
                                    ];
                                    // class specific endpoint
                                    let mut specific = intf.class_specific_descriptor.clone();
                                    intf_desc.append(&mut specific);
                                    // endpoint descriptors
                                    for (j, endpoint) in intf.endpoints.iter().enumerate() {
                                        let mut ep_desc = vec![
                                            0x07,                // bLength
                                            Endpoint as u8,      // bDescriptorType: Endpoint
                                            endpoint.address,    // bEndpointAddress
                                            endpoint.attributes, // bmAttributes
                                            endpoint.max_packet_size as u8,
                                            (endpoint.max_packet_size >> 8) as u8, // wMaxPacketSize
                                            endpoint.interval,                     // bInterval
                                        ];
                                        intf_desc.append(&mut ep_desc);
                                        // e.g. SuperSpeed endpoint companion or UAS
                                        // pipe usage, which must directly follow the
                                        // endpoint descriptor.
                                        if let Some(extra) = intf.endpoint_extra.get(j) {
                                            intf_desc.extend_from_slice(extra);
                                        }
                                    }
                                    desc.append(&mut intf_desc);
                                }
                                // length
                                let len = desc.len() as u16;
                                desc[2] = len as u8;
                                desc[3] = (len >> 8) as u8;

                                // requested len too short: wLength < real length
                                if setup_packet.length < desc.len() as u16 {
                                    desc.resize(setup_packet.length as usize, 0);
                                }
                                Ok(desc)
                            }
                            Some(String) => {
                                debug!("Get string descriptor");
                                let index = setup_packet.value as u8;
                                if index == 0 {
                                    // String Descriptor Zero, Specifying Languages Supported by the Device
                                    // language ids
                                    let mut desc = vec![
                                        4,                            // bLength
                                        DescriptorType::String as u8, // bDescriptorType
                                        0x09,
                                        0x04, // wLANGID[0], en-US
                                    ];
                                    // requested len too short: wLength < real length
                                    if setup_packet.length < desc.len() as u16 {
                                        desc.resize(setup_packet.length as usize, 0);
                                    }
                                    Ok(desc)
                                } else if let Some(s) = &self.string_pool.get(&index) {
                                    // UNICODE String Descriptor
                                    let bytes: Vec<u16> = s.encode_utf16().collect();
                                    let mut desc = vec![
                                        2 + bytes.len() as u8 * 2,    // bLength
                                        DescriptorType::String as u8, // bDescriptorType
                                    ];
                                    for byte in bytes {
                                        desc.push(byte as u8);
                                        desc.push((byte >> 8) as u8);
                                    }

                                    // requested len too short: wLength < real length
                                    if setup_packet.length < desc.len() as u16 {
                                        desc.resize(setup_packet.length as usize, 0);
                                    }
                                    Ok(desc)
                                } else {
                                    Err(std::io::Error::new(
                                        std::io::ErrorKind::InvalidInput,
                                        format!("Invalid string index: {index}"),
                                    ))
                                }
                            }
                            Some(DeviceQualifier) => {
                                debug!("Get device qualifier descriptor");
                                // Device_Qualifier Descriptor
                                let usb_version = self.usb_version.bcd();
                                let mut desc = vec![
                                    0x0A,                  // bLength
                                    DeviceQualifier as u8, // bDescriptorType: Device Qualifier
                                    usb_version[0],
                                    usb_version[1],                     // bcdUSB
                                    self.device_class,                  // bDeviceClass
                                    self.device_subclass,               // bDeviceSUbClass
                                    self.device_protocol,               // bDeviceProtocol
                                    self.qualifier_max_packet_size_0(), // bMaxPacketSize0
                                    self.num_configurations,            // bNumConfigurations
                                    0x00,                               // bReserved
                                ];

                                // requested len too short: wLength < real length
                                if setup_packet.length < desc.len() as u16 {
                                    desc.resize(setup_packet.length as usize, 0);
                                }
                                Ok(desc)
                            }
                            _ => {
                                warn!("unknown desc type: {setup_packet:x?}");
                                Ok(vec![])
                            }
                        }
                    }
                    _ if setup_packet.request_type & 0xF == 1 => {
                        // to interface
                        // see https://www.beyondlogic.org/usbnutshell/usb6.shtml
                        // only low 8 bits are valid
                        let intf = &self.interfaces[setup_packet.index as usize & 0xFF];
                        let mut handler = intf.handler.lock().unwrap();
                        handler.handle_urb(intf, ep, transfer_buffer_length, setup_packet, out_data)
                    }
                    _ if self.device_handler.is_some() => {
                        // device_handler implementations (RusbUsbHostDeviceHandler,
                        // NusbUsbHostDeviceHandler in host.rs) reconstruct the full
                        // recipient from setup_packet.request_type themselves, so they
                        // work for device/endpoint/other recipients. Interface-recipient
                        // requests are caught by the arm above.
                        let lock = self.device_handler.as_ref().unwrap();
                        let mut handler = lock.lock().unwrap();
                        handler.handle_urb(transfer_buffer_length, setup_packet, out_data)
                    }
                    _ => unimplemented!("control in"),
                }
            }
            (Some(Control), Out) => {
                // control out
                debug!("Control OUT setup={setup_packet:x?}");
                match (
                    setup_packet.request_type,
                    FromPrimitive::from_u8(setup_packet.request),
                ) {
                    (0b00000000, Some(SetConfiguration)) => {
                        let mut desc = vec![
                            self.configuration_value, // bConfigurationValue
                        ];

                        // requested len too short: wLength < real length
                        if setup_packet.length < desc.len() as u16 {
                            desc.resize(setup_packet.length as usize, 0);
                        }
                        Ok(desc)
                    }
                    _ if setup_packet.request_type & 0xF == 1 => {
                        // to interface
                        // see https://www.beyondlogic.org/usbnutshell/usb6.shtml
                        // only low 8 bits are valid
                        let intf = &self.interfaces[setup_packet.index as usize & 0xFF];
                        let mut handler = intf.handler.lock().unwrap();
                        handler.handle_urb(intf, ep, transfer_buffer_length, setup_packet, out_data)
                    }
                    _ if self.device_handler.is_some() => {
                        // non-interface recipients forwarded to device_handler
                        // (see the control-in arm above for details).
                        let lock = self.device_handler.as_ref().unwrap();
                        let mut handler = lock.lock().unwrap();
                        handler.handle_urb(transfer_buffer_length, setup_packet, out_data)
                    }
                    _ => unimplemented!("control out"),
                }
            }
            (Some(_), _) => {
                // others
                let intf = intf.unwrap();
                let mut handler = intf.handler.lock().unwrap();
                handler.handle_urb(intf, ep, transfer_buffer_length, setup_packet, out_data)
            }
            _ => unimplemented!("transfer to {:?}", ep),
        }
    }
}

/// A handler for URB targeting the device
pub trait UsbDeviceHandler: std::fmt::Debug {
    /// Handle a URB(USB Request Block) targeting at this device
    ///
    /// When the lower 4 bits of `bmRequestType` is zero and the URB is not handled by the library, this function is called.
    /// The resulting data should not exceed `transfer_buffer_length`
    fn handle_urb(
        &mut self,
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

#[cfg(test)]
mod test {
    use crate::util::tests::*;

    use super::*;

    #[test]
    fn test_set_string_descriptors() {
        setup_test_logger();
        let mut device = UsbDevice::new(0);

        assert_eq!(device.string_pool.len(), 4);

        assert!(device.set_configuration_name("test").is_some());
        assert!(device.set_manufacturer_name("test").is_some());
        assert!(device.set_product_name("test").is_some());
        assert!(device.set_serial_number("test").is_some());

        assert_eq!(device.string_pool.len(), 4);

        assert_eq!(device.string_pool[&1], "test");
        assert_eq!(device.string_pool[&2], "test");
        assert_eq!(device.string_pool[&3], "test");
        assert_eq!(device.string_pool[&4], "test");
    }

    #[tokio::test]
    async fn test_invalid_string_index() {
        setup_test_logger();
        let device = UsbDevice::new(0);
        let res = device
            .handle_urb(
                UsbEndpoint {
                    address: 0x80, // IN
                    attributes: EndpointAttributes::Control as u8,
                    max_packet_size: EP0_MAX_PACKET_SIZE,
                    interval: 0,
                },
                None,
                0,
                SetupPacket {
                    request_type: 0b10000000,
                    request: StandardRequest::GetDescriptor as u8,
                    // string pool only contains 4 strings, 5 should be invalid
                    value: ((DescriptorType::String as u16) << 8) | 5,
                    index: 0,
                    length: 0,
                },
                &[],
            )
            .await;

        assert!(res.is_err());
    }

    /// The synthesized device descriptor must carry bMaxPacketSize0 as-is: at high
    /// speed 64, and at SuperSpeed and above the exponent 9 (512 bytes).
    #[tokio::test]
    async fn test_device_descriptor_ep0_max_packet_size() {
        setup_test_logger();
        for (speed, max_packet_size_0) in [
            (UsbSpeed::High, 64),
            (UsbSpeed::Super, 9),
            (UsbSpeed::SuperPlus, 9),
        ] {
            let mut device = UsbDevice::new(0);
            device.speed = speed as u32;
            device.ep0_in.max_packet_size = max_packet_size_0;
            device.ep0_out.max_packet_size = max_packet_size_0;

            let desc = device
                .handle_urb(
                    device.ep0_in,
                    None,
                    u32::from(u16::MAX),
                    SetupPacket {
                        request_type: 0b10000000,
                        request: StandardRequest::GetDescriptor as u8,
                        value: (DescriptorType::Device as u16) << 8,
                        index: 0,
                        length: u16::MAX,
                    },
                    &[],
                )
                .await
                .unwrap();

            assert_eq!(
                u16::from(desc[7]),
                max_packet_size_0,
                "{speed:?} bMaxPacketSize0"
            );
        }
    }

    /// set_speed keeps the speed and ep0 in sync, including the exponent used at
    /// SuperSpeed.
    #[tokio::test]
    async fn test_set_speed_updates_ep0() {
        setup_test_logger();
        for (speed, expected_max_packet_size_0) in [
            (UsbSpeed::Low, 8),
            (UsbSpeed::Full, 64),
            (UsbSpeed::High, 64),
            (UsbSpeed::Super, 9),
            (UsbSpeed::SuperPlus, 9),
        ] {
            let mut device = UsbDevice::new(0);
            device.set_speed(speed);

            assert_eq!(device.speed, speed as u32);
            assert_eq!(device.ep0_in.max_packet_size, expected_max_packet_size_0);
            assert_eq!(device.ep0_out.max_packet_size, expected_max_packet_size_0);

            let desc = device
                .handle_urb(
                    device.ep0_in,
                    None,
                    u32::from(u16::MAX),
                    SetupPacket {
                        request_type: 0b10000000,
                        request: StandardRequest::GetDescriptor as u8,
                        value: (DescriptorType::Device as u16) << 8,
                        index: 0,
                        length: u16::MAX,
                    },
                    &[],
                )
                .await
                .unwrap();
            assert_eq!(u16::from(desc[7]), expected_max_packet_size_0, "{speed:?}");
        }
    }

    /// At SuperSpeed the device descriptor holds the exponent 9, but the (USB 2.0)
    /// device qualifier describes high-speed operation and must report 64 bytes.
    #[tokio::test]
    async fn test_device_qualifier_at_superspeed() {
        setup_test_logger();
        let mut device = UsbDevice::new(0);
        device.set_speed(UsbSpeed::Super);

        let desc = device
            .handle_urb(
                device.ep0_in,
                None,
                u32::from(u16::MAX),
                SetupPacket {
                    request_type: 0b10000000,
                    request: StandardRequest::GetDescriptor as u8,
                    value: (DescriptorType::DeviceQualifier as u16) << 8,
                    index: 0,
                    length: u16::MAX,
                },
                &[],
            )
            .await
            .unwrap();

        assert_eq!(desc[1], DescriptorType::DeviceQualifier as u8);
        assert_eq!(desc[7], 64);
    }

    /// Endpoint extra descriptors (SuperSpeed companion, UAS pipe usage) are
    /// emitted directly after the endpoint descriptor, as required by USB.
    #[tokio::test]
    async fn test_configuration_endpoint_extra() {
        setup_test_logger();

        #[derive(Debug)]
        struct DummyHandler;
        impl UsbInterfaceHandler for DummyHandler {
            fn get_class_specific_descriptor(&self) -> Vec<u8> {
                Vec::new()
            }
            fn handle_urb(
                &mut self,
                _interface: &UsbInterface,
                _ep: UsbEndpoint,
                _transfer_buffer_length: u32,
                _setup: SetupPacket,
                _req: &[u8],
            ) -> Result<Vec<u8>> {
                Ok(Vec::new())
            }
            fn as_any(&mut self) -> &mut dyn Any {
                self
            }
        }

        let mut device = UsbDevice::new(0).with_interface(
            0xff,
            0,
            0,
            None,
            vec![UsbEndpoint {
                address: 0x81,
                attributes: EndpointAttributes::Bulk as u8,
                max_packet_size: 1024,
                interval: 0,
            }],
            Arc::new(Mutex::new(
                Box::new(DummyHandler) as Box<dyn UsbInterfaceHandler + Send>
            )),
        );
        device.interfaces[0]
            .endpoint_extra
            .push(vec![0x06, 0x30, 0x0f, 0x00, 0x00, 0x00]);

        let desc = device
            .handle_urb(
                device.ep0_in,
                None,
                u32::from(u16::MAX),
                SetupPacket {
                    request_type: 0b10000000,
                    request: StandardRequest::GetDescriptor as u8,
                    value: (DescriptorType::Configuration as u16) << 8,
                    index: 0,
                    length: u16::MAX,
                },
                &[],
            )
            .await
            .unwrap();

        assert_eq!(u16::from_le_bytes([desc[2], desc[3]]) as usize, desc.len());
        assert!(
            desc.windows(6)
                .any(|w| w == [0x06, 0x30, 0x0f, 0x00, 0x00, 0x00]),
            "companion descriptor missing"
        );
    }

    /// The BOS descriptor (and with it the SuperSpeed capability) is passed
    /// through from the real device, and truncated for short requests.
    #[tokio::test]
    async fn test_bos_descriptor_passthrough() {
        setup_test_logger();
        let mut device = UsbDevice::new(0);
        device.set_speed(UsbSpeed::Super);
        device.bos = vec![
            0x05, 0x0F, 0x0F, 0x00, 0x01, // BOS header: wTotalLength=15, 1 capability
            0x0A, 0x10, 0x00, 0x0E, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, // SuperSpeed
        ];

        async fn get_bos(device: &UsbDevice, length: u16) -> Vec<u8> {
            device
                .handle_urb(
                    device.ep0_in,
                    None,
                    u32::from(length),
                    SetupPacket {
                        request_type: 0b10000000,
                        request: StandardRequest::GetDescriptor as u8,
                        value: (DescriptorType::BOS as u16) << 8,
                        index: 0,
                        length,
                    },
                    &[],
                )
                .await
                .unwrap()
        }

        let full = get_bos(&device, u16::MAX).await;
        assert_eq!(full[1], DescriptorType::BOS as u8);
        assert_eq!(full.len(), 15);

        let truncated = get_bos(&device, 7).await;
        assert_eq!(truncated.len(), 7);
        assert_eq!(&truncated[..7], &[0x05, 0x0F, 0x0F, 0x00, 0x01, 0x0A, 0x10]);
    }

    /// `bcdUSB` and `bcdDevice` are BCD: the low byte is `(minor << 4) | patch`,
    /// so a device reporting 3.02 must not be rounded down to 3.00.
    #[test]
    fn test_version_bcd_roundtrip() {
        for value in [0x0100u16, 0x0110, 0x0200, 0x0210, 0x0300, 0x0302, 0x0320] {
            let version: Version = value.into();
            assert_eq!(u16::from_le_bytes(version.bcd()), value, "{value:#06x}");
        }
    }

    /// Both BCD fields of the synthesized device descriptor keep their sub-minor
    /// digit, so the client sees the same `bcdUSB`/`bcdDevice` as the real device.
    #[tokio::test]
    async fn test_device_descriptor_bcd_fields() {
        setup_test_logger();
        let mut device = UsbDevice::new(0);
        device.usb_version = 0x0302u16.into();
        device.device_bcd = 0x0210u16.into();

        let desc = device
            .handle_urb(
                device.ep0_in,
                None,
                u32::from(u16::MAX),
                SetupPacket {
                    request_type: 0b10000000,
                    request: StandardRequest::GetDescriptor as u8,
                    value: (DescriptorType::Device as u16) << 8,
                    index: 0,
                    length: u16::MAX,
                },
                &[],
            )
            .await
            .unwrap();

        assert_eq!(u16::from_le_bytes([desc[2], desc[3]]), 0x0302);
        assert_eq!(u16::from_le_bytes([desc[12], desc[13]]), 0x0210);
    }

    /// The device qualifier carries the same BCD-encoded `bcdUSB`.
    #[tokio::test]
    async fn test_device_qualifier_bcd_version() {
        setup_test_logger();
        let mut device = UsbDevice::new(0);
        device.set_speed(UsbSpeed::Super);
        device.usb_version = 0x0302u16.into();

        let desc = device
            .handle_urb(
                device.ep0_in,
                None,
                u32::from(u16::MAX),
                SetupPacket {
                    request_type: 0b10000000,
                    request: StandardRequest::GetDescriptor as u8,
                    value: (DescriptorType::DeviceQualifier as u16) << 8,
                    index: 0,
                    length: u16::MAX,
                },
                &[],
            )
            .await
            .unwrap();

        assert_eq!(u16::from_le_bytes([desc[2], desc[3]]), 0x0302);
    }
}
