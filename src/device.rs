use super::*;
use rusb::Version as rusbVersion;

#[derive(Clone, Default)]
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

/// Represent a USB device
#[derive(Clone, Default)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct UsbDevice {
    pub path: String,
    pub bus_id: String,
    pub bus_num: u32,
    pub dev_num: u32,
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
        self.string_pool
            .insert(self.string_configuration, name.to_string())
    }

    /// Returns the old value, if present.
    pub fn set_serial_number(&mut self, name: &str) -> Option<String> {
        self.string_pool
            .insert(self.string_serial, name.to_string())
    }

    /// Returns the old value, if present.
    pub fn set_product_name(&mut self, name: &str) -> Option<String> {
        self.string_pool
            .insert(self.string_product, name.to_string())
    }

    /// Returns the old value, if present.
    pub fn set_manufacturer_name(&mut self, name: &str) -> Option<String> {
        self.string_pool
            .insert(self.string_manufacturer, name.to_string())
    }

    pub fn with_interface(
        mut self,
        interface_class: u8,
        interface_subclass: u8,
        interface_protocol: u8,
        name: &str,
        endpoints: Vec<UsbEndpoint>,
        handler: Arc<Mutex<Box<dyn UsbInterfaceHandler + Send>>>,
    ) -> Self {
        let string_interface = self.new_string(name);
        let class_specific_descriptor = handler.lock().unwrap().get_class_specific_descriptor();
        self.interfaces.push(UsbInterface {
            interface_class,
            interface_subclass,
            interface_protocol,
            endpoints,
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

    pub(crate) fn new_string(&mut self, s: &str) -> u8 {
        for i in 1.. {
            if self.string_pool.get(&i).is_none() {
                self.string_pool.insert(i, s.to_string());
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
                debug!("Control IN setup={:x?}", setup_packet);
                match (
                    setup_packet.request_type,
                    FromPrimitive::from_u8(setup_packet.request),
                ) {
                    (0b10000000, Some(GetDescriptor)) => {
                        // high byte: type
                        match FromPrimitive::from_u16(setup_packet.value >> 8) {
                            Some(Device) => {
                                debug!("Get device descriptor");
                                let mut desc = vec![
                                    0x12,         // bLength
                                    Device as u8, // bDescriptorType: Device
                                    self.usb_version.minor,
                                    self.usb_version.major, // bcdUSB: USB 2.0
                                    self.device_class,      // bDeviceClass
                                    self.device_subclass,   // bDeviceSubClass
                                    self.device_protocol,   // bDeviceProtocol
                                    self.ep0_in.max_packet_size as u8, // bMaxPacketSize0
                                    self.vendor_id as u8,   // idVendor
                                    (self.vendor_id >> 8) as u8,
                                    self.product_id as u8, // idProduct
                                    (self.product_id >> 8) as u8,
                                    self.device_bcd.minor, // bcdDevice
                                    self.device_bcd.major,
                                    self.string_manufacturer, // iManufacturer
                                    self.string_product,      // iProduct
                                    self.string_serial,       // iSerial
                                    self.num_configurations,
                                ];

                                // requested len too short: wLength < real length
                                if setup_packet.length < desc.len() as u16 {
                                    desc.resize(setup_packet.length as usize, 0);
                                }
                                Ok(desc)
                            }
                            Some(BOS) => {
                                debug!("Get BOS descriptor");
                                let mut desc = vec![
                                    0x05,      // bLength
                                    BOS as u8, // bDescriptorType: BOS
                                    0x05, 0x00, // wTotalLength
                                    0x00, // bNumCapabilities
                                ];

                                // requested len too short: wLength < real length
                                if setup_packet.length < desc.len() as u16 {
                                    desc.resize(setup_packet.length as usize, 0);
                                }
                                Ok(desc)
                            }
                            Some(Configuration) => {
                                debug!("Get configuration descriptor");
                                let mut desc = vec![
                                    0x09,                // bLength
                                    Configuration as u8, // bDescriptorType: Configuration
                                    0x00,
                                    0x00, // wTotalLength: to be filled below
                                    self.interfaces.len() as u8, // bNumInterfaces
                                    self.configuration_value, // bConfigurationValue
                                    self.string_configuration, // iConfiguration
                                    0x80, // bmAttributes Bus Powered
                                    0x32, // bMaxPower 100mA
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
                                    for endpoint in &intf.endpoints {
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
                                    // language ids
                                    let mut desc = vec![
                                        4,                            // bLength
                                        DescriptorType::String as u8, // bDescriptorType
                                        0x09,
                                        0x04, // bLANGID, en-US
                                    ];
                                    // requested len too short: wLength < real length
                                    if setup_packet.length < desc.len() as u16 {
                                        desc.resize(setup_packet.length as usize, 0);
                                    }
                                    Ok(desc)
                                } else {
                                    let s = &self.string_pool[&index];
                                    let bytes: Vec<u16> = s.encode_utf16().collect();
                                    let mut desc = vec![
                                        (2 + bytes.len() * 2) as u8,  // bLength
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
                                }
                            }
                            Some(DeviceQualifier) => {
                                debug!("Get device qualifier descriptor");
                                let mut desc = vec![
                                    0x0A,                  // bLength
                                    DeviceQualifier as u8, // bDescriptorType: Device Qualifier
                                    self.usb_version.minor,
                                    self.usb_version.major,
                                    self.device_class,    // bDeviceClass
                                    self.device_subclass, // bDeviceSUbClass
                                    self.device_protocol, // bDeviceProtocol
                                    self.ep0_in.max_packet_size as u8, // bMaxPacketSize0
                                    self.num_configurations, // bNumConfigurations
                                    0x00,                 // reserved
                                ];

                                // requested len too short: wLength < real length
                                if setup_packet.length < desc.len() as u16 {
                                    desc.resize(setup_packet.length as usize, 0);
                                }
                                Ok(desc)
                            }
                            _ => {
                                warn!("unknown desc type: {:x?}", setup_packet);
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
                    _ if setup_packet.request_type & 0xF == 0 && self.device_handler.is_some() => {
                        // to device
                        // see https://www.beyondlogic.org/usbnutshell/usb6.shtml
                        let lock = self.device_handler.as_ref().unwrap();
                        let mut handler = lock.lock().unwrap();
                        handler.handle_urb(transfer_buffer_length, setup_packet, out_data)
                    }
                    _ => unimplemented!("control in"),
                }
            }
            (Some(Control), Out) => {
                // control out
                debug!("Control OUT setup={:x?}", setup_packet);
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
                    _ if setup_packet.request_type & 0xF == 0 && self.device_handler.is_some() => {
                        // to device
                        // see https://www.beyondlogic.org/usbnutshell/usb6.shtml
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
pub trait UsbDeviceHandler {
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
}
