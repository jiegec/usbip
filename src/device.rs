use super::*;

#[derive(Clone, Debug, Default)]
pub struct UsbDevice {
    pub path: String,
    pub bus_id: String,
    pub bus_num: u32,
    pub dev_num: u32,
    pub speed: u32,
    pub vendor_id: u16,
    pub product_id: u16,
    pub device_bcd: u16,
    pub device_class: u8,
    pub device_subclass: u8,
    pub device_protocol: u8,
    pub configuration_value: u8,
    pub num_configurations: u8,
    pub interfaces: Vec<UsbInterface>,
    pub ep0_in: UsbEndpoint,
    pub ep0_out: UsbEndpoint,
}

impl UsbDevice {
    pub fn new(index: u32) -> Self {
        Self {
            path: format!("/sys/device/usbip/{}", index),
            bus_id: format!("{}", index),
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
            ..Self::default()
        }
    }

    pub fn with_interface(
        mut self,
        interface_class: u8,
        interface_subclass: u8,
        interface_protocol: u8,
    ) -> Self {
        self.interfaces.push(UsbInterface {
            interface_class,
            interface_subclass,
            interface_protocol,
            endpoints: vec![],
        });
        self
    }

    pub(crate) fn find_ep(&self, ep: u8) -> Option<UsbEndpoint> {
        if ep == self.ep0_in.address {
            Some(self.ep0_in)
        } else if ep == self.ep0_out.address {
            Some(self.ep0_out)
        } else {
            for intf in &self.interfaces {
                for endpoint in &intf.endpoints {
                    if endpoint.address == ep {
                        return Some(*endpoint);
                    }
                }
            }
            None
        }
    }

    pub(crate) async fn write_dev(&self, socket: &mut TcpStream) -> Result<()> {
        socket_write_fixed_string(socket, &self.path, 256).await?;
        socket_write_fixed_string(socket, &self.bus_id, 32).await?;

        // fields
        socket.write_u32(self.bus_num).await?;
        socket.write_u32(self.dev_num).await?;
        socket.write_u32(self.speed).await?;
        socket.write_u16(self.vendor_id).await?;
        socket.write_u16(self.product_id).await?;
        socket.write_u16(self.device_bcd).await?;
        socket.write_u8(self.device_class).await?;
        socket.write_u8(self.device_subclass).await?;
        socket.write_u8(self.device_protocol).await?;
        socket.write_u8(self.configuration_value).await?;
        socket.write_u8(self.num_configurations).await?;
        socket.write_u8(self.interfaces.len() as u8).await?;

        Ok(())
    }

    pub(crate) async fn write_dev_with_interfaces(&self, socket: &mut TcpStream) -> Result<()> {
        self.write_dev(socket).await?;

        for interface in &self.interfaces {
            socket.write_u8(interface.interface_class).await?;
            socket.write_u8(interface.interface_subclass).await?;
            socket.write_u8(interface.interface_protocol).await?;
            // padding
            socket.write_u8(0).await?;
        }
        Ok(())
    }

    pub(crate) async fn handle_urb(
        &self,
        socket: &mut TcpStream,
        ep: UsbEndpoint,
        transfer_buffer_length: u32,
        setup: [u8; 8],
    ) -> Result<Vec<u8>> {
        use DescriptorType::*;
        use Direction::*;
        use EndpointAttributes::*;
        use StandardRequest::*;

        // parse setup
        let request_type = setup[0];
        let request = setup[1];
        let value = (setup[3] as u16) << 8 | (setup[2] as u16);
        let index = (setup[5] as u16) << 8 | (setup[4] as u16);
        let length = (setup[7] as u16) << 8 | (setup[6] as u16);

        match (FromPrimitive::from_u8(ep.attributes), ep.direction()) {
            (Some(Control), In) => {
                // control in
                debug!("Control IN bmRequestType={:b} bRequest={:x} wValue={:x} wIndex={:x} wLength={:x}", request_type, request, value, index, length);
                match (request_type, FromPrimitive::from_u8(request)) {
                    (0b10000000, Some(GetDescriptor)) => {
                        // high byte: type
                        match FromPrimitive::from_u16(value >> 8) {
                            Some(Device) => {
                                debug!("Get device descriptor");
                                let desc = [
                                    0x12, // bLength
                                    0x01, // bDescriptorType: Device
                                    0x10,
                                    0x02,                      // bcdUSB: USB 2.1
                                    self.device_class,         // bDeviceClass
                                    self.device_subclass,      // bDeviceSubClass
                                    self.device_protocol,      // bDeviceProtocol
                                    EP0_MAX_PACKET_SIZE as u8, // bMaxPacketSize0
                                    self.vendor_id as u8,      // idVendor
                                    (self.vendor_id >> 8) as u8,
                                    self.product_id as u8, // idProduct
                                    (self.product_id >> 8) as u8,
                                    self.device_bcd as u8, // bcdDevice
                                    (self.device_bcd >> 8) as u8,
                                    StringType::Manufacturer as u8,
                                    StringType::Product as u8,
                                    StringType::Serial as u8,
                                    self.num_configurations,
                                ];
                                return Ok(desc.to_vec());
                            }
                            _ => unimplemented!("desc type"),
                        }
                    }
                    _ => unimplemented!("control in"),
                }
            }
            _ => unimplemented!("transfer"),
        }
        Ok(vec![])
    }
}
