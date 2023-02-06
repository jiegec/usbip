use env_logger;
use std::any::Any;
use std::net::*;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use usbip::{
    ftdi::FtdiDeviceHandler, Direction, EndpointAttributes, SetupPacket, UsbDevice, UsbEndpoint,
    UsbInterface, UsbInterfaceHandler,
};

const FTDI_VID: u16 = 0x0403;
const FTDI_PID: u16 = 0x6011;

#[derive(Clone)]
pub struct PseudoFtdiHandler {
    tx_buffer: Vec<u8>,
}

impl PseudoFtdiHandler {
    pub fn new() -> Self {
        Self { tx_buffer: vec![] }
    }
}

// This implemention does not
impl UsbInterfaceHandler for PseudoFtdiHandler {
    fn handle_urb(
        &mut self,
        _interface: &UsbInterface,
        ep: UsbEndpoint,
        _setup: SetupPacket,
        req: &[u8],
    ) -> Result<Vec<u8>, std::io::Error> {
        // interrupt
        if ep.attributes == EndpointAttributes::Interrupt as u8 {
            Ok(vec![])
        }
        // bulk
        else if let Direction::Out = ep.direction() {
            // write to device/file here...
            println!("Write endpoint {:02x}: {:?}", ep.address, req);
            Ok(vec![])
        } else {
            // Read from the device.
            // The first two bytes are device status.
            // These must always be present, otherwise the ftdi driver on the remote side will
            // consume these bytes.
            if self.tx_buffer.len() > 0 {
                let mut ftdi_packet: Vec<u8> = vec![0x01, 0x00];
                ftdi_packet.extend(&self.tx_buffer);
                self.tx_buffer = vec![];
                println!("Read endpoint {:02x}: {:?}", ep.address, ftdi_packet);
                Ok(ftdi_packet)
            } else {
                Ok(vec![0x01, 0x00])
            }
        }
    }

    fn get_class_specific_descriptor(&self) -> Vec<u8> {
        vec![]
    }

    fn as_any(&mut self) -> &mut dyn Any {
        self
    }
}

fn ftdi_device() -> (
    UsbDevice,
    Arc<std::sync::Mutex<Box<dyn UsbInterfaceHandler + Send>>>,
) {
    let pseudo = Arc::new(Mutex::new(
        Box::new(PseudoFtdiHandler::new()) as Box<dyn usbip::UsbInterfaceHandler + Send>
    ));
    let device_handler = Arc::new(Mutex::new(
        Box::new(FtdiDeviceHandler::new()) as Box<dyn usbip::UsbDeviceHandler + Send>
    ));
    let endpoints = FtdiDeviceHandler::endpoints(4);
    let mut device = UsbDevice::new(0)
        .with_interface(255, 255, 255, "", endpoints[0..2].to_vec(), pseudo.clone())
        .with_interface(255, 255, 255, "", endpoints[2..4].to_vec(), pseudo.clone())
        .with_interface(255, 255, 255, "", endpoints[4..6].to_vec(), pseudo.clone())
        .with_interface(255, 255, 255, "", endpoints[6..8].to_vec(), pseudo.clone())
        .with_device_handler(device_handler);

    device.product_id = FTDI_PID;
    device.vendor_id = FTDI_VID;
    (device, pseudo)
}

#[tokio::main]
async fn main() {
    env_logger::init();
    let (device, handler) = ftdi_device();
    let server = usbip::UsbIpServer::new_simulated(vec![device]);
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 3240);
    tokio::spawn(usbip::server(addr, server));

    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let mut handler = handler.lock().unwrap();
        if let Some(ftdi) = handler.as_any().downcast_mut::<PseudoFtdiHandler>() {
            ftdi.tx_buffer.extend(b"hello\0");
        }
    }
}
