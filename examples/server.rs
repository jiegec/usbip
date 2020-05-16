use env_logger;
use std::net::*;
use usbip;

#[tokio::main]
async fn main() {
    env_logger::init();
    let server = usbip::UsbIpServer {
        devices: vec![usbip::UsbDevice::new(0).with_interface(
            usbip::ClassCode::HID as u8,
            0x00,
            0x00,
            "Test HID",
            vec![usbip::UsbEndpoint {
                address: 0x81,         // IN
                attributes: 0x03,      // Interrupt
                max_packet_size: 0x08, // 8 bytes
                interval: 10,
            }],
            Box::new(usbip::UsbHidHandler::new_keyboard()),
        )],
    };
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 3240);
    usbip::server(&addr, server).await;
}
