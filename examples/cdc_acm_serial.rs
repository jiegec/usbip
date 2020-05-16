use env_logger;
use log::*;
use std::net::*;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use usbip;

#[tokio::main]
async fn main() {
    env_logger::init();
    let handler =
        Arc::new(Mutex::new(Box::new(usbip::cdc::UsbCDCACMHandler::new())
            as Box<dyn usbip::UsbInterfaceHandler + Send>));
    let server = usbip::UsbIpServer {
        devices: vec![usbip::UsbDevice::new(0).with_interface(
            usbip::ClassCode::CDC as u8,
            usbip::cdc::CDC_ACM_SUBCLASS,
            0x00,
            "Test CDC ACM",
            vec![
                // state notification
                usbip::UsbEndpoint {
                    address: 0x81,         // IN
                    attributes: usbip::EndpointAttributes::Interrupt as u8,      // Interrupt
                    max_packet_size: 0x08, // 8 bytes
                    interval: 10,
                },
                // bulk in
                usbip::UsbEndpoint {
                    address: 0x82,         // IN
                    attributes: usbip::EndpointAttributes::Bulk as u8,      // Bulkd
                    max_packet_size: 512, // 512 bytes
                    interval: 0,
                },
                // bulk out
                usbip::UsbEndpoint {
                    address: 0x02,         // OUT
                    attributes: usbip::EndpointAttributes::Bulk as u8,      // Bulkd
                    max_packet_size: 512, // 512 bytes
                    interval: 0,
                },
            ],
            handler.clone(),
        )],
    };
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 3240);
    tokio::spawn(usbip::server(addr, server));

    loop {
        // sleep 1s
        tokio::time::delay_for(Duration::new(1, 0)).await;
    }
}
