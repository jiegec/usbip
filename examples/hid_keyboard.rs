use log::*;
use std::net::*;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use usbip::server::*;

#[tokio::main]
async fn main() {
    env_logger::init();
    let handler = Arc::new(Mutex::new(
        Box::new(usbip::hid::UsbHidKeyboardHandler::new_keyboard())
            as Box<dyn usbip::UsbInterfaceHandler + Send>,
    ));
    let server = SyncUsbIpServer::new_simulated(vec![
        usbip::UsbDevice::new(0).with_interface(
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
            handler.clone(),
        ),
    ]);
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 3240);
    tokio::spawn(server.serve(addr));

    loop {
        // sleep 1s
        tokio::time::sleep(Duration::new(1, 0)).await;
        let mut handler = handler.lock().unwrap();
        if let Some(hid) = handler
            .as_any()
            .downcast_mut::<usbip::hid::UsbHidKeyboardHandler>()
        {
            hid.pending_key_events
                .push_back(usbip::hid::UsbHidKeyboardReport::from_ascii(b'1'));
            info!("Simulate a key event");
        }
    }
}
