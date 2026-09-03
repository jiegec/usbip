//! Simulate a HID keyboard that uses the deferred (pending) interrupt IN
//! behaviour (the fix for issue #63).
//!
//! Unlike `hid_keyboard.rs` (which answers every interrupt IN poll immediately,
//! possibly with an empty buffer), this example opts into `pending_notify` via
//! `UsbHidKeyboardHandler::new_keyboard_with_pending`. An interrupt IN URB stays
//! pending until a key is pressed, so a polling client (e.g. `usbip-win2`) is
//! not flooded with empty completions.

use log::*;
use std::net::*;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[tokio::main]
async fn main() {
    env_logger::init();
    let handler = Arc::new(Mutex::new(Box::new(
        usbip::hid::UsbHidKeyboardHandler::new_keyboard_with_pending(),
    )
        as Box<dyn usbip::UsbInterfaceHandler + Send>));
    let server = Arc::new(usbip::UsbIpServer::new_simulated(vec![
        usbip::UsbDevice::new(0).with_interface(
            usbip::ClassCode::HID as u8,
            0x00,
            0x00,
            Some("Test HID (pending interrupt IN)"),
            vec![usbip::UsbEndpoint {
                address: 0x81,         // IN
                attributes: 0x03,      // Interrupt
                max_packet_size: 0x08, // 8 bytes
                interval: 10,
            }],
            handler.clone(),
        ),
    ]));
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 3240);
    tokio::spawn(usbip::server(addr, server));

    loop {
        // sleep 1s
        tokio::time::sleep(Duration::new(1, 0)).await;
        let mut handler = handler.lock().unwrap();
        if let Some(hid) = handler
            .as_any()
            .downcast_mut::<usbip::hid::UsbHidKeyboardHandler>()
        {
            hid.press(b'1');
            info!("Simulate a key event (wakes a pending interrupt IN URB)");
        }
    }
}
