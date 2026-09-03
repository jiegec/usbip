//! Simulate a HID keyboard **and** a CDC ACM serial device on a single USB/IP server.
//!
//! This example is intended for the QEMU end-to-end test: it exports two simulated
//! devices on one server port (`0.0.0.0:3240`) so a real Linux (booted inside QEMU)
//! can attach to both of them and verify that the simulated serial port and keyboard
//! actually work.
use std::net::*;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use log::*;
use tokio::time;

/// Build a simulated HID keyboard device.
fn keyboard_device() -> usbip::UsbDevice {
    let handler = Arc::new(Mutex::new(
        Box::new(usbip::hid::UsbHidKeyboardHandler::new_keyboard())
            as Box<dyn usbip::UsbInterfaceHandler + Send>,
    ));
    let mut device = usbip::UsbDevice::new(1).with_interface(
        usbip::ClassCode::HID as u8,
        0x00,
        0x00,
        Some("Test HID"),
        vec![usbip::UsbEndpoint {
            address: 0x81,         // IN
            attributes: 0x03,      // Interrupt
            max_packet_size: 0x08, // 8 bytes
            interval: 10,
        }],
        handler.clone(),
    );
    device.bus_id = "1-1".to_string();
    device
}

/// Build a simulated CDC ACM serial device.
fn serial_device() -> usbip::UsbDevice {
    let handler =
        Arc::new(Mutex::new(Box::new(usbip::cdc::UsbCdcAcmHandler::new())
            as Box<dyn usbip::UsbInterfaceHandler + Send>));
    let mut device = usbip::UsbDevice::new(2).with_interface(
        usbip::ClassCode::CDC as u8,
        usbip::cdc::CDC_ACM_SUBCLASS,
        0x00,
        Some("Test CDC ACM"),
        usbip::cdc::UsbCdcAcmHandler::endpoints(),
        handler.clone(),
    );
    device.bus_id = "1-2".to_string();
    device
}

#[tokio::main]
async fn main() {
    env_logger::init();
    let keyboard = keyboard_device();
    let handler = keyboard.interfaces.first().unwrap().handler.clone();

    let serial = serial_device();
    let serial_handler = serial.interfaces.first().unwrap().handler.clone();

    let server = Arc::new(usbip::UsbIpServer::new_simulated(vec![keyboard, serial]));
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 3240);
    tokio::spawn(usbip::server(addr, server));

    loop {
        // Drive the simulated devices every second:
        //  - the keyboard presses "1"
        //  - the serial device emits a character 'a'
        time::sleep(Duration::new(1, 0)).await;

        if let Some(hid) = handler
            .lock()
            .unwrap()
            .as_any()
            .downcast_mut::<usbip::hid::UsbHidKeyboardHandler>()
        {
            hid.pending_key_events
                .push_back(usbip::hid::UsbHidKeyboardReport::from_ascii(b'1'));
            info!("Simulate a key event");
        }

        if let Some(acm) = serial_handler
            .lock()
            .unwrap()
            .as_any()
            .downcast_mut::<usbip::cdc::UsbCdcAcmHandler>()
        {
            acm.tx_buffer.push(b'a');
            info!("Simulate a char input");
        }
    }
}
