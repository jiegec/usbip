use log::*;
use std::net::*;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use usbip::server::*;

#[tokio::main]
async fn main() {
    env_logger::init();
    let handler =
        Arc::new(Mutex::new(Box::new(usbip::cdc::UsbCdcAcmHandler::new())
            as Box<dyn usbip::UsbInterfaceHandler + Send>));
    let server = SyncUsbIpServer::new_simulated(vec![
        usbip::UsbDevice::new(0).with_interface(
            usbip::ClassCode::CDC as u8,
            usbip::cdc::CDC_ACM_SUBCLASS,
            0x00,
            "Test CDC ACM",
            usbip::cdc::UsbCdcAcmHandler::endpoints(),
            handler.clone(),
        ),
    ]);
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 3240);
    tokio::spawn(server.serve(addr));

    loop {
        // sleep 1s
        tokio::time::sleep(Duration::new(1, 0)).await;
        let mut handler = handler.lock().unwrap();
        if let Some(acm) = handler
            .as_any()
            .downcast_mut::<usbip::cdc::UsbCdcAcmHandler>()
        {
            acm.tx_buffer.push(b'a');
            info!("Simulate a char input");
        }
    }
}
