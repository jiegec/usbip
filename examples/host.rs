use env_logger;
use std::net::*;
use std::sync::Arc;
use std::time::Duration;
use usbip;

#[tokio::main]
async fn main() {
    env_logger::init();
    let server = Arc::new(usbip::UsbIpServer::new_from_host());
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 3240);
    tokio::spawn(usbip::server(addr, server));

    loop {
        // sleep 1s
        tokio::time::sleep(Duration::new(1, 0)).await;
    }
}
