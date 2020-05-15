use env_logger;
use std::net::*;
use usbip;

#[tokio::main]
async fn main() {
    env_logger::init();
    let server = usbip::UsbIpServer { devices: vec![] };
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 3240);
    usbip::server(&addr, server).await;
}
