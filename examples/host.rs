use std::net::*;

use std::time::Duration;

use usbip::server::*;

#[tokio::main]
async fn main() {
    env_logger::init();
    let server = usbip::server::SyncUsbIpServer::new_from_host();
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 3240);
    tokio::spawn(server.serve(addr));

    loop {
        // sleep 1s
        tokio::time::sleep(Duration::new(1, 0)).await;
    }
}
