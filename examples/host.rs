//! Share host USB devices over USB/IP.
//!
//! Usage:
//!   host [--nusb|--rusb] [VID:PID]...
//!
//! `--rusb` (default) uses libusb, `--nusb` uses the nusb backend. Every optional
//! `VID:PID` argument (hex, e.g. `46f4:0003`) restricts sharing to matching
//! devices; without any, all host devices are shared. The QEMU passthrough test
//! uses the filter to pick only the device it provided to the guest.
use std::net::*;
use std::sync::Arc;
use std::time::Duration;

use nusb::MaybeFuture;
use usbip::UsbIpServer;

fn parse_filter(s: &str) -> Option<(u16, u16)> {
    let (vid, pid) = s.split_once(':')?;
    let hex = |v: &str| u16::from_str_radix(v.trim_start_matches("0x"), 16).ok();
    Some((hex(vid)?, hex(pid)?))
}

#[tokio::main]
async fn main() {
    env_logger::init();

    let mut backend = "rusb";
    let mut filters: Vec<(u16, u16)> = vec![];
    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "--nusb" => backend = "nusb",
            "--rusb" => backend = "rusb",
            _ => match parse_filter(&arg) {
                Some(filter) => filters.push(filter),
                None => {
                    eprintln!("usage: host [--nusb|--rusb] [VID:PID]...");
                    std::process::exit(2);
                }
            },
        }
    }

    let wanted = move |vid: u16, pid: u16| filters.is_empty() || filters.contains(&(vid, pid));

    let server = match backend {
        "nusb" => {
            let wanted = wanted.clone();
            let devices = nusb::list_devices()
                .wait()
                .expect("failed to enumerate nusb devices")
                .filter(|info| wanted(info.vendor_id(), info.product_id()))
                .collect::<Vec<_>>();
            let devices = UsbIpServer::with_nusb_devices(devices);
            log::info!("sharing {} device(s) via nusb", devices.len());
            Arc::new(UsbIpServer::new_simulated(devices))
        }
        _ => Arc::new(UsbIpServer::new_from_host_with_filter(|dev| {
            dev.device_descriptor()
                .map(|desc| wanted(desc.vendor_id(), desc.product_id()))
                .unwrap_or(false)
        })),
    };

    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 3240);
    tokio::spawn(usbip::server(addr, server));

    loop {
        // sleep 1s
        tokio::time::sleep(Duration::new(1, 0)).await;
    }
}
