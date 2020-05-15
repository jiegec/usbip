use futures::stream::StreamExt;
use log::*;
use std::io::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

pub struct UsbInterface {
    pub interface_class: u8,
    pub interface_subclass: u8,
    pub interface_protocol: u8,
}

pub struct UsbDevice {
    pub path: String,
    pub bus_id: String,
    pub bus_num: u32,
    pub dev_num: u32,
    pub speed: u32,
    pub vendor_id: u16,
    pub product_id: u16,
    pub device_bcd: u16,
    pub device_class: u8,
    pub device_subclass: u8,
    pub device_protocol: u8,
    pub configuration_value: u8,
    pub num_configurations: u8,
    pub interfaces: Vec<UsbInterface>,
}

impl UsbDevice {
    async fn write_dev(&self, socket: &mut TcpStream) -> Result<()> {
        // pad to 256 bytes
        let mut path = self.path.clone().into_bytes();
        assert!(path.len() <= 256);
        path.resize(256, 0);
        socket.write_all(&path).await?;

        // the same
        let mut bus_id = self.bus_id.clone().into_bytes();
        assert!(bus_id.len() <= 32);
        bus_id.resize(32, 0);
        socket.write_all(&bus_id).await?;

        // fields
        socket.write_u32(self.bus_num).await?;
        socket.write_u32(self.dev_num).await?;
        socket.write_u32(self.speed).await?;
        socket.write_u16(self.vendor_id).await?;
        socket.write_u16(self.product_id).await?;
        socket.write_u16(self.device_bcd).await?;
        socket.write_u8(self.device_class).await?;
        socket.write_u8(self.device_subclass).await?;
        socket.write_u8(self.device_protocol).await?;
        socket.write_u8(self.configuration_value).await?;
        socket.write_u8(self.num_configurations).await?;
        socket.write_u8(self.interfaces.len() as u8).await?;

        for interface in &self.interfaces {
            socket.write_u8(interface.interface_class).await?;
            socket.write_u8(interface.interface_subclass).await?;
            socket.write_u8(interface.interface_protocol).await?;
        }
        Ok(())
    }
}

pub struct UsbIpServer {
    pub devices: Vec<UsbDevice>,
}

async fn handler(mut socket: TcpStream, server: Arc<UsbIpServer>) -> Result<()> {
    loop {
        let mut command = [0u8; 4];
        socket.read_exact(&mut command).await?;
        match command {
            [0x01, 0x11, 0x80, 0x05] => {
                debug!("Got OP_REQ_DEVLIST");
                let _status = socket.read_u32().await?;

                // OP_REP_DEVLIST
                socket.write_u32(0x01110005).await?;
                socket.write_u32(0).await?;
                socket.write_u32(server.devices.len() as u32).await?;
                for dev in &server.devices {
                    dev.write_dev(&mut socket).await?;
                }
                debug!("Sent OP_REP_DEVLIST");
            }
            [0x01, 0x11, 0x80, 0x03] => {
                debug!("Got OP_REQ_IMPORT");
                let _status = socket.read_u32().await?;
            }
            [0x00, 0x00, 0x00, 0x01] => {
                debug!("Got USBIP_CMD_SUBMIT");
            }
            [0x00, 0x00, 0x00, 0x02] => {
                debug!("Got USBIP_CMD_UNLINK");
            }
            _ => warn!("Got unknown command {:?}", command),
        }
    }
}

pub async fn server(addr: &SocketAddr, server: UsbIpServer) {
    let mut listener = TcpListener::bind(addr).await.expect("bind to addr");

    let server = async move {
        let usbip_server = Arc::new(server);
        let mut incoming = listener.incoming();
        while let Some(socket_res) = incoming.next().await {
            match socket_res {
                Ok(socket) => {
                    info!("Got connection from {:?}", socket.peer_addr());
                    let new_server = usbip_server.clone();
                    tokio::spawn(async move {
                        let res = handler(socket, new_server).await;
                        info!("Handler ended with {:?}", res);
                    });
                }
                Err(err) => {
                    warn!("Got error {:?}", err);
                }
            }
        }
    };

    server.await
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
