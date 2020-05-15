use futures::stream::StreamExt;
use log::*;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};

pub struct UsbIpServer {}

async fn handler(mut socket: TcpStream, server: Arc<UsbIpServer>) -> std::io::Result<()> {
    loop {
        let mut command = [0u8; 4];
        socket.read_exact(&mut command).await?;
        match command {
            [0x01, 0x11, 0x80, 0x05] => {
                debug!("Got OP_REQ_DEVLIST");
                let status = socket.read_u32().await?;
            }
            [0x01, 0x11, 0x80, 0x03] => {
                debug!("Got OP_REQ_IMPORT");
                let status = socket.read_u32().await?;
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
