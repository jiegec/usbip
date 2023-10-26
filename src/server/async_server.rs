use std::vec;

use tokio::{
    io::{split, AsyncReadExt, AsyncWriteExt, ErrorKind, Result},
    sync::mpsc,
};

use super::*;

#[derive(Default, Clone)]
pub struct AsyncUsbIpServer {
    available_devices: Arc<RwLock<Vec<UsbDevice>>>,
    used_devices: Arc<RwLock<HashMap<String, UsbDevice>>>,
}

#[async_trait]
impl UsbIpServer for AsyncUsbIpServer {
    fn new_simulated(devices: Vec<UsbDevice>) -> Self {
        Self {
            available_devices: Arc::new(RwLock::new(devices)),
            used_devices: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    fn new_from_host_with_filter<F>(filter: F) -> Self
    where
        F: FnMut(&Device<GlobalContext>) -> bool,
    {
        match rusb::devices() {
            Ok(list) => {
                let mut devs = vec![];
                for d in list.iter().filter(filter) {
                    devs.push(d)
                }
                Self::new_simulated(get_list_of_real_devices(devs))
            }
            Err(_) => Default::default(),
        }
    }

    async fn add_device(&self, device: UsbDevice) {
        trace!("Adding device {:?}", device.bus_id);
        self.available_devices.write().await.push(device);
    }

    async fn remove_device(&self, bus_id: &str) -> Result<()> {
        let mut available_devices = self.available_devices.write().await;

        if let Some(device) = available_devices.iter().position(|d| d.bus_id == bus_id) {
            trace!("Removing device {:?}", bus_id);
            available_devices.remove(device);
            Ok(())
        } else if let Some(device) = self
            .used_devices
            .read()
            .await
            .values()
            .find(|d| d.bus_id == bus_id)
        {
            warn!("Device {} is in use", device.bus_id);
            Err(std::io::Error::new(
                ErrorKind::Other,
                format!("Device {} is in use", device.bus_id),
            ))
        } else {
            warn!("Device {} not found", bus_id);
            Err(std::io::Error::new(
                ErrorKind::NotFound,
                format!("Device {} not found", bus_id),
            ))
        }
    }

    async fn handler<T: AsyncReadExt + AsyncWriteExt + Unpin + Send>(
        self,
        socket: T,
    ) -> Result<()> {
        let _ = async_scoped::TokioScope::scope_and_block::<Result<()>, _>(|scope| {
            let (internal_tx, mut internal_rx) = mpsc::unbounded_channel::<UsbIpResponse>();
            let (shutdown_tx, mut shutdown_rx) = mpsc::unbounded_channel::<()>();
            let (mut sock_rx, mut sock_tx) = split(socket);

            // RX Thread
            scope.spawn(async move {
                let mut current_import_device_id: Option<String> = None;
                let internal_tx = Arc::new(Mutex::new(internal_tx));

                loop {
                    let command = UsbIpCommand::read_from_socket(&mut sock_rx).await;
                    if let Err(err) = command {
                        if let Some(dev_id) = current_import_device_id {
                            let mut used_devices = self.used_devices.write().await;
                            let mut available_devices = self.available_devices.write().await;
                            match used_devices.remove(&dev_id) {
                                Some(dev) => available_devices.push(dev),
                                None => unreachable!(),
                            }
                        }

                        shutdown_tx.send(()).unwrap();
                        if err.kind() == ErrorKind::UnexpectedEof {
                            info!("[RX] Remote closed the connection");
                        } else {
                            warn!("[RX] Exiting due to broken socket");
                            warn!("{:?}", err);
                        }
                        return;
                    }

                    let cmd = command.unwrap();
                    trace!("[RX] Got command: {:?}", cmd);

                    let used_devices = self.used_devices.read().await;
                    let mut current_import_device = current_import_device_id
                        .clone()
                        .and_then(|ref id| used_devices.get(id));

                    match cmd {
                        UsbIpCommand::OpReqDevlist { .. } => {
                            let device_list = self.available_devices.read().await;
                            internal_tx
                                .clone()
                                .lock()
                                .unwrap()
                                .send(UsbIpResponse::op_rep_devlist(&device_list))
                                .unwrap();
                        }
                        UsbIpCommand::OpReqImport { busid, .. } => {
                            current_import_device_id = None;
                            current_import_device = None;
                            std::mem::drop(used_devices);

                            let mut used_devices = self.used_devices.write().await;
                            let mut available_devices = self.available_devices.write().await;

                            for (i, dev) in available_devices.iter().enumerate() {
                                let mut expected = dev.bus_id.as_bytes().to_vec();
                                expected.resize(32, 0);
                                if expected.as_slice() == busid {
                                    let dev = available_devices.remove(i);
                                    let dev_id = dev.bus_id.clone();
                                    used_devices.insert(dev.bus_id.clone(), dev);
                                    current_import_device_id = dev_id.clone().into();
                                    current_import_device =
                                        Some(used_devices.get(&dev_id).unwrap());
                                    break;
                                }
                            }

                            let res = if let Some(dev) = current_import_device {
                                UsbIpResponse::op_rep_import_success(dev)
                            } else {
                                UsbIpResponse::op_rep_import_fail()
                            };

                            internal_tx.clone().lock().unwrap().send(res).unwrap();
                        }
                        UsbIpCommand::UsbIpCmdUnlink { header, .. } => {
                            std::mem::drop(used_devices);
                            let mut used_devices = self.used_devices.write().await;
                            let mut available_devices = self.available_devices.write().await;

                            let dev = current_import_device_id
                                .clone()
                                .and_then(|ref k| used_devices.remove(k));

                            let res = match dev {
                                Some(dev) => {
                                    available_devices.push(dev);
                                    current_import_device_id = None;
                                    UsbIpResponse::usbip_ret_unlink_success(&header)
                                }
                                None => {
                                    warn!("Device not found");
                                    UsbIpResponse::usbip_ret_unlink_fail(&header)
                                }
                            };
                            internal_tx.clone().lock().unwrap().send(res).unwrap();
                        }

                        UsbIpCommand::UsbIpCmdSubmit {
                            mut header,
                            transfer_buffer_length,
                            setup,
                            data,
                            ..
                        } => {
                            let device = current_import_device.unwrap().clone();
                            let internal_tx = internal_tx.clone();

                            tokio::spawn(async move {
                                let out = header.direction == 0;
                                let real_ep = if out { header.ep } else { header.ep | 0x80 };

                                header.command = USBIP_RET_SUBMIT.into();

                                let res = match device.find_ep(real_ep as u8) {
                                    None => {
                                        warn!("Endpoint {:02x?} not found", real_ep);
                                        UsbIpResponse::usbip_ret_submit_fail(&header)
                                    }
                                    Some((ep, intf)) => {
                                        trace!("->Endpoint {:02x?}", ep);
                                        trace!("->Setup {:02x?}", setup);
                                        trace!("->Request {:02x?}", data);
                                        let resp = device
                                            .handle_urb(
                                                ep,
                                                intf,
                                                transfer_buffer_length,
                                                SetupPacket::parse(&setup),
                                                &data,
                                            )
                                            .await
                                            .unwrap();

                                        if out {
                                            trace!("<-Wrote {}", data.len());
                                        } else {
                                            trace!("<-Resp {:02x?}", resp);
                                        }

                                        UsbIpResponse::usbip_ret_submit_success(
                                            &header,
                                            0,
                                            0,
                                            resp,
                                            vec![],
                                        )
                                    }
                                };
                                internal_tx.clone().lock().unwrap().send(res).unwrap();
                            });
                        }
                    }
                }
            });

            // TX thread
            scope.spawn(async move {
                loop {
                    tokio::select! {
                        Some(res) = internal_rx.recv() => {
                            trace!("[TX] Staging response: {:?}", res.to_bytes());
                            sock_tx.write_all(res.to_bytes().as_slice()).await.unwrap();
                            trace!("[TX] Sent response");
                        },
                        _ = shutdown_rx.recv() => {
                            warn!("[TX] Exiting due to RX shutdown signal");
                            return;
                        }
                    }
                }
            });
            Ok(())
        });
        Ok(())
    }

    async fn serve(self, addr: SocketAddr) {
        trace!("Trying to listen on {:?}", addr);
        let listener = TcpListener::bind(addr)
            .await
            .unwrap_or_else(|_| panic!("Could not bind to {}", addr));
        trace!("Listening on {:?}", addr);

        let server = async move {
            loop {
                match listener.accept().await {
                    Ok((mut socket, _addr)) => {
                        info!("Got connection from {:?}", socket.peer_addr());
                        let new_server = self.clone();
                        tokio::spawn(async move {
                            let res = new_server.handler(&mut socket).await;
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
}

#[cfg(test)]
mod tests {
    use tokio::{net::TcpStream, task::JoinSet};

    use super::*;
    use crate::{
        cdc,
        usbip_protocol::{self, UsbIpHeaderBasic, USBIP_CMD_SUBMIT, USBIP_CMD_UNLINK},
        util::tests::*,
        ClassCode, UsbDevice, UsbInterfaceHandler,
    };

    const SINGLE_DEVICE_BUSID: &str = "0-0-0";

    fn new_server_with_single_device() -> AsyncUsbIpServer {
        AsyncUsbIpServer::new_simulated(vec![UsbDevice::new(0).with_interface(
            ClassCode::CDC as u8,
            cdc::CDC_ACM_SUBCLASS,
            0x00,
            "Test CDC ACM",
            cdc::UsbCdcAcmHandler::endpoints(),
            Arc::new(Mutex::new(
                Box::new(cdc::UsbCdcAcmHandler::new()) as Box<dyn UsbInterfaceHandler + Send>
            )),
        )])
    }

    fn op_req_import(busid: &str) -> Vec<u8> {
        let mut busid = busid.to_string().as_bytes().to_vec();
        busid.resize(32, 0);
        UsbIpCommand::OpReqImport {
            status: 0,
            busid: busid.try_into().unwrap(),
        }
        .to_bytes()
    }

    async fn attach_device(connection: &mut TcpStream, busid: &str) -> u32 {
        let req = op_req_import(busid);
        connection.write_all(req.as_slice()).await.unwrap();
        connection.read_u32().await.unwrap();
        let result = connection.read_u32().await.unwrap();
        if result == 0 {
            connection.read_exact(&mut vec![0; 0x138]).await.unwrap();
        }
        result
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn req_empty_devlist() {
        setup_test_logger();
        let server = AsyncUsbIpServer::new_simulated(vec![]);
        let req = UsbIpCommand::OpReqDevlist { status: 0 };

        let mut mock_socket = MockSocket::new(req.to_bytes());
        server.handler(&mut mock_socket).await.ok();

        assert_eq!(
            mock_socket.output,
            UsbIpResponse::op_rep_devlist(&[]).to_bytes(),
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn req_sample_devlist() {
        setup_test_logger();
        let server = new_server_with_single_device();
        let req = UsbIpCommand::OpReqDevlist { status: 0 };

        let mut mock_socket = MockSocket::new(req.to_bytes());
        server.handler(&mut mock_socket).await.ok();

        // OP_REP_DEVLIST
        // header: 0xC
        // device: 0x138
        // interface: 4 * 0x1
        assert_eq!(mock_socket.output.len(), 0xC + 0x138 + 4);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn req_import() {
        setup_test_logger();
        let server = new_server_with_single_device();

        // OP_REQ_IMPORT
        let req = op_req_import(SINGLE_DEVICE_BUSID);
        let mut mock_socket = MockSocket::new(req);
        server.handler(&mut mock_socket).await.ok();
        // OP_REQ_IMPORT
        assert_eq!(mock_socket.output.len(), 0x140);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn add_and_remove_10_devices() {
        setup_test_logger();
        let server = AsyncUsbIpServer::new_simulated(vec![]);
        let server_ = server.clone();
        let addr = get_free_address().await;
        let server_thread = tokio::spawn(server_.serve(addr));

        let mut join_set = JoinSet::new();
        let devices = (0..10)
            .map(|i| {
                let mut device = UsbDevice::new(i);
                device.bus_id = format!("0-0-{}", i);
                device
            })
            .collect::<Vec<_>>();

        for device in devices.iter() {
            let new_server = server.clone();
            let new_device = device.clone();
            join_set.spawn(async move {
                new_server.add_device(new_device).await;
            });
        }

        for device in devices.iter() {
            let new_server = server.clone();
            let new_device = device.clone();
            join_set.spawn(async move {
                new_server.remove_device(&new_device.bus_id).await.unwrap();
            });
        }

        while join_set.join_next().await.is_some() {}

        let device_len = server.clone().available_devices.read().await.len();

        assert_eq!(device_len, 0);
        server_thread.abort();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn send_usb_traffic_while_adding_and_removing_devices() {
        setup_test_logger();
        let server = new_server_with_single_device();
        let server_ = server.clone();

        let addr = get_free_address().await;
        let server_thread = tokio::spawn(server_.serve(addr));

        let cmd_loop_handle = tokio::spawn(async move {
            let mut connection = poll_connect(addr).await;
            let result = attach_device(&mut connection, SINGLE_DEVICE_BUSID).await;
            assert_eq!(result, 0);

            let cdc_loopback_bulk_cmd = UsbIpCommand::UsbIpCmdSubmit {
                header: usbip_protocol::UsbIpHeaderBasic {
                    command: USBIP_CMD_SUBMIT.into(),
                    seqnum: 1,
                    devid: 0,
                    direction: 0, // OUT
                    ep: 2,
                },
                transfer_flags: 0,
                transfer_buffer_length: 8,
                start_frame: 0,
                number_of_packets: 0,
                interval: 0,
                setup: [0; 8],
                data: vec![1, 2, 3, 4, 5, 6, 7, 8],
                iso_packet_descriptor: vec![],
            };

            loop {
                connection
                    .write_all(cdc_loopback_bulk_cmd.to_bytes().as_slice())
                    .await
                    .unwrap();
                let mut result = vec![0; 4 * 12];
                connection.read_exact(&mut result).await.unwrap();
            }
        });

        let add_and_remove_device_handle = tokio::spawn(async move {
            let mut join_set = JoinSet::new();
            let devices = (1..4)
                .map(|i| {
                    let mut device = UsbDevice::new(i);
                    device.bus_id = format!("0-0-{}", i);
                    device
                })
                .collect::<Vec<_>>();

            loop {
                for device in devices.iter() {
                    let new_server = server.clone();
                    let new_device = device.clone();
                    join_set.spawn(async move {
                        new_server.add_device(new_device).await;
                    });
                }

                for device in devices.iter() {
                    let new_server = server.clone();
                    let new_device = device.clone();
                    join_set.spawn(async move {
                        new_server.remove_device(&new_device.bus_id).await.unwrap();
                    });
                }
                while join_set.join_next().await.is_some() {}
                tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;
            }
        });

        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        cmd_loop_handle.abort();
        add_and_remove_device_handle.abort();
        server_thread.abort();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn only_single_connection_allowed_to_device() {
        setup_test_logger();
        let server = new_server_with_single_device();

        let addr = get_free_address().await;
        let server_thread = tokio::spawn(server.serve(addr));

        let mut first_connection = poll_connect(addr).await;
        let mut second_connection = TcpStream::connect(addr).await.unwrap();

        let result = attach_device(&mut first_connection, SINGLE_DEVICE_BUSID).await;
        assert_eq!(result, 0);

        let result = attach_device(&mut second_connection, SINGLE_DEVICE_BUSID).await;
        assert_eq!(result, 1);
        server_thread.abort();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn device_gets_released_on_cmd_unlink() {
        setup_test_logger();
        let server = new_server_with_single_device();

        let addr = get_free_address().await;
        let server_thread = tokio::spawn(server.serve(addr));

        let mut connection = poll_connect(addr).await;

        let result = attach_device(&mut connection, SINGLE_DEVICE_BUSID).await;
        assert_eq!(result, 0);

        let unlink_req = UsbIpCommand::UsbIpCmdUnlink {
            header: UsbIpHeaderBasic {
                command: USBIP_CMD_UNLINK.into(),
                seqnum: 1,
                devid: 0,
                direction: 0,
                ep: 0,
            },
            unlink_seqnum: 0,
        }
        .to_bytes();

        connection.write_all(unlink_req.as_slice()).await.unwrap();
        connection.read_exact(&mut [0; 4 * 5]).await.unwrap();
        let result = connection.read_u32().await.unwrap();
        connection.read_exact(&mut [0; 4 * 6]).await.unwrap();
        assert_eq!(result, 0);

        let result = attach_device(&mut connection, SINGLE_DEVICE_BUSID).await;
        assert_eq!(result, 0);
        server_thread.abort();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn device_gets_released_on_closed_socket() {
        setup_test_logger();
        let server = new_server_with_single_device();

        let addr = get_free_address().await;
        tokio::spawn(server.serve(addr));

        let mut connection = poll_connect(addr).await;
        let result = attach_device(&mut connection, SINGLE_DEVICE_BUSID).await;
        assert_eq!(result, 0);

        std::mem::drop(connection);

        let mut connection = TcpStream::connect(addr).await.unwrap();
        let result = attach_device(&mut connection, SINGLE_DEVICE_BUSID).await;
        assert_eq!(result, 0);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn req_import_get_device_desc() {
        setup_test_logger();
        let server = new_server_with_single_device();

        let mut req = op_req_import(SINGLE_DEVICE_BUSID);
        req.extend(
            UsbIpCommand::UsbIpCmdSubmit {
                header: UsbIpHeaderBasic {
                    command: USBIP_CMD_SUBMIT.into(),
                    seqnum: 1,
                    devid: 0,
                    direction: 1, // IN
                    ep: 0,
                },
                transfer_flags: 0,
                transfer_buffer_length: 0,
                start_frame: 0,
                number_of_packets: 0,
                interval: 0,
                // GetDescriptor to Device
                setup: [0x80, 0x06, 0x00, 0x01, 0x00, 0x00, 0x40, 0x00],
                data: vec![],
                iso_packet_descriptor: vec![],
            }
            .to_bytes(),
        );

        let mut mock_socket = MockSocket::new(req);
        server.handler(&mut mock_socket).await.ok();
        // OP_REQ_IMPORT + USBIP_CMD_SUBMIT + Device Descriptor
        assert_eq!(mock_socket.output.len(), 0x140 + 0x30 + 0x12);
    }
}
