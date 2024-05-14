use std::{
    collections::HashMap,
    fmt::Debug,
    net::{Ipv4Addr, SocketAddrV4},
    str::FromStr,
    sync::atomic::{AtomicU32, Ordering},
    time::{Duration, Instant},
};

use dhcproto::v4::{
    Decodable, Decoder, DhcpOption, Encodable, Encoder, Flags, Message, MessageType, OptionCode,
};

use rpc::MachineId;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::{
    net::UdpSocket,
    select,
    sync::mpsc::{channel, Receiver, Sender},
};
use uuid::Uuid;

use mac_address::MacAddress;

use crate::{api_client, config::MachineATronContext, MachineATronConfig};
static NEXT_XID: AtomicU32 = AtomicU32::new(1000);

pub struct DhcpRelayService {
    last_dhcp_request: Instant,
    app_context: MachineATronContext,
    app_config: MachineATronConfig,
    request_tx: Sender<RequestType>,
    request_rx: Receiver<RequestType>,
}

#[derive(Clone)]
pub struct DhcpRelayClient {
    request_tx: Sender<RequestType>,
}

impl Debug for DhcpRelayClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DhcpClient").finish()
    }
}

impl DhcpRelayClient {
    pub async fn stop_service(&mut self) {
        let rt = RequestType::Quit;
        if self.request_tx.send(rt).await.is_err() {
            tracing::warn!("Failed to shutdown dhcp relay service");
        }
    }

    pub async fn request_ip(
        &mut self,
        mat_id: Uuid,
        mac_address: &MacAddress,
        relay_address: &Ipv4Addr,
        class_identifier: &str,
        template_dir: String,
        response_tx: tokio::sync::oneshot::Sender<Option<DhcpResponseInfo>>,
    ) {
        tracing::debug!("requesting ip for mac: {}", mac_address);

        let rt = RequestType::Request(DhcpRequestInfo {
            mat_id,
            mac_address: *mac_address,
            relay_address: *relay_address,
            class_identifier: class_identifier.to_owned(),
            requested_address: None,
            server_address: None,
            start: Instant::now(),
            xid: None,
            template_dir,
            segment_id: None,
            response_tx,
        });

        if self.request_tx.send(rt).await.is_err() {
            tracing::warn!("Failed to send dhcp request to relay service");
        }
    }
}

#[derive(Debug)]
enum RequestType {
    Request(DhcpRequestInfo),
    Response(DhcpResponseInfo),
    Quit,
}

#[derive(Debug)]
struct DhcpRequestInfo {
    mat_id: Uuid,
    mac_address: MacAddress,
    relay_address: Ipv4Addr,
    class_identifier: String,
    requested_address: Option<Ipv4Addr>,
    server_address: Option<Ipv4Addr>,
    start: Instant,
    xid: Option<u32>,

    template_dir: String,
    segment_id: Option<Uuid>,

    response_tx: tokio::sync::oneshot::Sender<Option<DhcpResponseInfo>>,
}

#[derive(Clone, Debug)]

pub struct DhcpResponseInfo {
    pub mat_id: Uuid,
    pub interface_id: Option<Uuid>,
    pub machine_id: Option<MachineId>,
    pub mac_address: MacAddress,
    pub ip_address: Ipv4Addr,
    pub hostname: Option<String>,
    pub subnet: Option<Ipv4Addr>,
    pub segment_id: Option<Uuid>,
}

impl DhcpRelayService {
    pub fn new(
        app_context: MachineATronContext,
        app_config: MachineATronConfig,
    ) -> (DhcpRelayClient, Self) {
        let (request_tx, request_rx) = channel(5000);
        (
            DhcpRelayClient {
                request_tx: request_tx.clone(),
            },
            DhcpRelayService {
                last_dhcp_request: Instant::now(),
                app_context,
                app_config,
                request_tx,
                request_rx,
            },
        )
    }

    pub fn create_udp_socket(&self) -> UdpSocket {
        let interface = self.app_config.interface.as_bytes();
        // Note that this is simulating a dhcp relay, not a client, so it uses port 67 for both the source and destination port
        let local_addr = "0.0.0.0:10067".to_owned().parse::<SocketAddrV4>().unwrap();
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).unwrap();

        socket.bind_device(Some(interface)).unwrap();
        socket.set_reuse_port(true).unwrap();
        socket.set_reuse_address(true).unwrap();
        socket.set_broadcast(true).unwrap();
        socket.set_nonblocking(true).unwrap();
        socket.bind(&local_addr.into()).unwrap();
        UdpSocket::from_std(socket.into()).unwrap()
    }

    pub async fn run(&mut self) {
        let mut requests: HashMap<Uuid, DhcpRequestInfo> = HashMap::default();

        let udp_socket = self.create_udp_socket();

        let mut running = true;
        while running {
            let mut buf = [0u8; 1024];

            select! {
                msg = udp_socket.recv_from(&mut buf) => {
                    match msg {
                        Ok((_bytes_read, _remote_addr)) => {
                            Self::handle_dhcp_message(&mut buf, &mut self.request_tx, &mut requests).await;
                        },
                        Err(e) => {
                            tracing::warn!("reading from socket failed: {:?}", e);
                            running = false;
                        }
                    }
                }
                msg = self.request_rx.recv() => {
                    match msg {
                        Some(RequestType::Quit) => {
                            running = false;
                        }
                        Some(request_info) => {
                            if self.last_dhcp_request.elapsed() < Duration::from_millis(500) {
                                tokio::time::sleep(Duration::from_millis(400)).await;
                            }
                            self.last_dhcp_request = Instant::now();

                            if self.app_config.use_dhcp_api {
                                if let RequestType::Request(request_info) = request_info {
                                    self.fake_dhcp_request(request_info).await;
                                }
                            } else {
                                running = self.handle_request_message(&udp_socket, &mut requests, request_info).await;
                            }
                        }
                        None => tracing::warn!("request channel is closed"),
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(1000)) => {}
            }
        }
    }

    async fn fake_dhcp_request(&mut self, request_info: DhcpRequestInfo) {
        tracing::info!("requesting IP for {}", request_info.mat_id);
        let Ok(dhcp_record) = api_client::discover_dhcp(
            &self.app_context,
            request_info.mac_address.to_string(),
            request_info.template_dir,
            request_info.relay_address.to_string(),
            None,
        )
        .await
        else {
            tracing::warn!("discover_dhcp failed");
            if request_info.response_tx.send(None).is_err() {
                tracing::warn!("Failed to send dhcp response");
            }
            return;
        };

        tracing::info!(
            "dhcp request for {} through relay {} got address {} (machine id {:?})",
            request_info.mac_address,
            request_info.relay_address,
            dhcp_record.address,
            dhcp_record.machine_id,
        );

        let interface_uuid =
            Uuid::from_str(dhcp_record.machine_interface_id.unwrap().value.as_str()).ok();
        let segment_id = Uuid::from_str(dhcp_record.segment_id.unwrap().value.as_str()).ok();
        let machine_id = dhcp_record.machine_id;

        let response_info = DhcpResponseInfo {
            mat_id: request_info.mat_id,
            interface_id: interface_uuid,
            machine_id,
            mac_address: request_info.mac_address,
            ip_address: dhcp_record.address.parse::<Ipv4Addr>().unwrap(),
            hostname: Some(dhcp_record.fqdn),
            subnet: Some(
                dhcp_record
                    .prefix
                    .split_once('/')
                    .unwrap()
                    .0
                    .parse::<Ipv4Addr>()
                    .unwrap(),
            ),
            segment_id,
        };

        if request_info.response_tx.send(Some(response_info)).is_err() {
            tracing::warn!("Failed to send dhcp response");
        }
    }

    async fn handle_request_message(
        &mut self,
        send_udp_socket: &UdpSocket,
        requests: &mut HashMap<Uuid, DhcpRequestInfo>,
        request_info: RequestType,
    ) -> bool {
        match request_info {
            RequestType::Request(mut request_info) => {
                if request_info.requested_address.is_some() {
                    self.send_request_packet(send_udp_socket, request_info)
                        .await;
                } else {
                    self.send_discovery_packet(send_udp_socket, &mut request_info)
                        .await;
                    requests.insert(request_info.mat_id, request_info);
                }
            }
            RequestType::Response(response_info) => {
                let request_info = requests.remove(&response_info.mat_id).unwrap();
                if request_info.response_tx.send(Some(response_info)).is_err() {
                    tracing::warn!("Failed to send dhcp response");
                }
            }
            RequestType::Quit => {
                return false;
            }
        }
        true
    }

    async fn handle_dhcp_message(
        buf: &mut [u8],
        request_tx: &mut Sender<RequestType>,
        requests: &mut HashMap<Uuid, DhcpRequestInfo>,
    ) {
        let msg = Message::decode(&mut Decoder::new(buf)).unwrap();
        let opts = msg.opts();

        let mat_id = if let Some(DhcpOption::ClientIdentifier(uuid)) =
            opts.get(OptionCode::ClientIdentifier)
        {
            Uuid::from_bytes(uuid.as_slice().try_into().unwrap())
        } else {
            tracing::warn!("Ignoring dhcp message: missing client id");
            return;
        };

        let Some(request) = requests.remove(&mat_id) else {
            tracing::warn!("Ignoring unexpected dhcp message");
            return;
        };

        let server_address = msg.siaddr();
        let mac_address = MacAddress::new(msg.chaddr().try_into().unwrap());
        let relay_address = msg.giaddr();

        if let Some(DhcpOption::MessageType(msg_type)) = opts.get(OptionCode::MessageType) {
            match msg_type {
                MessageType::Offer => {
                    let class_identifier =
                        if let Some(DhcpOption::ClassIdentifier(class_identifier)) =
                            opts.get(OptionCode::ClassIdentifier)
                        {
                            String::from_utf8_lossy(class_identifier).to_string()
                        } else {
                            String::default()
                        };

                    let requested_address = msg.yiaddr();

                    let request_info = RequestType::Request(DhcpRequestInfo {
                        mat_id,
                        mac_address,
                        relay_address,
                        class_identifier,
                        requested_address: Some(requested_address),
                        server_address: Some(server_address),
                        start: Instant::now(),
                        xid: None,
                        template_dir: String::default(), //temporary work-around
                        segment_id: request.segment_id,
                        response_tx: request.response_tx,
                    });
                    if request_tx.send(request_info).await.is_err() {
                        tracing::warn!("Failed to send dhcp request");
                    }
                }
                MessageType::Ack => {
                    tracing::info!("Ack Received from {}", server_address);

                    let requested_address = msg.yiaddr();
                    let interface_id = if let Some(DhcpOption::VendorExtensions(bytes)) =
                        opts.get(OptionCode::VendorExtensions)
                    {
                        let opt_val = find_string(70, bytes.as_slice());
                        opt_val
                    } else {
                        String::default()
                    };

                    let hostname = if let Some(DhcpOption::Hostname(hostname)) =
                        opts.get(OptionCode::Hostname)
                    {
                        Some(hostname.clone())
                    } else {
                        None
                    };

                    let subnet = if let Some(DhcpOption::SubnetMask(subnet)) =
                        opts.get(OptionCode::SubnetMask)
                    {
                        Some(*subnet)
                    } else {
                        None
                    };

                    let request_info = RequestType::Response(DhcpResponseInfo {
                        mat_id,
                        ip_address: requested_address,
                        machine_id: None,
                        mac_address,
                        interface_id: Uuid::parse_str(&interface_id).ok(),
                        hostname,
                        subnet,
                        segment_id: request.segment_id,
                    });
                    if request_tx.send(request_info).await.is_err() {
                        tracing::warn!("Failed to send dhcp ack");
                    }
                    requests.remove(&mat_id);
                }
                _ => todo!(),
            }
        }
    }

    async fn send_request_packet(
        &self,
        udp_socket: &tokio::net::UdpSocket,
        request_info: DhcpRequestInfo,
    ) {
        let dest_ip = self.app_config.dhcp_server_address.clone() + ":10067";
        let server_address = request_info.server_address.unwrap();
        let requested_address = request_info.requested_address.unwrap();

        let mut msg = Message::default();
        msg.set_opcode(dhcproto::v4::Opcode::BootRequest)
            .set_htype(dhcproto::v4::HType::Eth)
            .set_hops(0x0)
            .set_flags(Flags::default().set_broadcast())
            .set_xid(NEXT_XID.fetch_add(1, Ordering::Acquire))
            .set_secs(request_info.start.elapsed().as_secs() as u16)
            .set_chaddr(&request_info.mac_address.bytes())
            .set_giaddr(request_info.relay_address);

        msg.opts_mut()
            .insert(DhcpOption::MessageType(MessageType::Request));
        msg.opts_mut()
            .insert(DhcpOption::ServerIdentifier(server_address));
        msg.opts_mut()
            .insert(DhcpOption::RequestedIpAddress(requested_address));
        msg.opts_mut().insert(DhcpOption::ClassIdentifier(
            request_info.class_identifier.as_bytes().to_vec(),
        ));
        msg.opts_mut()
            .insert(DhcpOption::ClientIdentifier(request_info.mat_id.into()));

        msg.opts_mut().insert(DhcpOption::ParameterRequestList(vec![
            OptionCode::SubnetMask,
            OptionCode::Router,
            OptionCode::Hostname,
            OptionCode::BroadcastAddr,
            OptionCode::VendorExtensions,
            OptionCode::RequestedIpAddress,
            OptionCode::AddressLeaseTime,
            OptionCode::ServerIdentifier,
            OptionCode::ParameterRequestList,
            OptionCode::Renewal,
            OptionCode::Rebinding,
            OptionCode::ClassIdentifier,
            OptionCode::BootfileName,
            OptionCode::BootFileSize,
        ]));

        let mut buf = Vec::default();
        let mut e = Encoder::new(&mut buf);
        msg.encode(&mut e).unwrap();
        udp_socket.send_to(&buf, dest_ip).await.unwrap();
    }

    async fn send_discovery_packet(
        &self,
        udp_socket: &tokio::net::UdpSocket,
        request_info: &mut DhcpRequestInfo,
    ) {
        let dest_ip = self.app_config.dhcp_server_address.clone() + ":10067";
        let xid = request_info.xid.unwrap_or_else(|| {
            let xid = NEXT_XID.fetch_add(1, Ordering::Acquire);
            request_info.xid = Some(xid);
            xid
        });

        let mut msg = Message::default();
        msg.set_opcode(dhcproto::v4::Opcode::BootRequest)
            .set_htype(dhcproto::v4::HType::Eth)
            .set_hops(0x0)
            .set_flags(Flags::default().set_broadcast())
            .set_xid(xid)
            .set_secs(request_info.start.elapsed().as_secs() as u16)
            .set_chaddr(&request_info.mac_address.bytes())
            .set_giaddr(request_info.relay_address);

        msg.opts_mut()
            .insert(DhcpOption::MessageType(MessageType::Discover));
        msg.opts_mut()
            .insert(DhcpOption::ClientIdentifier(request_info.mat_id.into()));
        msg.opts_mut().insert(DhcpOption::ClientSystemArchitecture(
            dhcproto::v4::Architecture::Unknown(0x07),
        ));
        msg.opts_mut().insert(DhcpOption::ClassIdentifier(
            request_info.class_identifier.as_bytes().to_vec(),
        ));

        msg.opts_mut().insert(DhcpOption::ParameterRequestList(vec![
            OptionCode::SubnetMask,
            OptionCode::Router,
            OptionCode::Hostname,
            OptionCode::BroadcastAddr,
            OptionCode::VendorExtensions,
            OptionCode::RequestedIpAddress,
            OptionCode::AddressLeaseTime,
            OptionCode::ServerIdentifier,
            OptionCode::ParameterRequestList,
            OptionCode::Renewal,
            OptionCode::Rebinding,
            OptionCode::ClassIdentifier,
            OptionCode::BootfileName,
            OptionCode::BootFileSize,
        ]));

        let mut buf = Vec::default();
        let mut e = Encoder::new(&mut buf);
        msg.encode(&mut e).unwrap();
        udp_socket.send_to(&buf, dest_ip).await.unwrap();
    }
}

#[allow(dead_code)]
fn find_code(code: u8, options: &[u8]) -> usize {
    let mut opt_index = 0;
    while opt_index < options.len() {
        if options[opt_index] == code {
            break;
        }

        let len = options[opt_index + 1] as usize;
        opt_index += len + 2;
    }
    opt_index
}

#[allow(dead_code)]
fn find_string(code: u8, options: &[u8]) -> String {
    let opt_index: usize = find_code(code, options);
    let len: usize = options[opt_index + 1] as usize;

    let start = opt_index + 2;
    let end = start + len;
    String::from_utf8_lossy(&options[start..end]).into_owned()
}
