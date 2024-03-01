use std::{
    collections::HashMap,
    net::{Ipv4Addr, SocketAddrV4},
    sync::atomic::{AtomicU32, Ordering},
    time::{Duration, Instant},
};

use dhcproto::v4::{
    Decodable, Decoder, DhcpOption, Encodable, Encoder, Flags, Message, MessageType, OptionCode,
};

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use uuid::Uuid;
static NEXT_XID: AtomicU32 = AtomicU32::new(1000);

pub struct DhcpClientService {
    //pub machines: Arc<Mutex<HashMap<MacAddr, Machine>>>,
    request_tx: tokio::sync::mpsc::Sender<RequestType>,
    request_rx: tokio::sync::mpsc::Receiver<RequestType>,
    response_tx: tokio::sync::mpsc::Sender<DhcpResponseInfo>,
    pub interface: Option<String>,
}

pub struct DhcpClient {
    request_tx: tokio::sync::mpsc::Sender<RequestType>,
    response_rx: tokio::sync::mpsc::Receiver<DhcpResponseInfo>,
}

impl DhcpClient {
    pub async fn request_ip(&mut self, uuid: Uuid, mac_address: &[u8; 6]) {
        let rt = RequestType::Request(DhcpRequestInfo {
            mac_address: *mac_address,
            uuid: Some(uuid),
            requested_address: None,
            server_address: None,
            start: Instant::now(),
            xid: None,
        });
        self.request_tx.send(rt).await.unwrap();
    }

    pub async fn receive_ip(&mut self) -> Option<DhcpResponseInfo> {
        self.response_rx.recv().await
    }
}

#[derive(Debug)]
enum RequestType {
    Request(DhcpRequestInfo),
    Response(DhcpResponseInfo),
}

#[derive(Clone, Debug)]
struct DhcpRequestInfo {
    mac_address: [u8; 6],
    uuid: Option<Uuid>,
    requested_address: Option<Ipv4Addr>,
    server_address: Option<Ipv4Addr>,
    start: Instant,
    xid: Option<u32>,
}

#[derive(Clone, Debug)]

pub struct DhcpResponseInfo {
    pub uuid: Option<Uuid>,
    pub mac_address: [u8; 6],
    pub ip_address: Ipv4Addr,
    pub hostname: Option<String>,
    pub subnet: Option<Ipv4Addr>,
}

impl DhcpClientService {
    pub fn new(interface: Option<String>) -> (DhcpClient, Self) {
        let (request_tx, request_rx) = tokio::sync::mpsc::channel(5);
        let (response_tx, response_rx) = tokio::sync::mpsc::channel(5);
        (
            DhcpClient {
                request_tx: request_tx.clone(),
                response_rx,
            },
            DhcpClientService {
                request_tx,
                request_rx,
                response_tx,
                interface,
            },
        )
    }

    pub async fn run(&mut self) {
        let mut requests: HashMap<[u8; 6], DhcpRequestInfo> = HashMap::default();

        let interface_name = self.interface.clone().unwrap();
        let interface = interface_name.as_bytes();
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).unwrap();
        socket.bind_device(Some(interface)).unwrap();
        let local_addr = "255.255.255.255:68".parse::<SocketAddrV4>().unwrap();
        socket.bind(&local_addr.into()).unwrap();
        socket.set_broadcast(true).unwrap();
        let udp_socket = UdpSocket::from_std(socket.into()).unwrap();

        loop {
            let mut buf = [0u8; 1024];
            tokio::select! {
                result = udp_socket.recv_from(&mut buf) => {
                    match result {
                        Ok((bytes_read, remote_addr)) => {
                            tracing::info!("Received {bytes_read} bytes from {remote_addr}");
                            dhcp_receiver_loop(&mut buf, &mut self.request_tx).await
                        }
                        Err(e) => tracing::warn!("udp recv failed: {:?}", e),
                    }
                }
                maybe_request = self.request_rx.recv() => {
                    if let Some(request_info) = maybe_request {
                        dhcp_sender_loop(&udp_socket, &mut requests, request_info, &self.response_tx).await;
                    }
                }
                _ = tokio::time::sleep(Duration::from_secs(5)) => {
                    for request in requests.values_mut() {
                        let elapsed = request.start.elapsed();
                        if elapsed > Duration::from_secs(10) {
                            send_discovery_packet(&udp_socket, request).await;
                        }
                    }
                }
            }
        }
    }
}

async fn dhcp_sender_loop(
    udp_socket: &UdpSocket,
    requests: &mut HashMap<[u8; 6], DhcpRequestInfo>,
    request_info: RequestType,
    response_tx: &tokio::sync::mpsc::Sender<DhcpResponseInfo>,
) {
    match request_info {
        RequestType::Request(mut request_info) => {
            if request_info.requested_address.is_some() {
                tracing::info!("New Request: {:?}", request_info);
                requests.remove(&request_info.mac_address);
                send_request_packet(udp_socket, request_info).await;
            } else {
                tracing::info!("New Discovery: {:?}", request_info);
                send_discovery_packet(udp_socket, &mut request_info).await;
                requests.insert(request_info.mac_address, request_info);
            }
        }
        RequestType::Response(response_info) => {
            response_tx.send(response_info).await.unwrap();
        }
    }
}

async fn dhcp_receiver_loop(buf: &mut [u8], request_tx: &tokio::sync::mpsc::Sender<RequestType>) {
    let msg = Message::decode(&mut Decoder::new(buf)).unwrap();
    let opts = msg.opts();
    if let Some(DhcpOption::MessageType(msg_type)) = opts.get(OptionCode::MessageType) {
        match msg_type {
            MessageType::Offer => {
                let server_address = msg.siaddr();
                tracing::info!("Offer Received from {}", server_address);
                let uuid = if let Some(DhcpOption::ClientIdentifier(uuid)) =
                    opts.get(OptionCode::ClientIdentifier)
                {
                    Some(Uuid::from_bytes(uuid.as_slice().try_into().unwrap()))
                } else {
                    None
                };
                if let Some(DhcpOption::ServerIdentifier(server_address)) =
                    opts.get(OptionCode::ServerIdentifier)
                {
                    let requested_address = msg.yiaddr();
                    let mac_address: [u8; 6] = <[u8; 6]>::try_from(msg.chaddr()).unwrap();

                    let request_info = RequestType::Request(DhcpRequestInfo {
                        mac_address,
                        uuid,
                        requested_address: Some(requested_address),
                        server_address: Some(*server_address), //xid: dhcp_packet.get_xid(),
                        start: Instant::now(),
                        xid: None,
                    });
                    tracing::info!("new request info: {:?}", request_info);
                    request_tx.send(request_info).await.unwrap();
                } else {
                    tracing::warn!("Server IP missing!");
                }
            }
            MessageType::Ack => {
                tracing::info!("Ack Received");
                let server_address = msg.siaddr();
                let requested_address = msg.yiaddr();
                let mac_address: [u8; 6] = <[u8; 6]>::try_from(msg.chaddr()).unwrap();

                tracing::info!("Offer Received from {}", server_address);
                tracing::info!("requested_address: {requested_address}");
                tracing::info!("mac_address: {mac_address:?}");
                if let Some(DhcpOption::ServerIdentifier(server_id)) =
                    opts.get(OptionCode::ServerIdentifier)
                {
                    tracing::info!("server id: {}", server_id);
                }

                if let Some(DhcpOption::BootFileSize(boot_file_size)) =
                    opts.get(OptionCode::BootFileSize)
                {
                    tracing::info!("boot file size: {}", boot_file_size);
                }

                if let Some(DhcpOption::VendorExtensions(bytes)) =
                    opts.get(OptionCode::VendorExtensions)
                {
                    let opt_val = find_string(70, bytes.as_slice());
                    tracing::info!("Found Vendor option 70: {}", opt_val);
                }
                if let Some(DhcpOption::BootfileName(boot_file_name)) =
                    opts.get(OptionCode::BootFileSize)
                {
                    tracing::info!(
                        "boot file size: {}",
                        String::from_utf8_lossy(boot_file_name)
                    );
                }
                let uuid = if let Some(DhcpOption::ClientIdentifier(uuid)) =
                    opts.get(OptionCode::ClientIdentifier)
                {
                    Some(Uuid::from_bytes(uuid.as_slice().try_into().unwrap()))
                } else {
                    None
                };

                let hostname =
                    if let Some(DhcpOption::Hostname(hostname)) = opts.get(OptionCode::Hostname) {
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
                    ip_address: requested_address,
                    mac_address,
                    uuid,
                    hostname,
                    subnet,
                });
                tracing::info!("new request info: {:?}", request_info);
                request_tx.send(request_info).await.unwrap();
            }
            _ => todo!(),
        }
    }
}

async fn send_request_packet(udp_socket: &tokio::net::UdpSocket, request_info: DhcpRequestInfo) {
    tracing::info!("request info: {:?}", request_info);
    let broadcast_ip = "255.255.255.255:67";
    let server_address = request_info.server_address.unwrap();
    let requested_address = request_info.requested_address.unwrap();
    let uuid = request_info.uuid.unwrap();

    let mut msg = Message::default();
    msg.set_opcode(dhcproto::v4::Opcode::BootRequest)
        .set_htype(dhcproto::v4::HType::Eth)
        .set_hops(0x0)
        .set_flags(Flags::default().set_broadcast())
        .set_xid(NEXT_XID.fetch_add(1, Ordering::Acquire))
        .set_secs(request_info.start.elapsed().as_secs() as u16)
        .set_chaddr(&request_info.mac_address);

    msg.opts_mut()
        .insert(DhcpOption::MessageType(MessageType::Request));
    msg.opts_mut()
        .insert(DhcpOption::ServerIdentifier(server_address));
    msg.opts_mut()
        .insert(DhcpOption::RequestedIpAddress(requested_address));
    msg.opts_mut()
        .insert(DhcpOption::ClassIdentifier("PXEClient".as_bytes().to_vec()));
    msg.opts_mut()
        .insert(DhcpOption::ClientIdentifier(uuid.into()));

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
    udp_socket.send_to(&buf, broadcast_ip).await.unwrap();
}

async fn send_discovery_packet(
    udp_socket: &tokio::net::UdpSocket,
    request_info: &mut DhcpRequestInfo,
) {
    tracing::info!("request info: {:?}", request_info);
    let broadcast_ip = "255.255.255.255:67";
    let uuid = request_info.uuid.unwrap();
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
        .set_chaddr(&request_info.mac_address);

    msg.opts_mut()
        .insert(DhcpOption::MessageType(MessageType::Discover));
    msg.opts_mut()
        .insert(DhcpOption::ClientIdentifier(uuid.into()));
    msg.opts_mut().insert(DhcpOption::ClientSystemArchitecture(
        dhcproto::v4::Architecture::Unknown(0x07),
    ));
    msg.opts_mut()
        .insert(DhcpOption::ClassIdentifier("PXEClient".as_bytes().to_vec()));

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
    udp_socket.send_to(&buf, broadcast_ip).await.unwrap();
}

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
fn find_string(code: u8, options: &[u8]) -> String {
    let opt_index: usize = find_code(code, options);
    let len: usize = options[opt_index + 1] as usize;

    tracing::info!("found string at {} len {}", opt_index, len);
    let start = opt_index + 2;
    let end = start + len;
    String::from_utf8_lossy(&options[start..end]).into_owned()
}
