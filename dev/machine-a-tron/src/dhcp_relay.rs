use std::net::SocketAddr;
use std::{
    collections::HashMap,
    fmt::Debug,
    net::{Ipv4Addr, SocketAddrV4},
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
use tokio::time::sleep;

use crate::{
    api_client::{self, ClientApiError},
    config::{MachineATronConfig, MachineATronContext},
};
static NEXT_XID: AtomicU32 = AtomicU32::new(1000);

type DhcpRelayResult = Result<(), DhcpRelayError>;

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

    pub fn create_udp_socket(&self) -> Result<UdpSocket, DhcpRelayError> {
        let interface = self.app_config.interface.as_bytes();
        // Note that this is simulating a dhcp relay, not a client, so it uses port 67 for both the source and destination port
        let local_addr = "0.0.0.0:10067".to_owned().parse::<SocketAddrV4>().unwrap();
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).unwrap();

        socket.bind_device(Some(interface))?;
        socket.set_reuse_port(true)?;
        socket.set_reuse_address(true)?;
        socket.set_broadcast(true)?;
        socket.set_nonblocking(true)?;
        socket.bind(&local_addr.into())?;
        UdpSocket::from_std(socket.into()).map_err(DhcpRelayError::from)
    }

    pub async fn run(&mut self) -> DhcpRelayResult {
        let mut requests: HashMap<Uuid, DhcpRequestInfo> = HashMap::default();

        let udp_socket =
            if self.app_config.use_dhcp_api {
                None
            } else {
                Some(self.create_udp_socket().inspect_err(|e| {
                    tracing::error!("DHCP relay: error creating UDP socket: {}", e)
                })?)
            };

        let mut running = true;
        while running {
            let mut buf = [0u8; 1024];
            select! {
                msg = Self::get_next_request_from_udp_socket_or_sleep_forever(&mut buf, udp_socket.as_ref()) => {
                    match msg {
                        Ok((_bytes_read, _remote_addr)) => {
                            _ = Self::handle_dhcp_message(&mut buf, &mut self.request_tx, &mut requests).await
                                .inspect_err(|e| tracing::warn!("Could not handle DHCP message: {}", e));
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

                            if let Some(udp_socket) = udp_socket.as_ref() {
                                running = self.handle_request_message(udp_socket, &mut requests, request_info).await;
                            } else if let RequestType::Request(request_info) = request_info {
                                // Handle the request using the API server, and send the
                                // response back. Send a None response if we got an error
                                // handling the request: If we don't send a response, the
                                // client will be awaiting response_rx forever.
                                let response = self.fake_dhcp_request(&request_info).await
                                    .inspect_err(|e| tracing::error!("Error sending fake DHCP request via API: {}", e))
                                    .ok();
                                if request_info.response_tx.send(response).is_err() {
                                    tracing::error!("Error sending fake DHCP response");
                                }
                            }
                        }
                        None => tracing::warn!("request channel is closed"),
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(1000)) => {}
            }
        }
        Ok(())
    }

    /// Read from the given Option<&UdpSocket> if it's Some, else sleep forever.
    ///
    /// This is a simple ha^H^Htrick to make it so we can avoid listening on a UNIX socket
    /// altogether if we're not configured to, but without needing to worry about condidtionally
    /// passing a UDP socket to tokio::select.
    async fn get_next_request_from_udp_socket_or_sleep_forever(
        buf: &mut [u8],
        udp_socket: Option<&UdpSocket>,
    ) -> std::io::Result<(usize, SocketAddr)> {
        let Some(udp_socket) = udp_socket else {
            sleep(Duration::from_secs(u64::MAX)).await;
            unreachable!("No UDP socket configured, should sleep forever")
        };
        udp_socket.recv_from(buf).await
    }

    async fn fake_dhcp_request(
        &mut self,
        request_info: &DhcpRequestInfo,
    ) -> Result<DhcpResponseInfo, DhcpRelayError> {
        tracing::info!("requesting IP for {}", request_info.mat_id);

        let dhcp_record = api_client::discover_dhcp(
            &self.app_context,
            request_info.mac_address.to_string(),
            request_info.template_dir.clone(),
            request_info.relay_address.to_string(),
            None,
        )
        .await
        .inspect_err(|e| {
            tracing::warn!("discover_dhcp failed: {e}");
        })?;

        tracing::info!(
            "dhcp request for {} through relay {} got address {} (machine id {:?})",
            request_info.mac_address,
            request_info.relay_address,
            dhcp_record.address,
            dhcp_record.machine_id,
        );

        let interface_uuid = dhcp_record.machine_interface_id.ok_or_else(|| {
            DhcpRelayError::InvalidDhcpRecord("missing machine_interface_id".to_string())
        })?;
        let segment_id = dhcp_record
            .segment_id
            .ok_or_else(|| DhcpRelayError::InvalidDhcpRecord("missing segment_id".to_string()))?;
        let machine_id = dhcp_record.machine_id;

        let response_info = DhcpResponseInfo {
            mat_id: request_info.mat_id,
            interface_id: Some(Uuid::try_from(interface_uuid).unwrap()),
            machine_id,
            mac_address: request_info.mac_address,
            ip_address: dhcp_record.address.parse::<Ipv4Addr>().map_err(|e| {
                DhcpRelayError::InvalidDhcpRecord(format!(
                    "{} is not an IPv4 address: {}",
                    dhcp_record.address, e
                ))
            })?,
            hostname: Some(dhcp_record.fqdn),
            subnet: Some(
                dhcp_record
                    .prefix
                    .split_once('/')
                    .ok_or_else(|| {
                        DhcpRelayError::InvalidDhcpRecord(format!(
                            "contains an invalid prefix (must contain a '/'): {}",
                            dhcp_record.prefix
                        ))
                    })?
                    .0
                    .parse::<Ipv4Addr>()
                    .map_err(|e| {
                        DhcpRelayError::InvalidDhcpRecord(format!(
                            "contains an invalid prefix: {}",
                            e
                        ))
                    })?,
            ),
            segment_id: Some(Uuid::try_from(segment_id).unwrap()),
        };

        Ok(response_info)
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
                    _ = self
                        .send_request_packet(send_udp_socket, request_info)
                        .await
                        .inspect_err(|e| tracing::warn!("Error sending request packet: {e}"));
                } else {
                    _ = self
                        .send_discovery_packet(send_udp_socket, &mut request_info)
                        .await
                        .inspect_err(|e| tracing::warn!("Error sending request packet: {e}"));
                    requests.insert(request_info.mat_id, request_info);
                }
            }
            RequestType::Response(response_info) => {
                let Some(request_info) = requests.remove(&response_info.mat_id) else {
                    tracing::error!(
                        "Cannot find DHCP request corresponding to response {:?}",
                        response_info
                    );
                    return false;
                };
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
    ) -> DhcpRelayResult {
        let msg = Message::decode(&mut Decoder::new(buf))?;
        let opts = msg.opts();

        let mat_id = if let Some(DhcpOption::ClientIdentifier(uuid)) =
            opts.get(OptionCode::ClientIdentifier)
        {
            Uuid::from_bytes(uuid.as_slice().try_into().map_err(|_| {
                DhcpRelayError::InvalidDhcpRecord("Invalid UUID in client id field".to_string())
            })?)
        } else {
            return Err(DhcpRelayError::InvalidDhcpRecord(
                "missing client id".to_string(),
            ));
        };

        let request = requests
            .remove(&mat_id)
            .ok_or(DhcpRelayError::MissingDhcpRequest)?;

        let server_address = msg.siaddr();
        let mac_address = MacAddress::new(msg.chaddr().try_into().map_err(|_| {
            DhcpRelayError::InvalidDhcpRecord(format!(
                "chaddr is not a valid mac address: {:?}",
                msg.chaddr()
            ))
        })?);
        let relay_address = msg.giaddr();

        let DhcpOption::MessageType(msg_type) = opts
            .get(OptionCode::MessageType)
            .ok_or_else(|| DhcpRelayError::InvalidDhcpRecord("Missing message type".to_string()))?
        else {
            return Err(DhcpRelayError::InvalidDhcpRecord(
                "Invalid message type".to_string(),
            ));
        };
        match msg_type {
            MessageType::Offer => {
                let class_identifier = if let Some(DhcpOption::ClassIdentifier(class_identifier)) =
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
            _ => {
                tracing::error!("Unknown message type {:?}", msg_type);
            }
        };
        Ok(())
    }

    async fn send_request_packet(
        &self,
        udp_socket: &tokio::net::UdpSocket,
        request_info: DhcpRequestInfo,
    ) -> DhcpRelayResult {
        let dest_ip = self.app_config.dhcp_server_address.clone() + ":10067";
        let server_address = request_info.server_address.ok_or_else(|| {
            DhcpRelayError::InvalidDhcpRecord("missing server address".to_string())
        })?;
        let requested_address = request_info.requested_address.ok_or_else(|| {
            DhcpRelayError::InvalidDhcpRecord("missing requested address".to_string())
        })?;

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
        msg.encode(&mut e)?;
        udp_socket.send_to(&buf, dest_ip).await?;
        Ok(())
    }

    async fn send_discovery_packet(
        &self,
        udp_socket: &tokio::net::UdpSocket,
        request_info: &mut DhcpRequestInfo,
    ) -> DhcpRelayResult {
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
        msg.encode(&mut e)?;
        udp_socket.send_to(&buf, dest_ip).await?;
        Ok(())
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

#[derive(thiserror::Error, Debug)]
pub enum DhcpRelayError {
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Client API error: {0}")]
    ClientApiError(#[from] ClientApiError),
    #[error("Invalid DHCP record: {0}")]
    InvalidDhcpRecord(String),
    #[error("Error sending DHCP response: {0}")]
    ErrorSendingResponse(String),
    #[error("Error decoding DHCP request: {0}")]
    ErrorDecodingDhcpRequest(#[from] dhcproto::error::DecodeError),
    #[error("Could not find DHCP request corresponding to this response")]
    MissingDhcpRequest,
    #[error("Error encoding DHCP response")]
    ResponseEncodingError(#[from] dhcproto::error::EncodeError),
}
