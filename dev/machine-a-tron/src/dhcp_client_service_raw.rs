use std::{
    collections::HashMap, net::Ipv4Addr, sync::atomic::{AtomicU32, Ordering}, time::{Duration, Instant}
};

use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::{
    datalink::{self, DataLinkSender},
    packet::{
        dhcp::{DhcpHardwareType, DhcpOperation, DhcpPacket, MutableDhcpPacket},
        ethernet::EthernetPacket,
        ipv4::{Ipv4Packet, MutableIpv4Packet},
        udp::{MutableUdpPacket, UdpPacket},
        Packet,
    },
    util::MacAddr,
};
use pnet::datalink::{Channel::Ethernet, DataLinkReceiver};
use uuid::Uuid;

static NEXT_XID: AtomicU32 = AtomicU32::new(1000);

pub struct DhcpClientService {
    //pub machines: Arc<Mutex<HashMap<MacAddr, Machine>>>,
    request_tx: tokio::sync::mpsc::Sender<RequestType>,
    request_rx: tokio::sync::mpsc::Receiver<RequestType>,
    response_tx: tokio::sync::mpsc::Sender<DhcpResponseInfo>,
    pub interface: datalink::NetworkInterface,
}

pub struct DhcpClient{
    request_tx: tokio::sync::mpsc::Sender<RequestType>,
    response_rx: tokio::sync::mpsc::Receiver<DhcpResponseInfo>
}

impl DhcpClient {
    pub async fn request_ip(&mut self, uuid: Uuid,  mac_address: MacAddr) {
        let rt = RequestType::Request(DhcpRequestInfo{
            mac_address,
            uuid: Some(uuid),
            requested_address: None,
            server_address: None,
            start: Instant::now(),
        });
        self.request_tx.send(rt).await.unwrap();
    }

    pub async fn receive_ip(&mut self) -> Option<DhcpResponseInfo> {
        self.response_rx.recv().await
    }
}

enum RequestType {
    Request(DhcpRequestInfo),
    Response(DhcpResponseInfo),
}

#[derive(Debug)]
struct DhcpRequestInfo {
    mac_address: MacAddr,
    uuid: Option<Uuid>,
    requested_address: Option<Ipv4Addr>,
    server_address: Option<Ipv4Addr>,
    start: Instant,
}

#[allow(dead_code)]
pub struct DhcpResponseInfo {
    pub mac_address: MacAddr,
    pub ip_address: Ipv4Addr,
    pub hostname: String,
    pub subnet: Ipv4Addr,
}

impl DhcpClientService {
    pub fn new(interface: datalink::NetworkInterface) -> (DhcpClient, Self) {
        let (request_tx, request_rx) = tokio::sync::mpsc::channel(5);
        let (response_tx, response_rx) = tokio::sync::mpsc::channel(5);
        (DhcpClient {
            request_tx:request_tx.clone(),
            response_rx,
         },
          DhcpClientService {
            request_tx,
            request_rx,
            response_tx,
            interface,
        })
    }

    pub fn run(&mut self) {
        let interface = self.interface.clone();

        //let (internal_tx, internal_rx) = std::sync::mpsc::sync_channel::<RequestType>(2);
        let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
            Ok(Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => panic!("Unhandled channel type"),
            Err(e) => panic!(
                "An error occurred when creating the datalink channel: {}",
                e
            ),
        };

        let request_clone = self.request_tx.clone();
        let _handle: std::thread::JoinHandle<_> = std::thread::spawn(move || {
            dhcp_receiver_loop(&mut rx, request_clone);
        });

        dhcp_sender_loop(&mut tx, &mut self.request_rx, &self.response_tx);
        //handle.join();
    }
}

fn dhcp_sender_loop(
    tx: &mut Box<dyn DataLinkSender>,
    request_rx: &mut tokio::sync::mpsc::Receiver<RequestType>,
    response_tx: &tokio::sync::mpsc::Sender<DhcpResponseInfo>,
) {
    let mut requests: HashMap<MacAddr, DhcpRequestInfo> = HashMap::default();

    loop {
        match request_rx.blocking_recv() {
            Some(RequestType::Request(request_info)) => {
                tracing::info!("New Request: {:?}", request_info);
                if request_info.requested_address.is_some() {
                    send_request_packet(tx, request_info);
                } else {
                    send_discovery_packet(tx, &request_info);
                    requests.insert(request_info.mac_address, request_info);
                }
            }
            Some(RequestType::Response(response_info)) => {
                response_tx.blocking_send(response_info).unwrap();
            }
            None => tracing::info!("Request channel closed"),
        }
        for request in requests.values() {
            let elapsed = request.start.elapsed();
            if elapsed > Duration::from_secs(10) {
                send_discovery_packet(tx, request);
            }
        }
    }
}

fn dhcp_receiver_loop(
    rx: &mut Box<dyn DataLinkReceiver>,
    request_tx: tokio::sync::mpsc::Sender<RequestType>,
) {
    loop {
        match rx.next() {
            Ok(packet) => {
                let ethernet_header = EthernetPacket::new(packet).unwrap();
                if ethernet_header.get_ethertype() == EtherTypes::Ipv4 {
                    let ip_header = Ipv4Packet::new(ethernet_header.payload())
                        .expect("Failed to parse ip header");
                    let udp_header =
                        UdpPacket::new(ip_header.payload()).expect("Failed to parse udp header");
                    /*
                                                tracing::info!(
                                                    "{}:{} -> {}:{}",
                                                    ip_header.get_source(),
                                                    udp_header.get_source(),
                                                    ip_header.get_destination(),
                                                    udp_header.get_destination()
                                                );
                    */
                    if (udp_header.get_destination() == 67 && udp_header.get_source() == 68)
                        || (udp_header.get_source() == 67 && udp_header.get_destination() == 68)
                    {
                        let dhcp_packet = DhcpPacket::new(udp_header.payload())
                            .expect("Failed to parse DHCP packet");
                        tracing::info!("dhcp : {dhcp_packet:?}");
                        let mac_address = dhcp_packet.get_chaddr();
                        match dhcp_packet.get_op() {
                            DhcpOperation(2) => {
                                let options = dhcp_packet.payload();
                                assert_eq!(options[0..6], [0x63, 0x82, 0x53, 0x63, 0x35, 0x01]);
                                let real_op = options[6];
                                match real_op {
                                    0x02 => {
                                        let option_val = find_option(0x36, &options[4..]);
                                        let request_info = RequestType::Request(DhcpRequestInfo {
                                            mac_address,
                                            uuid: None,
                                            requested_address: Some(dhcp_packet.get_yiaddr()),
                                            server_address: Some(Ipv4Addr::from(option_val)), //xid: dhcp_packet.get_xid(),
                                            start: Instant::now(),
                                        });
                                        request_tx.blocking_send(request_info).unwrap();
                                    }
                                    0x05 => {
                                        let subnet =
                                            Ipv4Addr::from(find_option(0x01, &options[4..]));
                                            request_tx.blocking_send(RequestType::Response(DhcpResponseInfo {
                                                mac_address,
                                                ip_address: dhcp_packet.get_yiaddr(),
                                                hostname: find_string(0x0c, &options[4..]),
                                                subnet,
                                            }))
                                            .unwrap();
                                    }
                                    op => tracing::warn!(
                                        "Ignoring unexpected dhcp message: op={}",
                                        op
                                    ),
                                }
                            }
                            op => tracing::warn!("Ignoring unexpected dhcp message: op={}", op.0),
                        }
                    };
                }
            }
            Err(e) => {
                // If an error occurs, we can handle it here
                panic!("An error occurred while reading: {}", e);
            }
        }
    }
}

fn send_request_packet(tx: &mut Box<dyn DataLinkSender>, request_info: DhcpRequestInfo) {
    tracing::info!("request info: {:?}", request_info);
    let broadcast_ip = Ipv4Addr::new(255, 255, 255, 255);
    let server_address = request_info.server_address.unwrap();
    let requested_address = request_info.requested_address.unwrap();

    let server_id: Vec<u8> = [0x36u8, 0x04]
        .iter()
        .chain(&server_address.octets())
        .cloned()
        .collect();

    let requested_ip: Vec<u8> = [0x32u8, 0x04]
        .iter()
        .chain(&requested_address.octets())
        .cloned()
        .collect();

    #[rustfmt::skip]
    let options: Vec<u8> = [
        // DHCP magic cookie (must be first)
        0x63, 0x82, 0x53, 0x63,
        // DHCP message type
        0x35, 0x01, 0x03,
        // param req list
        0x37, 0x0e, 0x01, 0x03, 0x0c, 0x1c, 0x28, 0x29, 0x2a, 0x2b, 0x32, 0x33, 0x36, 0x3a, 0x3b, 0x3c,
    ]
    .iter()
    .chain(&server_id)
    .chain(&requested_ip)
    .chain(&[0xffu8])
    .cloned()
    .collect();

    // 202 bytes for boot file name and server host name (not used but still added) and padding
    let dhcp_buffer_size = DhcpPacket::minimum_packet_size() + options.len() + 202;
    let mut discover_data = vec![0u8; dhcp_buffer_size];
    let mut discover_request =
        MutableDhcpPacket::new(&mut discover_data).expect("Failed to create dhcp packet");
    discover_request.set_op(DhcpOperation(1));
    discover_request.set_htype(DhcpHardwareType(1));
    discover_request.set_hlen(6);
    discover_request.set_chaddr(request_info.mac_address.clone());
    //    discover_request.set_xid(request_info.xid);
    discover_request.set_xid(NEXT_XID.fetch_add(1, Ordering::Acquire));
    discover_request.set_options(&options);
    discover_request.set_file(&[]);
    discover_request.set_flags(0x8000);
    discover_request.set_secs(request_info.start.elapsed().as_secs() as u16);
    tracing::info!(
        "dhcp min: {} actual: {} calc: {}",
        DhcpPacket::minimum_packet_size(),
        discover_request.packet().len(),
        dhcp_buffer_size
    );
    tracing::info!("udp: {discover_request:?}");

    let udp_buffer_size = UdpPacket::minimum_packet_size() + discover_request.packet().len();
    let mut udp_data = vec![0u8; udp_buffer_size];
    let mut udp_packet = MutableUdpPacket::new(&mut udp_data).unwrap();
    udp_packet.set_destination(67);
    udp_packet.set_source(68);
    udp_packet.set_payload(discover_request.packet());
    udp_packet.set_length((dhcp_buffer_size + 8) as u16);
    //    udp_packet.set_length(discover_request.packet().len() as u16);

    let udp_checksum = pnet::packet::udp::ipv4_checksum(
        &udp_packet.to_immutable(),
        &Ipv4Addr::UNSPECIFIED,
        &broadcast_ip,
    );
    udp_packet.set_checksum(udp_checksum);
    /*
        tracing::info!(
            "udp min: {} actual: {} calc: {}",
            UdpPacket::minimum_packet_size(),
            udp_packet.packet().len(),
            udp_buffer_size
        );
        tracing::info!("udp: {udp_packet:?}");
    */
    let ip_buffer_size = MutableIpv4Packet::minimum_packet_size() + udp_packet.packet().len();
    let mut ip_data = vec![0u8; ip_buffer_size];
    let mut ip_packet = MutableIpv4Packet::new(&mut ip_data).unwrap();
    ip_packet.set_version(4);
    ip_packet.set_header_length(5);
    ip_packet.set_destination(broadcast_ip);
    ip_packet.set_ttl(255);
    ip_packet.set_next_level_protocol(pnet::packet::ip::IpNextHeaderProtocols::Udp);
    ip_packet.set_total_length(ip_buffer_size as u16);
    ip_packet.set_payload(udp_packet.packet());
    let ip_checksum = pnet::packet::ipv4::checksum(&ip_packet.to_immutable());
    ip_packet.set_checksum(ip_checksum);

    /*
        tracing::info!(
            "ip min: {} actual: {} calc: {}",
            MutableIpv4Packet::minimum_packet_size(),
            ip_packet.packet().len(),
            ip_buffer_size
        );
        tracing::info!("ip: {ip_packet:?}");
    */

    let mut eth_data =
        vec![0u8; MutableEthernetPacket::minimum_packet_size() + ip_packet.packet().len()];
    let mut eth_packet = MutableEthernetPacket::new(&mut eth_data).unwrap();
    eth_packet.set_destination(MacAddr::broadcast());
    eth_packet.set_source(request_info.mac_address.clone());
    eth_packet.set_ethertype(EtherTypes::Ipv4);
    eth_packet.set_payload(ip_packet.packet());

    tracing::info!("Sending dhcp request: {eth_packet:?}");
    tx.send_to(eth_packet.packet(), None).unwrap().unwrap();
}

fn send_discovery_packet(tx: &mut Box<dyn DataLinkSender>, request: &DhcpRequestInfo) {
    let broadcast_ip = Ipv4Addr::new(255, 255, 255, 255);

    let xid = NEXT_XID.fetch_add(1, Ordering::Acquire);
    let uuid = request.uuid.unwrap();

    #[rustfmt::skip]
    let options: Vec<u8> = [
        // DHCP magic cookie (must be first)
        0x63, 0x82, 0x53, 0x63,
        // DHCP message type
        0x35, 0x01, 0x01,
        // max message size
        0x39, 0x02, 0x05, 0xc0,
        // param req list
        0x37, 0x0e, 0x01, 0x03, 0x0c, 0x1c, 0x28, 0x29, 0x2a, 0x2b, 0x32, 0x33, 0x36, 0x3a, 0x3b, 0x3c,
        //system arch
        0x5d, 0x02, 0x00, 0x07,
        // vendor class id
        0x3c, 0x20, 0x50, 0x58, 0x45, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x3a, 0x41, 0x72,
        0x63, 0x68, 0x3a, 0x30, 0x30, 0x30, 0x30, 0x37, 0x3a, 0x55, 0x4e, 0x44, 0x49, 0x3a,
        0x30, 0x30, 0x33, 0x30, 0x30, 0x31,
        // UUID option, length and type (hex)
         0x61, 0x11, 0x00,
    ].iter().chain(uuid.as_bytes()).chain(&[0xffu8]).cloned().collect();

    // 202 bytes for boot file name and server host name (not used but still added) and padding
    let dhcp_buffer_size = DhcpPacket::minimum_packet_size() + options.len() + 202;
    let mut request_data = vec![0u8; dhcp_buffer_size];
    let mut dhcp_request =
        MutableDhcpPacket::new(&mut request_data).expect("Failed to create dhcp packet");
    dhcp_request.set_op(DhcpOperation(1));
    dhcp_request.set_htype(DhcpHardwareType(1));
    dhcp_request.set_hlen(6);
    dhcp_request.set_chaddr(request.mac_address);
    dhcp_request.set_xid(xid);
    dhcp_request.set_options(&options);
    dhcp_request.set_file(&[]);
    dhcp_request.set_flags(0x8000);
    dhcp_request.set_secs(0x04);

    let udp_buffer_size = UdpPacket::minimum_packet_size() + dhcp_request.packet().len();
    let mut udp_data = vec![0u8; udp_buffer_size];
    let mut udp_packet = MutableUdpPacket::new(&mut udp_data).unwrap();
    udp_packet.set_destination(67);
    udp_packet.set_source(68);
    udp_packet.set_payload(dhcp_request.packet());
    udp_packet.set_length(udp_buffer_size as u16);
    let udp_checksum = pnet::packet::udp::ipv4_checksum(
        &udp_packet.to_immutable(),
        &Ipv4Addr::UNSPECIFIED,
        &broadcast_ip,
    );
    udp_packet.set_checksum(udp_checksum);

    tracing::info!(
        "udp min: {} actual: {} calc: {}",
        UdpPacket::minimum_packet_size(),
        udp_packet.packet().len(),
        udp_buffer_size
    );
    tracing::info!("udp: {udp_packet:?}");

    let ip_buffer_size = MutableIpv4Packet::minimum_packet_size() + udp_packet.packet().len();
    let mut ip_data = vec![0u8; ip_buffer_size];
    let mut ip_packet = MutableIpv4Packet::new(&mut ip_data).unwrap();
    ip_packet.set_version(4);
    ip_packet.set_header_length(5);
    ip_packet.set_destination(broadcast_ip);
    ip_packet.set_ttl(255);
    ip_packet.set_next_level_protocol(pnet::packet::ip::IpNextHeaderProtocols::Udp);
    ip_packet.set_total_length(ip_buffer_size as u16);
    ip_packet.set_payload(udp_packet.packet());
    let ip_checksum = pnet::packet::ipv4::checksum(&ip_packet.to_immutable());
    ip_packet.set_checksum(ip_checksum);

    tracing::info!(
        "ip min: {} actual: {} calc: {}",
        MutableIpv4Packet::minimum_packet_size(),
        ip_packet.packet().len(),
        ip_buffer_size
    );
    tracing::info!("ip: {ip_packet:?}");

    let mut eth_data =
        vec![0u8; MutableEthernetPacket::minimum_packet_size() + ip_packet.packet().len()];
    let mut eth_packet = MutableEthernetPacket::new(&mut eth_data).unwrap();
    eth_packet.set_destination(MacAddr::broadcast());
    eth_packet.set_source(request.mac_address);
    eth_packet.set_ethertype(EtherTypes::Ipv4);
    eth_packet.set_payload(ip_packet.packet());

    tracing::info!("Sending dhcp discover: {eth_packet:?}");
    tx.send_to(eth_packet.packet(), None).unwrap().unwrap();
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

fn find_option(code: u8, options: &[u8]) -> [u8; 4] {
    let opt_index: usize = find_code(code, options);
    let len: usize = options[opt_index + 1] as usize;
    assert_eq!(len, 4);
    let start = opt_index + 2;
    let end = start + len;
    options[start..end].try_into().unwrap()
}
