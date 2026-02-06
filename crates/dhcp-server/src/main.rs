/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

mod cache;
mod command_line;
mod errors;
mod modes;
mod packet_handler;
mod rpc;
mod util;
mod vendor_class;

use std::error::Error;
use std::net::SocketAddr;
use std::sync::Arc;

use ::rpc::forge::{DhcpDiscovery, DhcpRecord};
use cache::CacheEntry;
use chrono::Utc;
use command_line::{Args, ServerMode};
use errors::DhcpError;
use lru::LruCache;
use modes::DhcpMode;
use modes::controller::Controller;
use modes::dpu::{Dpu, get_host_config};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tonic::async_trait;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::prelude::*;
use utils::models::dhcp::{DhcpConfig, DhcpTimestamps, DhcpTimestampsFilePath, HostConfig};

use crate::util::get_socket;

pub struct Server {
    socket: Arc<UdpSocket>,
}

const MAX_PARALLEL_PACKET_HANDLING_ALLOWED: usize = 128;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let env_filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy()
        .add_directive("tower=warn".parse().unwrap())
        .add_directive("rustls=warn".parse().unwrap())
        .add_directive("hyper=warn".parse().unwrap())
        .add_directive("tokio_util::codec=warn".parse().unwrap())
        .add_directive("h2=warn".parse().unwrap())
        .add_directive("hickory_resolver::error=info".parse().unwrap())
        .add_directive("hickory_proto::xfer=info".parse().unwrap())
        .add_directive("hickory_resolver::name_server=info".parse().unwrap())
        .add_directive("hickory_proto=info".parse().unwrap());
    let stdout_formatter = logfmt::layer();

    tracing_subscriber::registry()
        .with(stdout_formatter.with_filter(env_filter))
        .try_init()?;

    let args = Args::load();
    let config__ = init(args.clone()).await?;

    if let ServerMode::Controller = args.mode
        && args.interfaces.len() != 1
    {
        return Err(
            DhcpError::MultipleInterfacesProvidedOneSupported(args.interfaces.len()).into(),
        );
    }

    let mut join_handles = vec![];
    let dhcp_timestamps = Arc::new(Mutex::new(DhcpTimestamps::new(
        if let ServerMode::Dpu = args.mode {
            DhcpTimestampsFilePath::Hbn
        } else {
            DhcpTimestampsFilePath::NotSet
        },
    )));

    // Rate limiter limits the packet processing from all interfaces.
    let rate_limiter_ = Arc::new(tokio::sync::Semaphore::new(
        MAX_PARALLEL_PACKET_HANDLING_ALLOWED,
    ));

    // Create a new socket for each interface.
    // In case of Controller, there will be only 1 interface.
    for interface in args.interfaces {
        let config_ = config__.clone();
        let args_mode = args.mode.clone();
        let dhcp_timestamps_ = dhcp_timestamps.clone();
        let rate_limiter = rate_limiter_.clone();

        let handle = tokio::spawn(async move {
            let handler: Arc<Box<dyn DhcpMode>> = Arc::new(get_mode(&args_mode));
            let listen_address = SocketAddr::new(std::net::IpAddr::from([0, 0, 0, 0]), 67);

            let socket = get_socket(listen_address, interface.clone()).await;
            tracing::info!(
                "Listening on {:?} on interface: {}, mode: {:?}",
                listen_address,
                interface,
                handler
            );

            let mut server = Server {
                socket: Arc::new(socket),
            };

            // Machine cache is used only in Controller mode and Controller listens only on one
            // interface, so it is ok to initialize cache here.
            let machine_cache_ = Arc::new(Mutex::new(LruCache::new(
                std::num::NonZeroUsize::new(cache::MACHINE_CACHE_SIZE).unwrap(),
            )));

            // Listen on each interface and process it.
            loop {
                let mut buf = [0; 1500];
                let (len, addr) = match server.socket.recv_from(&mut buf).await {
                    Ok((len, addr)) => (len, addr),
                    Err(err) => {
                        // We don't know after this read is failed, will we be able to read again
                        // from this socket? Mostly no. In this case, recreate the socket.
                        // We observed this fluctuation during admin to tenant network switch.
                        tracing::error!("Socket recv failed with error: {err}");
                        // Try to close the existing socket.
                        drop(server.socket);
                        tracing::info!("Recreating the socket on {listen_address}, {interface}");
                        server.socket =
                            Arc::new(get_socket(listen_address, interface.clone()).await);
                        continue;
                    }
                };

                // We never close this semaphore, so if an error is returned it should be
                // TryAcquireError::NoPermits; Not checking explicitly.
                let Ok(permit) = rate_limiter.clone().try_acquire_owned() else {
                    // drop packet.
                    tracing::error!("Dropping packet because of rate limiting.");
                    continue;
                };

                // Not a valid packet.
                if len < MINIMUM_DHCP_PKT_SIZE {
                    tracing::error!("Dropping packet because it is smaller than min length.");
                    continue;
                }

                let config = config_.clone();
                let mut machine_cache = machine_cache_.clone();
                let iface = interface.clone();
                let handler_ = handler.clone();
                let dhcp_timestamps = dhcp_timestamps_.clone();
                let socket = server.socket.clone();

                tokio::spawn(async move {
                    process(
                        addr,
                        socket,
                        &buf,
                        config.clone(),
                        &**handler_,
                        &iface,
                        &mut machine_cache,
                        dhcp_timestamps,
                    )
                    .await;
                    drop(permit);
                });
            }
        });

        join_handles.push(handle);
    }

    let _ = futures::future::select_all(join_handles).await;

    Ok(())
}

fn get_mode(args_mode: &ServerMode) -> Box<dyn DhcpMode> {
    match args_mode {
        ServerMode::Dpu => Box::new(Dpu {}),
        ServerMode::Controller => Box::new(Controller {}),
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    dhcp_config: DhcpConfig,
    host_config: Option<HostConfig>, // Valid only for Dpu mode.
}

async fn init(args: Args) -> Result<Config, DhcpError> {
    let f = tokio::fs::read_to_string(args.dhcp_config).await?;
    let dhcp_config: DhcpConfig = serde_yaml::from_str(&f)?;

    let host_config;
    if let ServerMode::Dpu = args.mode {
        host_config = get_host_config(args.host_config).await?;
    } else {
        host_config = None;
    };

    Ok(Config {
        dhcp_config,
        host_config,
    })
}

#[derive(Debug)]
pub struct TestArm {}

#[async_trait]
impl DhcpMode for TestArm {
    async fn discover_dhcp(
        &self,
        _discovery_request: DhcpDiscovery,
        _config: &Config,
        _machine_cache: &mut Arc<Mutex<LruCache<String, CacheEntry>>>,
    ) -> Result<DhcpRecord, DhcpError> {
        Test::dhcp_record()
    }

    // Packets received from DPU to API must be relayed.
    fn should_be_relayed(&self) -> bool {
        true
    }
}

#[derive(Debug)]
pub struct Test {}

impl Test {
    pub fn dhcp_record() -> Result<DhcpRecord, DhcpError> {
        Ok(DhcpRecord {
            machine_id: Some(
                "fm100dsbiu5ckus880v8407u0mkcensa39cule26im5gnpvmuufckacguc0"
                    .parse()
                    .unwrap(),
            ),
            machine_interface_id: Some("0fd6e9a3-06fc-4a22-ad29-aca299677b00".parse().unwrap()),
            segment_id: Some("55a2d74e-f9e1-49d5-bf99-be05171a5d75".parse().unwrap()),
            subdomain_id: Some("56a2d74e-f9e1-49d5-bf99-be05171a5d75".parse().unwrap()),
            fqdn: "seventeen-connecticut.dev3.frg.nvidia.com".to_string(),
            mac_address: "b8:3f:d2:90:9a:12".to_string(),
            address: "10.217.132.204".to_string(),
            mtu: 6000,
            prefix: "10.217.132.192/26".to_string(),
            gateway: Some("10.217.132.193".to_string()),
            booturl: None,
            last_invalidation_time: None,
        })
    }
}

#[async_trait]
impl DhcpMode for Test {
    async fn discover_dhcp(
        &self,
        _discovery_request: DhcpDiscovery,
        _config: &Config,
        _machine_cache: &mut Arc<Mutex<LruCache<String, CacheEntry>>>,
    ) -> Result<DhcpRecord, DhcpError> {
        Test::dhcp_record()
    }

    fn should_be_relayed(&self) -> bool {
        false
    }
}

const MINIMUM_DHCP_PKT_SIZE: usize = 236;

#[tracing::instrument(skip_all)]
#[allow(clippy::too_many_arguments)]
async fn process(
    addr: SocketAddr,
    socket: Arc<UdpSocket>,
    buf: &[u8],
    config: Config,
    handler: &dyn DhcpMode,
    circuit_id: &str, // interface name
    machine_cache: &mut Arc<Mutex<LruCache<String, CacheEntry>>>,
    dhcp_timestamps: Arc<Mutex<DhcpTimestamps>>,
) {
    if !addr.is_ipv4() {
        tracing::error!("Dropping ivp6 packet.");
        return;
    }

    tracing::info!("Received packet [{}] from {}", buf[0], addr);

    let packet = match packet_handler::process_packet(
        buf,
        &config,
        circuit_id,
        handler,
        machine_cache,
    )
    .await
    {
        Ok(packet) => packet,
        Err(err) => {
            tracing::error!("Dropping packet because of error: {}", err);
            return;
        }
    };

    let dest_address = handler.get_destination_address(&packet);
    match packet.send(dest_address, socket).await {
        Ok(_) => {}
        Err(err) => {
            tracing::error!("Packet sending failed because of error: {}", err);
        }
    }

    // Tell forge-dpu-agent that an IP has been requested for this interface.
    if let Some(host_config) = config.host_config {
        let mut dhcp_timestamps = dhcp_timestamps.lock().await;
        dhcp_timestamps.add_timestamp(host_config.host_interface_id, Utc::now().to_rfc3339());
        if let Err(e) = dhcp_timestamps.write() {
            tracing::error!(
                "Failed writing to {}: {e}",
                DhcpTimestampsFilePath::Hbn.path_str()
            );
        }
    }
}

#[cfg(test)]
mod test {
    use std::env;
    use std::net::{Ipv4Addr, SocketAddrV4};
    use std::path::PathBuf;
    use std::str::FromStr;
    use std::sync::Arc;

    use chrono::{DateTime, Utc};
    use dhcproto::v4::{DhcpOption, Message, MessageType, OptionCode};
    use dhcproto::{Decodable, Decoder, Encodable};
    use lru::LruCache;
    use tokio::net::UdpSocket;
    use tokio::sync::Mutex;
    use utils::models::dhcp::{DhcpTimestamps, DhcpTimestampsFilePath};

    use crate::command_line::Args;
    use crate::errors::DhcpError;
    use crate::{DhcpMode, Test, TestArm, cache, init, packet_handler, process};

    fn get_test_args() -> Args {
        let base_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

        Args {
            interfaces: vec!["eth0".to_string()],
            dhcp_config: base_path.join("conf/conf.yaml").display().to_string(),
            host_config: Some(
                base_path
                    .join("test/host_config.yaml")
                    .display()
                    .to_string(),
            ),
            mode: crate::command_line::ServerMode::Dpu,
        }
    }

    #[tokio::test]
    async fn test_init() {
        init(get_test_args()).await.unwrap();
    }

    #[tokio::test]
    async fn test_arm_non_relayed_packet() {
        let byte_stream = get_byte_stream(Ipv4Addr::new(0, 0, 0, 0), None, MessageType::Request);
        let handler: Box<dyn DhcpMode> = Box::new(TestArm {});
        let config = init(get_test_args()).await.unwrap();
        let mut machine_cache = Arc::new(Mutex::new(LruCache::new(
            std::num::NonZeroUsize::new(cache::MACHINE_CACHE_SIZE).unwrap(),
        )));
        assert!(matches!(
            packet_handler::process_packet(
                &byte_stream,
                &config,
                "vlan200",
                &*handler,
                &mut machine_cache,
            )
            .await,
            Err(DhcpError::NonRelayedPacket(..))
        ));
    }

    #[tokio::test]
    async fn test_arm_relayed_packet() {
        let byte_stream = get_byte_stream(
            Ipv4Addr::new(0, 0, 0, 0),
            Some(Ipv4Addr::from_str("10.217.5.41").unwrap()),
            MessageType::Request,
        );
        let handler: Box<dyn DhcpMode> = Box::new(TestArm {});
        let config = init(get_test_args()).await.unwrap();
        let mut machine_cache = Arc::new(Mutex::new(LruCache::new(
            std::num::NonZeroUsize::new(cache::MACHINE_CACHE_SIZE).unwrap(),
        )));
        assert!(
            packet_handler::process_packet(
                &byte_stream,
                &config,
                "vlan200",
                &*handler,
                &mut machine_cache,
            )
            .await
            .is_ok()
        );
    }

    #[tokio::test]
    async fn test_complete_flow() {
        let byte_stream = get_byte_stream(
            Ipv4Addr::new(0, 0, 0, 0),
            Some(Ipv4Addr::from_str("10.217.5.41").unwrap()),
            MessageType::Request,
        );
        let handler: Box<dyn DhcpMode> = Box::new(Test {});
        let config = init(get_test_args()).await.unwrap();
        let mut machine_cache = Arc::new(Mutex::new(LruCache::new(
            std::num::NonZeroUsize::new(cache::MACHINE_CACHE_SIZE).unwrap(),
        )));
        let packet = packet_handler::process_packet(
            &byte_stream,
            &config,
            "vlan200",
            &*handler,
            &mut machine_cache,
        )
        .await
        .unwrap();

        assert_eq!(
            packet.dst_address(),
            SocketAddrV4::new(Ipv4Addr::from([0x0a, 0xd9, 0x05, 0x29]), 67)
        );
        let packet = Message::decode(&mut dhcproto::Decoder::new(packet.encoded_packet())).unwrap();

        assert_eq!(packet.yiaddr(), Ipv4Addr::from([10, 217, 132, 204]));
    }

    #[tokio::test]
    async fn test_complete_flow_with_valid_ciaddr() {
        let byte_stream = get_byte_stream(
            Ipv4Addr::new(10, 217, 132, 204),
            Some(Ipv4Addr::from_str("10.217.5.41").unwrap()),
            MessageType::Request,
        );
        let handler: Box<dyn DhcpMode> = Box::new(Test {});
        let config = init(get_test_args()).await.unwrap();
        let mut machine_cache = Arc::new(Mutex::new(LruCache::new(
            std::num::NonZeroUsize::new(cache::MACHINE_CACHE_SIZE).unwrap(),
        )));
        let packet = packet_handler::process_packet(
            &byte_stream,
            &config,
            "vlan200",
            &*handler,
            &mut machine_cache,
        )
        .await
        .unwrap();

        assert_eq!(
            packet.dst_address(),
            SocketAddrV4::new(Ipv4Addr::from([10, 217, 5, 41]), 67)
        );

        let packet = Message::decode(&mut dhcproto::Decoder::new(packet.encoded_packet())).unwrap();

        assert_eq!(packet.yiaddr(), Ipv4Addr::from([10, 217, 132, 204]));
    }

    #[tokio::test]
    async fn test_send_metadata_to_agent() {
        let byte_stream = get_byte_stream(Ipv4Addr::new(0, 0, 0, 0), None, MessageType::Discover);
        let handler: Box<dyn DhcpMode> = Box::new(Test {});
        let config = init(get_test_args()).await.unwrap();
        let mut machine_cache = Arc::new(Mutex::new(LruCache::new(
            std::num::NonZeroUsize::new(cache::MACHINE_CACHE_SIZE).unwrap(),
        )));

        let before_dhcp = Utc::now();
        let udp_socket_addr: SocketAddrV4 = "127.0.0.1:1236".parse().unwrap();
        let dhcp_timestamps = Arc::new(Mutex::new(DhcpTimestamps::new(
            DhcpTimestampsFilePath::Test,
        )));

        process(
            "1.2.3.4:0".parse().unwrap(),
            Arc::new(UdpSocket::bind(udp_socket_addr).await.unwrap()),
            &byte_stream,
            config.clone(),
            &*handler,
            "vlan100",
            &mut machine_cache,
            dhcp_timestamps.clone(),
        )
        .await;

        let dhcp_timestamps = dhcp_timestamps.lock().await;

        let timestamp = dhcp_timestamps
            .get_timestamp(&config.host_config.as_ref().unwrap().host_interface_id)
            .unwrap();

        let dhcp_time: DateTime<Utc> = timestamp.parse().unwrap();
        assert!(before_dhcp < dhcp_time);

        let mut dhcp_timestamps_new = DhcpTimestamps::new(DhcpTimestampsFilePath::Test);
        dhcp_timestamps_new.read().unwrap();
        let file_timestamp: DateTime<Utc> = dhcp_timestamps_new
            .get_timestamp(&config.host_config.unwrap().host_interface_id)
            .unwrap()
            .parse()
            .unwrap();

        assert!(before_dhcp < file_timestamp)
    }

    #[tokio::test]
    async fn validate_test_host_config() {
        let config = init(get_test_args()).await.unwrap();

        let host_config = config.host_config.unwrap();
        assert_eq!(host_config.host_ip_addresses.len(), 2);
        assert!(host_config.host_ip_addresses["vlan200"].booturl.is_none());
    }

    fn get_byte_stream(
        ciaddr: Ipv4Addr,
        giaddr: Option<Ipv4Addr>,
        message_type: MessageType,
    ) -> Vec<u8> {
        let mut msg = Message::new(
            ciaddr,
            Ipv4Addr::new(0, 0, 0, 0),
            Ipv4Addr::new(0, 0, 0, 0),
            Ipv4Addr::new(0, 0, 0, 0),
            &[00, 0x1b, 0x63, 0x84, 0x45, 0xe6],
        );

        if let Some(giaddr) = giaddr {
            msg.set_giaddr(giaddr);
        }

        msg.opts_mut().insert(DhcpOption::MessageType(message_type));

        let mut encoded_packet = Vec::new();
        let mut e = dhcproto::Encoder::new(&mut encoded_packet);
        msg.encode(&mut e).unwrap();
        encoded_packet
    }

    #[tokio::test]
    async fn validate_basic_ack() {
        let packet = get_byte_stream(Ipv4Addr::new(0, 0, 0, 0), None, MessageType::Request);

        let config = init(get_test_args()).await.unwrap();
        let handler: Box<dyn DhcpMode> = Box::new(Test {});
        let mut machine_cache = Arc::new(Mutex::new(LruCache::new(
            std::num::NonZeroUsize::new(cache::MACHINE_CACHE_SIZE).unwrap(),
        )));

        let encoded_packet = packet_handler::process_packet(
            &packet,
            &config,
            "vlan200",
            &*handler,
            &mut machine_cache,
        )
        .await
        .unwrap();

        let packet = Message::decode(&mut Decoder::new(encoded_packet.encoded_packet())).unwrap();
        assert_eq!(
            packet.opts().get(OptionCode::MessageType).unwrap().clone(),
            DhcpOption::MessageType(MessageType::Ack)
        );
    }

    #[tokio::test]
    async fn validate_nak() {
        let packet = get_byte_stream(Ipv4Addr::new(10, 0, 0, 1), None, MessageType::Request);

        let config = init(get_test_args()).await.unwrap();
        let handler: Box<dyn DhcpMode> = Box::new(Test {});
        let mut machine_cache = Arc::new(Mutex::new(LruCache::new(
            std::num::NonZeroUsize::new(cache::MACHINE_CACHE_SIZE).unwrap(),
        )));

        let encoded_packet = packet_handler::process_packet(
            &packet,
            &config,
            "vlan200",
            &*handler,
            &mut machine_cache,
        )
        .await
        .unwrap();

        let packet = Message::decode(&mut Decoder::new(encoded_packet.encoded_packet())).unwrap();
        assert_eq!(
            packet.opts().get(OptionCode::MessageType).unwrap().clone(),
            DhcpOption::MessageType(MessageType::Nak)
        );
    }
}
