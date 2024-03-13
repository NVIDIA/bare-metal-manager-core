/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use std::{
    net::{Ipv4Addr, SocketAddrV4},
    str::FromStr,
    sync::Arc,
};

use dhcproto::{
    v4::{
        relay::{RelayAgentInformation, RelayCode, RelayInfo},
        Decodable, Decoder, DhcpOption, Message, MessageType, OptionCode,
    },
    Encodable, Encoder,
};
use ipnetwork::IpNetwork;
use lru::LruCache;
use rpc::forge::{DhcpDiscovery, DhcpRecord};
use tokio::net::UdpSocket;

use crate::{
    cache::CacheEntry, errors::DhcpError, util, vendor_class::VendorClass, Config, DhcpMode,
};

const PKT_TYPE_OP_REQUEST: u8 = 1;

pub struct DecodedPacket {
    packet: Message,
}

trait DecodedPacketTrait<T> {
    fn get_option_val(
        &self,
        option: OptionCode,
        relay_code: Option<RelayCode>,
    ) -> Result<T, DhcpError>;
}

impl DecodedPacketTrait<String> for DecodedPacket {
    fn get_option_val(
        &self,
        option: OptionCode,
        relay_code: Option<RelayCode>,
    ) -> Result<String, DhcpError> {
        if let Some(value) = self.packet.opts().get(option) {
            match value {
                DhcpOption::ClassIdentifier(x) => Ok(std::str::from_utf8(x)?.to_string()),
                DhcpOption::RelayAgentInformation(agent_info) => {
                    let relay_code = relay_code.unwrap(); // This can not be None
                    let Some(val) = agent_info.get(relay_code) else {
                        return Err(DhcpError::MissingRelayCode(relay_code));
                    };

                    match val {
                        RelayInfo::LinkSelection(ip) => Ok(ip.to_string()),
                        RelayInfo::AgentCircuitId(x) | RelayInfo::AgentRemoteId(x) => {
                            Ok(util::u8_to_hex_string(x)?)
                        }
                        _ => Err(DhcpError::GenericError("Unknown relay option.".to_string())),
                    }
                }
                _ => Err(DhcpError::GenericError(format!(
                    "option is not matched, got: {:?}.",
                    value
                ))),
            }
        } else {
            Err(DhcpError::MissingOption(option))
        }
    }
}

impl DecodedPacketTrait<MessageType> for DecodedPacket {
    fn get_option_val(
        &self,
        option: OptionCode,
        _relay_code: Option<RelayCode>,
    ) -> Result<MessageType, DhcpError> {
        if let Some(value) = self.packet.opts().get(option) {
            match value {
                DhcpOption::MessageType(x) => Ok(*x),
                _ => Err(DhcpError::GenericError(format!(
                    "Message type is not matched, got: {:?}.",
                    value,
                ))),
            }
        } else {
            Err(DhcpError::MissingOption(option))
        }
    }
}

impl DecodedPacketTrait<Option<Ipv4Addr>> for DecodedPacket {
    fn get_option_val(
        &self,
        option: OptionCode,
        _relay_code: Option<RelayCode>,
    ) -> Result<Option<Ipv4Addr>, DhcpError> {
        match self.packet.opts().get(option) {
            Some(value) => {
                if let DhcpOption::ServerIdentifier(x) = value {
                    Ok(Some(*x))
                } else {
                    Ok(None)
                }
            }
            None => Ok(None),
        }
    }
}

impl DecodedPacket {
    fn is_relayed(&self) -> Result<(), DhcpError> {
        // get gi address
        let giaddress = self.packet.giaddr();
        if giaddress.is_broadcast() || giaddress == Ipv4Addr::new(0, 0, 0, 0) {
            return Err(DhcpError::NonRelayedPacket(giaddress));
        }
        Ok(())
    }

    fn is_this_for_us(&self, config: &Config) -> Result<(), DhcpError> {
        if let Some(val) = self.get_option_val(OptionCode::ServerIdentifier, None)? {
            if val == config.dhcp_config.carbide_dhcp_server {
                return Ok(());
            }
            return Err(DhcpError::NotMyPacket(val.to_string()));
        }

        // No identifier sent by client. It can be for us
        Ok(())
    }

    fn get_vendor_string(&self) -> Option<String> {
        self.get_option_val(OptionCode::ClassIdentifier, None).ok()
    }

    fn get_link_select(&self) -> Option<String> {
        self.get_option_val(
            OptionCode::RelayAgentInformation,
            Some(RelayCode::LinkSelection),
        )
        .ok()
    }

    pub fn get_circuit_id(&self) -> Option<String> {
        self.get_option_val(
            OptionCode::RelayAgentInformation,
            Some(RelayCode::AgentCircuitId),
        )
        .ok()
    }

    pub fn get_remote_id(&self) -> Option<String> {
        self.get_option_val(
            OptionCode::RelayAgentInformation,
            Some(RelayCode::AgentRemoteId),
        )
        .ok()
    }

    fn get_discovery_request(&self, handler: &dyn DhcpMode, circuit_id: &str) -> DhcpDiscovery {
        DhcpDiscovery {
            mac_address: util::u8_to_mac(self.packet.chaddr()),
            relay_address: self.packet.giaddr().to_string(),
            vendor_string: self.get_vendor_string(),
            link_address: self.get_link_select(),
            circuit_id: handler.get_circuit_id(self, circuit_id),
            remote_id: self.get_remote_id(),
        }
    }

    /// Relay/Gateway IP is used as destination ip.
    /// Only exception is if ciaddr is not empty. If it is not empty means client already has a IP
    /// and listening on it.
    fn decide_dst_ip(&self, _message_type: MessageType) -> (Ipv4Addr, u16) {
        // Relayed packet.
        if self.packet.giaddr() != Ipv4Addr::from([0, 0, 0, 0]) {
            return (self.packet.giaddr(), 67); // Relayed packet. Relay listen on 67
        }

        // Client unicast packet. Lease renewal case.
        if self.packet.ciaddr() != Ipv4Addr::from([0, 0, 0, 0]) {
            return (self.packet.ciaddr(), 68); // Client is listening on port 68
        }

        // We don't know who sent this packet. Broadcast it back.
        (Ipv4Addr::from([255, 255, 255, 255]), 68)
    }
}

pub struct Packet {
    encoded_packet: Vec<u8>,
    pub dst_address: Ipv4Addr,
    pub dst_port: u16,
}

impl Packet {
    #[cfg(test)]
    pub fn encoded_packet(&self) -> &Vec<u8> {
        &self.encoded_packet
    }
    pub fn dst_address(&self) -> SocketAddrV4 {
        SocketAddrV4::new(self.dst_address, self.dst_port)
    }
}

impl Packet {
    pub async fn send(
        &self,
        dst_address: SocketAddrV4,
        socket: Arc<UdpSocket>,
    ) -> Result<(), String> {
        tracing::info!("Sending packet to {:?}", dst_address);
        socket
            .send_to(&self.encoded_packet, dst_address)
            .await
            .map_err(|x| x.to_string())?;

        Ok(())
    }
}

pub async fn process_packet(
    buf: &[u8],
    config: &Config,
    circuit_id: &str,
    handler: &dyn DhcpMode,
    machine_cache: &mut LruCache<String, CacheEntry>,
) -> Result<Packet, DhcpError> {
    if buf[0] != PKT_TYPE_OP_REQUEST {
        // Not valid packet. Drop it.
        return Err(DhcpError::UnknownPacket(buf[0]));
    }

    let packet = Message::decode(&mut Decoder::new(buf))?;
    tracing::info!(packet.received=%packet, "Received Packet");
    let decoded_packet = DecodedPacket { packet };

    if handler.should_be_relayed() {
        decoded_packet.is_relayed()?;
    }
    decoded_packet.is_this_for_us(config)?;

    let msg_type = decoded_packet.get_option_val(OptionCode::MessageType, None)?;
    let dhcp_response = handler
        .discover_dhcp(
            decoded_packet.get_discovery_request(handler, circuit_id),
            config,
            machine_cache,
        )
        .await?;

    let (dst_address, dst_port) = decoded_packet.decide_dst_ip(msg_type);

    let packet = create_dhcp_reply_packet(&decoded_packet, dhcp_response, config, msg_type)?;
    tracing::info!(packet.send=%packet, "Sending Packet");

    let mut encoded_packet = Vec::new();
    let mut e = Encoder::new(&mut encoded_packet);
    packet.encode(&mut e)?;

    Ok(Packet {
        encoded_packet,
        dst_address,
        dst_port,
    })
}

fn create_dhcp_reply_packet(
    src: &DecodedPacket,
    forge_response: DhcpRecord,
    config: &Config,
    dhcp_msg_type: MessageType,
) -> Result<Message, DhcpError> {
    let relay_address = forge_response
        .gateway
        .clone()
        .map(|x| {
            x.parse::<Ipv4Addr>()
                .unwrap_or_else(|_| Ipv4Addr::from([0, 0, 0, 0]))
        })
        .unwrap_or(config.dhcp_config.carbide_dhcp_server);

    let reply_message_type = match dhcp_msg_type {
        MessageType::Discover => MessageType::Offer,
        MessageType::Request => MessageType::Ack,
        MessageType::Decline => {
            return Err(DhcpError::DhcpDeclineMessage(
                src.packet.ciaddr().to_string(),
                src.packet
                    .chaddr()
                    .iter()
                    .map(|x| format!("{:x}", x))
                    .collect::<Vec<String>>()
                    .join(":"),
            ));
        }
        _ => {
            return Err(DhcpError::UnhandledMessageType(dhcp_msg_type));
        }
    };

    let parse = forge_response.prefix.parse::<IpNetwork>();
    let (prefix, broadcast) = match parse {
        Ok(prefix) => match prefix {
            IpNetwork::V4(prefix) => (prefix.mask(), prefix.broadcast()),
            IpNetwork::V6(prefix) => {
                return Err(DhcpError::GenericError(format!(
                    "Prefix ({}) is an IPv6 network, which is not supported.",
                    prefix
                )));
            }
        },
        Err(error) => {
            return Err(DhcpError::GenericError(format!(
                "prefix value in deserialized protobuf is not an IP Network: {0}",
                error
            )));
        }
    };

    let vendor_string = src.get_vendor_string();

    let vendor_class = if let Some(vendor_string) = vendor_string {
        Some(VendorClass::from_str(vendor_string.as_str()).map_err(|e| {
            DhcpError::VendorClassParseError(format!("Vendor string parse failed: {:?}", e))
        })?)
    } else {
        None
    };

    // https://www.ietf.org/rfc/rfc2131.txt
    let mut msg = Message::default();
    msg.set_opcode(dhcproto::v4::Opcode::BootReply)
        .set_htype(dhcproto::v4::HType::Eth)
        .set_hops(0x0)
        .set_xid(src.packet.xid())
        .set_secs(0)
        .set_flags(src.packet.flags())
        .set_ciaddr(src.packet.ciaddr())
        .set_yiaddr(Ipv4Addr::from_str(&forge_response.address)?)
        .set_siaddr(config.dhcp_config.carbide_provisioning_server_ipv4)
        .set_giaddr(src.packet.giaddr())
        .set_chaddr(src.packet.chaddr());

    msg.opts_mut()
        .insert(DhcpOption::MessageType(reply_message_type));
    msg.opts_mut().insert(DhcpOption::SubnetMask(prefix));
    msg.opts_mut()
        .insert(DhcpOption::Router(vec![relay_address]));
    msg.opts_mut().insert(DhcpOption::NameServer(
        config.dhcp_config.carbide_nameservers.clone(),
    ));
    msg.opts_mut().insert(DhcpOption::DomainNameServer(
        config.dhcp_config.carbide_nameservers.clone(),
    ));
    msg.opts_mut()
        .insert(DhcpOption::DomainName(forge_response.fqdn.clone()));
    msg.opts_mut()
        .insert(DhcpOption::Hostname(forge_response.fqdn.clone()));

    // // I guess we don't need Client_FQDN. Option12, Hostname seems sufficient.
    // let mut client_fqdn = ClientFQDN::new(
    //     FqdnFlags::new(0x0e),
    //     Name::from_str(&forge_response.fqdn.clone())
    //         .map_err(|x| DhcpError::GenericError(x.to_string()))?,
    // );
    // client_fqdn.set_r1(0);
    // client_fqdn.set_r2(0);
    // msg.opts_mut().insert(DhcpOption::ClientFQDN(client_fqdn));

    msg.opts_mut().insert(DhcpOption::BroadcastAddr(broadcast));
    msg.opts_mut().insert(DhcpOption::AddressLeaseTime(
        config.dhcp_config.lease_time_secs,
    ));
    msg.opts_mut().insert(DhcpOption::ServerIdentifier(
        config.dhcp_config.carbide_dhcp_server,
    ));
    msg.opts_mut()
        .insert(DhcpOption::Renewal(config.dhcp_config.renewal_time_secs));
    msg.opts_mut().insert(DhcpOption::Rebinding(
        config.dhcp_config.rebinding_time_secs,
    ));

    let mut client_identifier: Vec<u8> = vec![1]; // ethernet
    src.packet
        .chaddr()
        .iter()
        .for_each(|x| client_identifier.push(*x));
    msg.opts_mut()
        .insert(DhcpOption::ClientIdentifier(client_identifier));

    if let Some(ntp_server) = config.dhcp_config.carbide_ntpserver {
        msg.opts_mut()
            .insert(DhcpOption::NtpServers(vec![ntp_server]));
    }

    if let Some(vendor_class) = vendor_class {
        msg.opts_mut().insert(DhcpOption::ClassIdentifier(
            vendor_class.id.as_bytes().to_vec(),
        ));

        if vendor_class.is_netboot() {
            msg.opts_mut()
                .insert(DhcpOption::BootfileName(util::machine_get_filename(
                    &forge_response,
                    &vendor_class,
                    config,
                )));
        }
    }

    let mut relay_agent = RelayAgentInformation::default();
    let circuit_id = src.get_circuit_id();
    if let Some(circuit_id) = circuit_id {
        relay_agent.insert(RelayInfo::AgentCircuitId(circuit_id.as_bytes().to_vec()));
    }

    let remote_id = src.get_remote_id();
    if let Some(remote_id) = remote_id {
        relay_agent.insert(RelayInfo::AgentRemoteId(remote_id.as_bytes().to_vec()));
    }

    let link_select = src.get_link_select();

    if let Some(link_select) = link_select {
        relay_agent.insert(RelayInfo::LinkSelection(Ipv4Addr::from_str(
            link_select.as_str(),
        )?));
    }

    if !relay_agent.is_empty() {
        let agent_options = DhcpOption::RelayAgentInformation(relay_agent);
        msg.opts_mut().insert(agent_options);
    }

    let mut vendor_option: Vec<u8> = vec![6, 4, 0, 0, 0, 8, 70];
    let mut machine_id = forge_response
        .machine_interface_id
        .map(|x| x.value.clone())
        .unwrap_or_default()
        .as_bytes()
        .to_vec();

    vendor_option.push(machine_id.len() as u8);
    vendor_option.append(&mut machine_id);

    msg.opts_mut()
        .insert(DhcpOption::VendorExtensions(vendor_option));

    Ok(msg)
}
