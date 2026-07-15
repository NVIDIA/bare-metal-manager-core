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
//! DHCPv6 decode and identity selection for the Kea hook.
//!
//! This module is intentionally not a general DHCPv6 implementation. Kea still
//! owns the DHCP state machine and `dhcproto` decodes normal client messages;
//! the local raw parsing is limited to the hook boundary where we must recover
//! one-hop relay metadata, enforce relay trust rules, and select the client
//! identity before calling the Carbide API. Kea may provide that relay metadata
//! as a side-channel after unwrapping the packet, or leave it in the raw wire
//! bytes, so this module handles both shapes with the same policy.

use std::ffi::CString;
use std::net::Ipv6Addr;

use dhcproto::v6::{DhcpOption, Message, MessageType, OptionCode};
use dhcproto::{Decodable, Decoder};
use mac_address::MacAddress;
use rpc::forge as rpc;

const DHCPV6_RELAY_FORW: u8 = 12;
const DHCPV6_RELAY_REPL: u8 = 13;
const DUID_LLT: u16 = 1;
const DUID_EN: u16 = 2;
const DUID_LL: u16 = 3;
const DUID_UUID: u16 = 4;
const HTYPE_ETHERNET: u16 = 1;
const ETHERNET_MAC_LEN: usize = 6;
const DUID_EN_MIN_LEN: usize = 7;
const DUID_MAX_LEN: usize = 128;
const DUID_UUID_LEN: usize = 18;

/// Supplemental relay metadata from Kea when it has already unwrapped the relay envelope.
#[derive(Debug, Default, Clone)]
pub struct RelayContext {
    pub relay_count: usize,
    pub hop_count: u8,
    pub link_address: Option<Ipv6Addr>,
    pub interface_id: Option<Vec<u8>>,
    pub remote_id: Option<Vec<u8>>,
    pub client_link_layer: Option<Vec<u8>>,
}

/// DHCPv6 discovery data selected by the hook before calling Carbide.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V6Discovery {
    pub selected_mac: MacAddress,
    pub duid_mac: Option<MacAddress>,
    pub duid: Vec<u8>,
    pub message_type: MessageType,
    pub relay_link: Option<Ipv6Addr>,
    pub vendor_class: Option<String>,
    pub interface_id: Option<Vec<u8>>,
    pub remote_id: Option<Vec<u8>>,
    pub desired_addr: Option<Ipv6Addr>,
    pub ia_addrs: Vec<Ipv6Addr>,
    pub has_ia_na: bool,
    pub client_link_layer: Option<MacAddress>,
}

/// Reasons a DHCPv6 packet cannot be decoded or served by this hook.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum V6DecodeError {
    MalformedPacket,
    NestedRelay,
    RelayHopCountExceeded(u8),
    MissingDuid,
    NoMacNoOption79,
    UnsupportedDuid,
    UnsupportedMessage(MessageType),
}

/// Result of parsing a DUID for a link-layer identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DuidMac {
    Mac(MacAddress),
    NoLinkLayerMac,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DuidError {
    Malformed,
    UnsupportedType,
}

#[derive(Debug)]
struct RawOption<'a> {
    code: u16,
    data: &'a [u8],
}

/// Decode a DHCPv6 packet without any Kea-provided relay fallback metadata.
#[cfg(test)]
pub fn decode(packet: &[u8]) -> Result<V6Discovery, V6DecodeError> {
    decode_with_relay_context(packet, &RelayContext::default())
}

/// Decode a DHCPv6 packet and select the client identity for the Carbide API call.
pub fn decode_with_relay_context(
    packet: &[u8],
    relay_context: &RelayContext,
) -> Result<V6Discovery, V6DecodeError> {
    if relay_context.relay_count > 1 {
        return Err(V6DecodeError::NestedRelay);
    }

    let decoded = match packet.first().copied() {
        Some(DHCPV6_RELAY_FORW) => decode_relay_forward(packet)?,
        Some(DHCPV6_RELAY_REPL) => {
            return Err(V6DecodeError::UnsupportedMessage(MessageType::RelayRepl));
        }
        Some(_) => decode_direct(packet, relay_context)?,
        None => return Err(V6DecodeError::MalformedPacket),
    };

    select_identity(decoded)
}

/// Extract an Ethernet MAC from a DUID-LL or DUID-LLT byte string.
pub fn extract_mac_from_duid(duid: &[u8]) -> Result<DuidMac, DuidError> {
    // Kea caps DUIDs at RFC 8415's 128-byte maximum.
    if duid.len() < 2 || duid.len() > DUID_MAX_LEN {
        return Err(DuidError::Malformed);
    }

    let duid_type = u16::from_be_bytes([duid[0], duid[1]]);
    match duid_type {
        DUID_LLT => parse_link_layer_duid(&duid[2..], 4),
        DUID_LL => parse_link_layer_duid(&duid[2..], 0),
        DUID_EN if duid.len() >= DUID_EN_MIN_LEN => Ok(DuidMac::NoLinkLayerMac),
        DUID_UUID if duid.len() == DUID_UUID_LEN => Ok(DuidMac::NoLinkLayerMac),
        DUID_EN | DUID_UUID => Err(DuidError::Malformed),
        _ => Err(DuidError::UnsupportedType),
    }
}

/// Parse RFC 6939 option 79 and return an Ethernet MAC when it carries one.
pub fn extract_mac_from_option79(payload: &[u8]) -> Option<MacAddress> {
    if payload.len() != 2 + ETHERNET_MAC_LEN {
        return None;
    }

    let htype = u16::from_be_bytes([payload[0], payload[1]]);
    (htype == HTYPE_ETHERNET).then(|| {
        MacAddress::new([
            payload[2], payload[3], payload[4], payload[5], payload[6], payload[7],
        ])
    })
}

/// Return a newly allocated MAC string extracted from a DHCPv6 DUID.
///
/// # Safety
/// `duid_ptr` must be null only when `duid_len` is 0, or point to readable memory of that length.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn carbide_mac_from_duid(
    duid_ptr: *const u8,
    duid_len: usize,
) -> *mut libc::c_char {
    if duid_ptr.is_null() || duid_len == 0 {
        return std::ptr::null_mut();
    }

    let duid = unsafe { std::slice::from_raw_parts(duid_ptr, duid_len) };
    match extract_mac_from_duid(duid) {
        Ok(DuidMac::Mac(mac)) => CString::new(mac.to_string())
            .map(CString::into_raw)
            .unwrap_or_else(|_| std::ptr::null_mut()),
        Ok(DuidMac::NoLinkLayerMac) | Err(_) => std::ptr::null_mut(),
    }
}

/// Free a MAC string returned by `carbide_mac_from_duid`.
///
/// # Safety
/// `mac` must have been returned by this crate and not freed before.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn carbide_free_mac_string(mac: *mut libc::c_char) {
    if mac.is_null() {
        return;
    }

    unsafe {
        drop(CString::from_raw(mac));
    }
}

/// Parse the link-layer payload portion shared by DUID-LL and DUID-LLT.
fn parse_link_layer_duid(bytes: &[u8], payload_offset: usize) -> Result<DuidMac, DuidError> {
    if bytes.len() < 2 + payload_offset + ETHERNET_MAC_LEN {
        return Err(DuidError::Malformed);
    }

    let htype = u16::from_be_bytes([bytes[0], bytes[1]]);
    if htype != HTYPE_ETHERNET {
        return Err(DuidError::UnsupportedType);
    }

    let mac = &bytes[2 + payload_offset..];
    if mac.len() != ETHERNET_MAC_LEN {
        return Err(DuidError::Malformed);
    }

    Ok(DuidMac::Mac(MacAddress::new([
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
    ])))
}

#[derive(Debug)]
struct DecodedV6 {
    message: Message,
    relay_link: Option<Ipv6Addr>,
    interface_id: Option<Vec<u8>>,
    remote_id: Option<Vec<u8>>,
    client_link_layer: Option<Vec<u8>>,
}

/// Decode a client packet while preserving Kea-provided relay metadata.
fn decode_direct(packet: &[u8], relay_context: &RelayContext) -> Result<DecodedV6, V6DecodeError> {
    if relay_context.hop_count > 1 {
        return Err(V6DecodeError::RelayHopCountExceeded(
            relay_context.hop_count,
        ));
    }

    // Kea may have stripped the relay envelope already; keep its relay fields
    // only as fallback metadata and let the packet body drive message parsing.
    let message =
        Message::decode(&mut Decoder::new(packet)).map_err(|_| V6DecodeError::MalformedPacket)?;
    Ok(DecodedV6 {
        message,
        relay_link: relay_context.link_address,
        interface_id: relay_context.interface_id.clone(),
        remote_id: relay_context.remote_id.clone(),
        client_link_layer: relay_context.client_link_layer.clone(),
    })
}

/// Decode one relay-forward envelope and its direct client message.
///
/// `dhcproto` handles the inner client message, but relay envelopes need a
/// narrow raw-TLV pass here. In `dhcproto 0.15`, option 9 is modeled as another
/// `RelayMessage`; for our authoritative path it normally carries a direct
/// client message, and nested relay is intentionally rejected by policy.
fn decode_relay_forward(packet: &[u8]) -> Result<DecodedV6, V6DecodeError> {
    if packet.len() < 34 {
        return Err(V6DecodeError::MalformedPacket);
    }
    let hop_count = packet[1];
    if hop_count > 1 {
        return Err(V6DecodeError::RelayHopCountExceeded(hop_count));
    }

    let link_address = Ipv6Addr::from(
        <[u8; 16]>::try_from(&packet[2..18]).map_err(|_| V6DecodeError::MalformedPacket)?,
    );
    let options = parse_raw_options(&packet[34..])?;
    let relay_messages = options
        .iter()
        .filter(|option| option.code == u16::from(OptionCode::RelayMsg))
        .map(|option| option.data)
        .collect::<Vec<_>>();
    // Kea keeps only one decoded Relay Message for later processing. Reject
    // duplicates so identity selection cannot observe a different client.
    let relay_message = match relay_messages.as_slice() {
        [relay_message] => *relay_message,
        _ => return Err(V6DecodeError::MalformedPacket),
    };

    // Nested relay is deliberately unsupported because segment selection would
    // otherwise need a clear policy for which relay link-address wins.
    if matches!(
        relay_message.first().copied(),
        Some(DHCPV6_RELAY_FORW) | Some(DHCPV6_RELAY_REPL)
    ) {
        return Err(V6DecodeError::NestedRelay);
    }

    let message = Message::decode(&mut Decoder::new(relay_message))
        .map_err(|_| V6DecodeError::MalformedPacket)?;
    Ok(DecodedV6 {
        message,
        relay_link: Some(link_address),
        interface_id: raw_option_bytes(&options, OptionCode::InterfaceId),
        remote_id: raw_option_bytes(&options, OptionCode::RemoteId),
        client_link_layer: raw_option_bytes(&options, OptionCode::ClientLinklayerAddr),
    })
}

/// Select the MAC identity and transport fields sent to the Carbide API.
fn select_identity(decoded: DecodedV6) -> Result<V6Discovery, V6DecodeError> {
    let duid = match decoded.message.opts().get(OptionCode::ClientId) {
        Some(DhcpOption::ClientId(duid)) if !duid.is_empty() => duid.clone(),
        _ => return Err(V6DecodeError::MissingDuid),
    };

    let duid_mac = match extract_mac_from_duid(&duid) {
        Ok(DuidMac::Mac(mac)) => Some(mac),
        Ok(DuidMac::NoLinkLayerMac) => None,
        Err(_) => return Err(V6DecodeError::UnsupportedDuid),
    };
    let client_link_layer = decoded
        .client_link_layer
        .as_deref()
        .and_then(extract_mac_from_option79);

    let selected_mac = match (client_link_layer, duid_mac) {
        // RFC 6939 identifies the sending link, so it wins over a DUID MAC.
        (Some(client_mac), Some(duid_mac)) => {
            if client_mac != duid_mac {
                log::warn!(
                    "DHCPv6 option 79 MAC disagrees with DUID MAC client_mac={client_mac} duid_mac={duid_mac}"
                );
            }
            client_mac
        }
        (Some(client_mac), None) => client_mac,
        (None, Some(duid_mac)) => duid_mac,
        (None, None) => return Err(V6DecodeError::NoMacNoOption79),
    };

    let options = decoded.message.opts();
    let ia_na_count = ia_na_count(options);
    let has_ia_na = ia_na_count > 0;
    let has_unsupported_ia =
        options.get(OptionCode::IATA).is_some() || options.get(OptionCode::IAPD).is_some();
    let ia_addrs = ia_addrs(options);
    let desired_addr = ia_addrs.first().copied();
    let vendor_class = vendor_class(options);
    let message_type = decoded.message.msg_type();
    let lease_end_message = matches!(message_type, MessageType::Release | MessageType::Decline);
    let api_bound_message = message_kind_for(message_type, has_ia_na).is_some();

    // IA_TA, IA_PD, and multiple IA_NA/address containers cannot be mapped to
    // the single-address Carbide API allocation contract.
    if api_bound_message && (has_unsupported_ia || ia_na_count > 1 || ia_addrs.len() > 1) {
        return Err(V6DecodeError::UnsupportedMessage(message_type));
    }

    // Lease-end and CONFIRM are handled locally; all API-bound request-like
    // messages must map to a supported wire contract first.
    if !api_bound_message && !matches!(message_type, MessageType::Confirm) && !lease_end_message {
        return Err(V6DecodeError::UnsupportedMessage(message_type));
    }

    Ok(V6Discovery {
        selected_mac,
        duid_mac,
        duid,
        message_type,
        relay_link: decoded.relay_link,
        vendor_class,
        interface_id: decoded.interface_id,
        remote_id: decoded.remote_id,
        desired_addr,
        ia_addrs,
        has_ia_na,
        client_link_layer,
    })
}

/// Map DHCPv6 transport message type to the existing Carbide API message kind.
pub fn message_kind_for(message_type: MessageType, has_ia_na: bool) -> Option<rpc::MessageKind> {
    match message_type {
        // Stateless SOLICIT is an information-only observation; stateful
        // SOLICIT starts address allocation.
        MessageType::Solicit if has_ia_na => Some(rpc::MessageKind::V6Solicit),
        MessageType::Solicit => Some(rpc::MessageKind::V6InfoRequest),
        MessageType::InformationRequest => Some(rpc::MessageKind::V6InfoRequest),
        // The API only needs one request-like value today: REQUEST, RENEW, and
        // REBIND with IA_NA all ask Carbide for the same authoritative
        // persisted lease, while Kea keeps the DHCP exchange-state differences.
        MessageType::Request | MessageType::Renew | MessageType::Rebind if has_ia_na => {
            Some(rpc::MessageKind::V6Request)
        }
        _ => None,
    }
}

/// Count IA_NA containers supplied by the client.
fn ia_na_count(options: &dhcproto::v6::DhcpOptions) -> usize {
    options
        .get_all(OptionCode::IANA)
        .into_iter()
        .flatten()
        .filter(|option| matches!(option, DhcpOption::IANA(_)))
        .count()
}

/// Return the requested IA_NA addresses supplied by the client.
fn ia_addrs(options: &dhcproto::v6::DhcpOptions) -> Vec<Ipv6Addr> {
    options
        .get_all(OptionCode::IANA)
        .into_iter()
        .flatten()
        .flat_map(|option| match option {
            DhcpOption::IANA(ia_na) => ia_na
                .opts
                .iter()
                .filter_map(|option| match option {
                    DhcpOption::IAAddr(addr) => Some(addr.addr),
                    _ => None,
                })
                .collect::<Vec<_>>(),
            _ => Vec::new(),
        })
        .collect()
}

/// Extract the first vendor-class string that is valid UTF-8.
fn vendor_class(options: &dhcproto::v6::DhcpOptions) -> Option<String> {
    match options.get(OptionCode::VendorClass) {
        Some(DhcpOption::VendorClass(vendor)) => vendor
            .data
            .iter()
            .find_map(|value| String::from_utf8(value.clone()).ok()),
        _ => None,
    }
}

/// Parse raw DHCPv6 option TLVs from a relay envelope.
fn parse_raw_options(mut bytes: &[u8]) -> Result<Vec<RawOption<'_>>, V6DecodeError> {
    let mut options = Vec::new();
    while !bytes.is_empty() {
        if bytes.len() < 4 {
            return Err(V6DecodeError::MalformedPacket);
        }

        let code = u16::from_be_bytes([bytes[0], bytes[1]]);
        let len = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
        bytes = &bytes[4..];
        if bytes.len() < len {
            return Err(V6DecodeError::MalformedPacket);
        }

        let (data, rest) = bytes.split_at(len);
        options.push(RawOption { code, data });
        bytes = rest;
    }

    Ok(options)
}

/// Return an owned copy of one raw relay option payload.
fn raw_option_bytes(options: &[RawOption<'_>], code: OptionCode) -> Option<Vec<u8>> {
    options
        .iter()
        .find(|option| option.code == u16::from(code))
        .map(|option| option.data.to_vec())
}

#[cfg(test)]
mod tests {
    use dhcproto::v6::{DhcpOption, IAAddr, IANA, IAPD, IATA, UnknownOption};
    use dhcproto::{Encodable, Encoder};

    use super::*;

    const DUID_LL: &[u8] = &[0, 3, 0, 1, 2, 0, 0, 0, 0, 1];
    const DUID_LLT: &[u8] = &[0, 1, 0, 1, 1, 2, 3, 4, 2, 0, 0, 0, 0, 1];
    const DUID_UUID: &[u8] = &[0, 4, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    const OPTION79: &[u8] = &[0, 1, 2, 0xaa, 0xbb, 0xcc, 0xdd, 0xee];

    /// Build a DUID-EN identity with the requested total byte length.
    fn duid_en(len: usize) -> Vec<u8> {
        // Type 2 plus enterprise-number form the minimum DUID-EN prefix.
        let mut duid = vec![0, 2, 0, 0, 0, 1];
        duid.resize(len, 0xaa);
        duid
    }

    fn encode_message(message: Message) -> Vec<u8> {
        let mut out = Vec::new();
        message.encode(&mut Encoder::new(&mut out)).unwrap();
        out
    }

    fn client_message(message_type: MessageType, has_ia_na: bool, duid: &[u8]) -> Message {
        let mut message = Message::new_with_id(message_type, [0xaa, 0xbb, 0xcc]);
        message
            .opts_mut()
            .insert(DhcpOption::ClientId(duid.to_vec()));
        if has_ia_na {
            let mut ia_na = IANA {
                id: 1,
                t1: 0,
                t2: 0,
                opts: Default::default(),
            };
            ia_na.opts.insert(DhcpOption::IAAddr(IAAddr {
                addr: "2001:db8::42".parse().unwrap(),
                preferred_life: 300,
                valid_life: 600,
                opts: Default::default(),
            }));
            message.opts_mut().insert(DhcpOption::IANA(ia_na));
        }
        message
    }

    fn option(code: OptionCode, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&u16::from(code).to_be_bytes());
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    fn relay_forward(inner: &[u8], hop_count: u8) -> Vec<u8> {
        let mut out = vec![12, hop_count];
        out.extend_from_slice(&Ipv6Addr::from(0x20010db8000000000000000000000001u128).octets());
        out.extend_from_slice(&Ipv6Addr::from(0xfe800000000000000000000000000001u128).octets());
        out.extend_from_slice(&option(OptionCode::InterfaceId, b"eth0"));
        out.extend_from_slice(&option(OptionCode::RemoteId, b"rack-a"));
        out.extend_from_slice(&option(OptionCode::ClientLinklayerAddr, OPTION79));
        out.extend_from_slice(&option(OptionCode::RelayMsg, inner));
        out
    }

    /// Build a Relay-Forward carrying two option-9 Relay Message payloads.
    fn relay_forward_with_duplicate_relay_message(first: &[u8], second: &[u8]) -> Vec<u8> {
        let mut out = vec![12, 0];
        out.extend_from_slice(&Ipv6Addr::from(0x20010db8000000000000000000000001u128).octets());
        out.extend_from_slice(&Ipv6Addr::from(0xfe800000000000000000000000000001u128).octets());
        out.extend_from_slice(&option(OptionCode::InterfaceId, b"eth0"));
        out.extend_from_slice(&option(OptionCode::RemoteId, b"rack-a"));
        out.extend_from_slice(&option(OptionCode::RelayMsg, first));
        out.extend_from_slice(&option(OptionCode::RelayMsg, second));
        out
    }

    #[test]
    fn extracts_mac_from_supported_duid_types() {
        // DUID-LL and DUID-LLT carry the Ethernet MAC in different offsets.
        assert_eq!(
            extract_mac_from_duid(DUID_LL).unwrap(),
            DuidMac::Mac("02:00:00:00:00:01".parse().unwrap())
        );
        assert_eq!(
            extract_mac_from_duid(DUID_LLT).unwrap(),
            DuidMac::Mac("02:00:00:00:00:01".parse().unwrap())
        );
    }

    #[test]
    fn classifies_duids_without_ethernet_mac() {
        // Enterprise and UUID DUIDs are valid DHCPv6 identities, but do not
        // contain the sending link MAC unless a relay supplies option 79.
        assert_eq!(
            extract_mac_from_duid(&[0, 2, 0, 0, 0, 1, 0xaa]).unwrap(),
            DuidMac::NoLinkLayerMac
        );
        assert_eq!(
            extract_mac_from_duid(&duid_en(DUID_MAX_LEN)).unwrap(),
            DuidMac::NoLinkLayerMac
        );
        assert_eq!(
            extract_mac_from_duid(DUID_UUID).unwrap(),
            DuidMac::NoLinkLayerMac
        );
    }

    #[test]
    fn rejects_malformed_duids() {
        // Truncated and unknown DUID forms cannot safely identify the client.
        assert_eq!(extract_mac_from_duid(&[0]), Err(DuidError::Malformed));
        assert_eq!(
            extract_mac_from_duid(&[0, 2, 0, 0, 0, 1]),
            Err(DuidError::Malformed)
        );
        assert_eq!(
            extract_mac_from_duid(&[0, 4, 0, 1, 2, 3]),
            Err(DuidError::Malformed)
        );
        assert_eq!(
            extract_mac_from_duid(&duid_en(DUID_MAX_LEN + 1)),
            Err(DuidError::Malformed)
        );
        assert_eq!(
            extract_mac_from_duid(&[0, 99, 0, 1, 2, 3]),
            Err(DuidError::UnsupportedType)
        );
        assert_eq!(
            extract_mac_from_duid(&[0, 3, 0, 32, 2, 0, 0, 0, 0, 1]),
            Err(DuidError::UnsupportedType)
        );
    }

    #[test]
    fn parses_option79_ethernet_mac() {
        // Option 79 is decoded as Unknown by dhcproto, so we hand-parse the
        // link-layer type and address payload here.
        assert_eq!(
            extract_mac_from_option79(OPTION79),
            Some("02:aa:bb:cc:dd:ee".parse().unwrap())
        );
        assert_eq!(extract_mac_from_option79(&[0, 2, 1, 2, 3, 4, 5, 6]), None);
    }

    #[test]
    fn decodes_direct_stateful_solicit() {
        // Stateful SOLICIT carries IA_NA and maps to the v6 allocation path.
        let packet = encode_message(client_message(MessageType::Solicit, true, DUID_LL));
        let decoded = decode(&packet).unwrap();

        assert_eq!(decoded.selected_mac, "02:00:00:00:00:01".parse().unwrap());
        assert_eq!(decoded.desired_addr, Some("2001:db8::42".parse().unwrap()));
        assert_eq!(
            message_kind_for(decoded.message_type, decoded.has_ia_na),
            Some(rpc::MessageKind::V6Solicit)
        );
    }

    #[test]
    fn decodes_relay_forward_with_option79_precedence() {
        // A one-hop relay supplies segment metadata and option 79; option 79
        // wins over the MAC embedded in DUID-LL/LLT.
        let inner = encode_message(client_message(MessageType::Solicit, true, DUID_LL));
        let decoded = decode(&relay_forward(&inner, 1)).unwrap();

        assert_eq!(decoded.selected_mac, "02:aa:bb:cc:dd:ee".parse().unwrap());
        assert_eq!(
            decoded.client_link_layer,
            Some("02:aa:bb:cc:dd:ee".parse().unwrap())
        );
        assert_eq!(decoded.relay_link, Some("2001:db8::1".parse().unwrap()));
        assert_eq!(decoded.interface_id, Some(b"eth0".to_vec()));
        assert_eq!(decoded.remote_id, Some(b"rack-a".to_vec()));
    }

    #[test]
    fn accepts_unwrapped_packet_with_kea_relay_context() {
        // Kea may pass an already-unwrapped client message in data_; in that
        // case relay metadata comes from the side-channel context.
        let packet = encode_message(client_message(
            MessageType::InformationRequest,
            false,
            DUID_LL,
        ));
        let decoded = decode_with_relay_context(
            &packet,
            &RelayContext {
                relay_count: 1,
                hop_count: 1,
                link_address: Some("2001:db8::10".parse().unwrap()),
                interface_id: Some(b"swp1".to_vec()),
                remote_id: None,
                client_link_layer: None,
            },
        )
        .unwrap();

        assert_eq!(decoded.relay_link, Some("2001:db8::10".parse().unwrap()));
        assert_eq!(decoded.interface_id, Some(b"swp1".to_vec()));
        assert_eq!(
            message_kind_for(decoded.message_type, decoded.has_ia_na),
            Some(rpc::MessageKind::V6InfoRequest)
        );
    }

    #[test]
    fn drops_non_mac_duid_without_option79() {
        // A DUID-UUID cannot be joined to the v4 MAC row unless option 79
        // supplies the sending link-layer address.
        let packet = encode_message(client_message(MessageType::Solicit, true, DUID_UUID));

        assert_eq!(decode(&packet), Err(V6DecodeError::NoMacNoOption79));
    }

    #[test]
    fn ignores_client_supplied_option79_for_non_mac_duid() {
        // Option 79 is only trusted when it comes from relay metadata; a
        // client-supplied inner option must not choose the Carbide MAC row.
        let mut message = client_message(MessageType::Solicit, true, DUID_UUID);
        message
            .opts_mut()
            .insert(DhcpOption::Unknown(UnknownOption::new(
                OptionCode::ClientLinklayerAddr,
                OPTION79.to_vec(),
            )));

        assert_eq!(
            decode(&encode_message(message)),
            Err(V6DecodeError::NoMacNoOption79)
        );
    }

    #[test]
    fn accepts_non_mac_duid_with_relay_option79() {
        // Relay-supplied option 79 identifies the sending link for valid
        // non-MAC DUIDs.
        let inner = encode_message(client_message(MessageType::Solicit, true, DUID_UUID));

        assert_eq!(
            decode(&relay_forward(&inner, 1)).unwrap().selected_mac,
            "02:aa:bb:cc:dd:ee".parse().unwrap()
        );
    }

    #[test]
    fn drops_malformed_duid_even_with_relay_option79() {
        // Relay option 79 only helps valid non-MAC DUIDs; malformed or
        // unhandled DUID forms are unsupported before MAC selection.
        let truncated = encode_message(client_message(
            MessageType::Solicit,
            true,
            &[0, 4, 0, 1, 2, 3],
        ));
        let non_ethernet = encode_message(client_message(
            MessageType::Solicit,
            true,
            &[0, 3, 0, 32, 2, 0, 0, 0, 0, 1],
        ));

        assert_eq!(
            decode(&relay_forward(&truncated, 1)),
            Err(V6DecodeError::UnsupportedDuid)
        );
        assert_eq!(
            decode(&relay_forward(&non_ethernet, 1)),
            Err(V6DecodeError::UnsupportedDuid)
        );
    }

    #[test]
    fn rejects_unsupported_ia_shapes_before_api_classification() {
        // IA_TA and IA_PD are non-goals and must not be downgraded to
        // information-only or stateful API discovery.
        let mut solicit_ia_ta = client_message(MessageType::Solicit, false, DUID_LL);
        solicit_ia_ta.opts_mut().insert(DhcpOption::IATA(IATA {
            id: 1,
            opts: Default::default(),
        }));
        let mut solicit_ia_pd = client_message(MessageType::Solicit, false, DUID_LL);
        solicit_ia_pd.opts_mut().insert(DhcpOption::IAPD(IAPD {
            id: 1,
            t1: 0,
            t2: 0,
            opts: Default::default(),
        }));

        assert_eq!(
            decode(&encode_message(solicit_ia_ta)),
            Err(V6DecodeError::UnsupportedMessage(MessageType::Solicit))
        );
        assert_eq!(
            decode(&encode_message(solicit_ia_pd)),
            Err(V6DecodeError::UnsupportedMessage(MessageType::Solicit))
        );
    }

    #[test]
    fn rejects_supported_ia_na_when_unsupported_ia_is_also_present() {
        // The API can return only one address for one supported IA_NA flow, so
        // mixed unsupported IA containers are rejected before lease override.
        let mut solicit_ia_ta = client_message(MessageType::Solicit, true, DUID_LL);
        solicit_ia_ta.opts_mut().insert(DhcpOption::IATA(IATA {
            id: 1,
            opts: Default::default(),
        }));
        let mut request_ia_pd = client_message(MessageType::Request, true, DUID_LL);
        request_ia_pd.opts_mut().insert(DhcpOption::IAPD(IAPD {
            id: 1,
            t1: 0,
            t2: 0,
            opts: Default::default(),
        }));

        assert_eq!(
            decode(&encode_message(solicit_ia_ta)),
            Err(V6DecodeError::UnsupportedMessage(MessageType::Solicit))
        );
        assert_eq!(
            decode(&encode_message(request_ia_pd)),
            Err(V6DecodeError::UnsupportedMessage(MessageType::Request))
        );
    }

    #[test]
    fn rejects_ambiguous_ia_na_address_selection() {
        // The current API contract has one desired address and one returned
        // address, so multiple IA_NA containers or IAADDR hints are ambiguous.
        let mut second_ia_na = IANA {
            id: 2,
            t1: 0,
            t2: 0,
            opts: Default::default(),
        };
        second_ia_na.opts.insert(DhcpOption::IAAddr(IAAddr {
            addr: "2001:db8::43".parse().unwrap(),
            preferred_life: 300,
            valid_life: 600,
            opts: Default::default(),
        }));
        let mut multiple_ia_na = client_message(MessageType::Solicit, true, DUID_LL);
        multiple_ia_na
            .opts_mut()
            .insert(DhcpOption::IANA(second_ia_na));

        let mut multiple_iaaddr = client_message(MessageType::Solicit, true, DUID_LL);
        if let Some(DhcpOption::IANA(ia_na)) = multiple_iaaddr.opts_mut().get_mut(OptionCode::IANA)
        {
            ia_na.opts.insert(DhcpOption::IAAddr(IAAddr {
                addr: "2001:db8::43".parse().unwrap(),
                preferred_life: 300,
                valid_life: 600,
                opts: Default::default(),
            }));
        }

        assert_eq!(
            decode(&encode_message(multiple_ia_na)),
            Err(V6DecodeError::UnsupportedMessage(MessageType::Solicit))
        );
        assert_eq!(
            decode(&encode_message(multiple_iaaddr)),
            Err(V6DecodeError::UnsupportedMessage(MessageType::Solicit))
        );
    }

    #[test]
    fn accepts_lease_end_messages_with_unsupported_ia_for_kea_handling() {
        // RELEASE and DECLINE are Kea protocol paths; Carbide validates
        // identity and lets Kea handle them without API discovery.
        let mut release = client_message(MessageType::Release, true, DUID_LL);
        release.opts_mut().insert(DhcpOption::IATA(IATA {
            id: 1,
            opts: Default::default(),
        }));
        let mut decline = client_message(MessageType::Decline, true, DUID_LL);
        decline.opts_mut().insert(DhcpOption::IAPD(IAPD {
            id: 1,
            t1: 0,
            t2: 0,
            opts: Default::default(),
        }));

        assert_eq!(
            decode(&encode_message(release)).unwrap().message_type,
            MessageType::Release
        );
        assert_eq!(
            decode(&encode_message(decline)).unwrap().message_type,
            MessageType::Decline
        );
    }

    #[test]
    fn rejects_request_like_messages_without_ia_na() {
        // REQUEST, RENEW, and REBIND are stateful paths; without IA_NA there
        // is no supported lease request to send to the API.
        for message_type in [
            MessageType::Request,
            MessageType::Renew,
            MessageType::Rebind,
        ] {
            assert_eq!(
                decode(&encode_message(client_message(
                    message_type,
                    false,
                    DUID_LL
                ))),
                Err(V6DecodeError::UnsupportedMessage(message_type))
            );
        }
    }

    #[test]
    fn drops_oversized_duid_en_even_with_relay_option79() {
        // Relay option 79 may supply the MAC, but the DUID still has to fit
        // Kea and RFC 8415 length limits.
        let inner = encode_message(client_message(
            MessageType::Solicit,
            true,
            &duid_en(DUID_MAX_LEN + 1),
        ));

        assert_eq!(
            decode(&relay_forward(&inner, 1)),
            Err(V6DecodeError::UnsupportedDuid)
        );
    }

    #[test]
    fn rejects_nested_or_multi_hop_relay() {
        // Multi-hop relay handling needs an explicit segment precedence rule,
        // so this milestone rejects it instead of serving silently.
        let inner = encode_message(client_message(MessageType::Solicit, true, DUID_LL));
        let nested = relay_forward(&relay_forward(&inner, 1), 1);

        assert_eq!(
            decode(&relay_forward(&inner, 2)),
            Err(V6DecodeError::RelayHopCountExceeded(2))
        );
        assert_eq!(decode(&nested), Err(V6DecodeError::NestedRelay));
    }

    #[test]
    fn rejects_duplicate_relay_message_options() {
        // Multiple option-9 payloads can make Rust and Kea inspect different
        // inner clients, so reject before choosing an identity.
        let first = encode_message(client_message(MessageType::Solicit, true, DUID_LL));
        let second = encode_message(client_message(MessageType::Solicit, true, DUID_LLT));

        assert_eq!(
            decode(&relay_forward_with_duplicate_relay_message(&first, &second)),
            Err(V6DecodeError::MalformedPacket)
        );
    }
}
