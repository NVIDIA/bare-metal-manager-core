/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use std::net::Ipv4Addr;

use dhcproto::v4::relay::RelayInfo;
use dhcproto::v4::{Message, relay};
use dhcproto::{Encodable, Encoder, v4};

pub const RELAY_IP: &str = "127.1.2.3";

pub struct DHCPFactory {}

impl DHCPFactory {
    pub fn encode(msg: Message) -> Result<Vec<u8>, eyre::Report> {
        let mut buf = Vec::with_capacity(300); // msg is 279 bytes
        let mut e = Encoder::new(&mut buf);
        msg.encode(&mut e)?;
        Ok(buf)
    }

    // Make and encode a relayed DHCP_DISCOVER packet
    // The idx is used as the last byte of the MAC and Link addresses to make them unique.
    pub fn discover(idx: u8) -> Message {
        // 0x02 prefix is a 'locally administered address'
        let mac = vec![0x02, 0x00, 0x00, 0x00, 0x00, idx];

        // Five colon separated fields. Our parser (vendor_class.rs) only uses fields 0 and 2.
        // 7 is MachineArchitecture::EfiX64, HTTP version
        let uefi_vendor_class = b"HTTPClient::7::".to_vec();

        let mut relay_agent = relay::RelayAgentInformation::default();
        relay_agent.insert(RelayInfo::AgentCircuitId(b"eth0".to_vec()));
        let link_address = [172, 16, 42, idx];
        relay_agent.insert(RelayInfo::LinkSelection(link_address.into()));

        let gateway_ip = RELAY_IP.parse::<Ipv4Addr>().unwrap();

        let mut msg = v4::Message::default();
        let opts = msg
            .set_chaddr(&mac)
            .set_giaddr(gateway_ip) // This says message was relayed
            .set_hops(1) // a real relayed packet would have this. not necessary for the test.
            .opts_mut();
        use v4::DhcpOption::*;
        opts.insert(ClassIdentifier(uefi_vendor_class)); // 60
        opts.insert(RelayAgentInformation(relay_agent)); // 82
        opts.insert(ClientSystemArchitecture(v4::Architecture::Intelx86PC)); // 93
        opts.insert(MessageType(v4::MessageType::Discover));

        msg
    }
}
