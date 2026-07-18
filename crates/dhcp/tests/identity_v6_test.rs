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
use std::net::UdpSocket;
use std::time::Duration;

use dhcp::mock_api_server::{self, ENDPOINT_DISCOVER_DHCP};
use dhcproto::v6;
use rpc::forge as rpc;

mod common;

use common::{DHCPv6Factory, Kea6, v6_drop_metric_value, wait_for_v6_drop_metric_at_least};

const READ_TIMEOUT: Duration = Duration::from_millis(500);
const LOG_TIMEOUT: Duration = Duration::from_secs(2);
const METRIC_TIMEOUT: Duration = Duration::from_secs(5);
const DUID_MAX_LEN: usize = 128;

fn send_and_recv(socket: &UdpSocket, packet: Vec<u8>) -> Option<v6::Message> {
    socket.send(&packet).unwrap();
    let mut buf = [0u8; 1500];
    let n = socket.recv(&mut buf).ok()?;
    Some(DHCPv6Factory::decode_reply(&buf[..n]).unwrap())
}

struct Harness {
    _rt: tokio::runtime::Runtime,
    api_server: mock_api_server::MockAPIServer,
    _kea: Kea6,
    socket: UdpSocket,
}

impl Harness {
    fn new() -> Self {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let api_server = rt.block_on(mock_api_server::MockAPIServer::start());
        let (_kea, socket) = Kea6::start(api_server.local_http_addr(), None).unwrap();
        socket.set_read_timeout(Some(READ_TIMEOUT)).unwrap();

        Harness {
            _rt: rt,
            api_server,
            _kea,
            socket,
        }
    }

    fn last_discovery(&self) -> rpc::DhcpDiscovery {
        self.api_server.discoveries().last().unwrap().clone()
    }

    fn wait_for_log(&self, needle: &str) -> bool {
        self._kea.wait_for_log(needle, LOG_TIMEOUT)
    }

    fn wait_for_drop_metric(&self, reason: &str) -> bool {
        wait_for_v6_drop_metric_at_least(self._kea.metrics_endpoint(), reason, 1.0, METRIC_TIMEOUT)
    }

    /// Return the current DHCPv6 dropped-request counter value for a reason label.
    fn drop_metric_value(&self, reason: &str) -> f64 {
        v6_drop_metric_value(self._kea.metrics_endpoint(), reason)
    }

    /// Wait until the DHCPv6 dropped-request counter reaches the expected value.
    fn wait_for_drop_metric_at_least(&self, reason: &str, minimum: f64) -> bool {
        wait_for_v6_drop_metric_at_least(
            self._kea.metrics_endpoint(),
            reason,
            minimum,
            METRIC_TIMEOUT,
        )
    }
}

#[test]
fn duid_llt_selects_embedded_link_layer_mac() -> Result<(), eyre::Report> {
    let idx = 0x50;
    let h = Harness::new();

    // DUID-LLT skips the timestamp and selects the embedded Ethernet MAC.
    let response = send_and_recv(
        &h.socket,
        DHCPv6Factory::solicit_with_duid(idx, DHCPv6Factory::duid_llt(idx), false),
    )
    .expect("kea did not respond to DUID-LLT SOLICIT");
    assert_eq!(response.msg_type(), v6::MessageType::Advertise);
    assert_eq!(
        h.last_discovery().mac_address,
        DHCPv6Factory::mac_string(idx)
    );
    assert_eq!(
        h.last_discovery().message_kind,
        Some(rpc::MessageKind::V6Solicit as i32)
    );

    Ok(())
}

#[test]
fn non_mac_duid_without_relay_option79_is_dropped() -> Result<(), eyre::Report> {
    let h = Harness::new();

    // A valid UUID DUID still needs relay-supplied option 79 to choose a MAC row.
    assert!(
        send_and_recv(
            &h.socket,
            DHCPv6Factory::solicit_with_duid(0x51, DHCPv6Factory::duid_uuid(0x51), false),
        )
        .is_none()
    );
    assert_eq!(h.api_server.calls_for(ENDPOINT_DISCOVER_DHCP), 0);
    assert!(h.wait_for_log("no_mac_no_option79"));
    assert!(h.wait_for_log("relay 2001:db8::1 with non-MAC DUID and no RFC 6939 option 79"));
    assert!(h.wait_for_drop_metric("no_mac_no_option79"));

    Ok(())
}

#[test]
fn client_supplied_option79_is_not_trusted() -> Result<(), eyre::Report> {
    let h = Harness::new();

    // Inner option 79 is client-controlled and must not satisfy identity selection.
    assert!(
        send_and_recv(
            &h.socket,
            DHCPv6Factory::solicit_with_inner_option79(0x52, DHCPv6Factory::duid_uuid(0x52)),
        )
        .is_none()
    );
    assert_eq!(h.api_server.calls_for(ENDPOINT_DISCOVER_DHCP), 0);
    assert!(h.wait_for_log("no_mac_no_option79"));
    assert!(h.wait_for_drop_metric("no_mac_no_option79"));

    Ok(())
}

#[test]
fn relay_option79_selects_mac_for_valid_non_mac_duid() -> Result<(), eyre::Report> {
    let idx = 0x53;
    let h = Harness::new();

    // Relay option 79 supplies the sending link-layer MAC for UUID DUIDs.
    let response = send_and_recv(
        &h.socket,
        DHCPv6Factory::solicit_with_duid(idx, DHCPv6Factory::duid_uuid(idx), true),
    )
    .expect("kea did not respond to relay-option79 SOLICIT");
    assert_eq!(response.msg_type(), v6::MessageType::Advertise);
    assert_eq!(
        h.last_discovery().mac_address,
        DHCPv6Factory::mac_string(idx)
    );

    Ok(())
}

#[test]
fn relay_option79_wins_when_duid_mac_disagrees() -> Result<(), eyre::Report> {
    let relay_idx = 0x54;
    let duid_idx = 0x55;
    let h = Harness::new();

    // Relay option 79 is the sending link and intentionally wins over DUID MAC.
    let response = send_and_recv(
        &h.socket,
        DHCPv6Factory::solicit_with_duid(relay_idx, DHCPv6Factory::duid_ll(duid_idx), true),
    )
    .expect("kea did not respond to disagreeing DUID/option79 SOLICIT");
    assert_eq!(response.msg_type(), v6::MessageType::Advertise);
    assert_eq!(
        h.last_discovery().mac_address,
        DHCPv6Factory::mac_string(relay_idx)
    );
    assert!(h.wait_for_log("option 79 MAC"));
    assert!(h.wait_for_log("disagrees with DUID MAC"));

    Ok(())
}

#[test]
fn malformed_duid_is_dropped_before_api_call() -> Result<(), eyre::Report> {
    let h = Harness::new();

    // Malformed DUIDs are unsupported even if relay option 79 is present.
    assert!(
        send_and_recv(
            &h.socket,
            DHCPv6Factory::solicit_with_duid(0x56, DHCPv6Factory::truncated_duid_uuid(), true),
        )
        .is_none()
    );
    assert_eq!(h.api_server.calls_for(ENDPOINT_DISCOVER_DHCP), 0);
    assert!(h.wait_for_log("unsupported_duid"));
    assert!(h.wait_for_log("malformed or unsupported DUID"));
    assert!(h.wait_for_drop_metric("unsupported_duid"));

    Ok(())
}

#[test]
fn duid_en_length_boundary_is_enforced_before_api_call() -> Result<(), eyre::Report> {
    let accepted_idx = 0x57;
    let rejected_idx = 0x58;
    let h = Harness::new();

    // A max-length DUID-EN is valid only when relay option 79 supplies the MAC.
    let response = send_and_recv(
        &h.socket,
        DHCPv6Factory::solicit_with_duid(accepted_idx, DHCPv6Factory::duid_en(DUID_MAX_LEN), true),
    )
    .expect("kea did not respond to max-length DUID-EN SOLICIT");
    assert_eq!(response.msg_type(), v6::MessageType::Advertise);
    assert_eq!(
        h.last_discovery().mac_address,
        DHCPv6Factory::mac_string(accepted_idx)
    );
    assert_eq!(
        h.last_discovery().duid.as_ref().map(Vec::len),
        Some(DUID_MAX_LEN)
    );
    let discover_calls = h.api_server.calls_for(ENDPOINT_DISCOVER_DHCP);

    // One byte over Kea's DUID cap is malformed even with relay option 79.
    assert!(
        send_and_recv(
            &h.socket,
            DHCPv6Factory::solicit_with_duid(
                rejected_idx,
                DHCPv6Factory::duid_en(DUID_MAX_LEN + 1),
                true,
            ),
        )
        .is_none()
    );
    assert_eq!(
        h.api_server.calls_for(ENDPOINT_DISCOVER_DHCP),
        discover_calls
    );
    assert!(h.wait_for_log("unsupported_duid"));
    assert!(h.wait_for_drop_metric("unsupported_duid"));

    Ok(())
}

#[test]
fn unsupported_ia_shapes_are_dropped_before_api_call() -> Result<(), eyre::Report> {
    let h = Harness::new();
    let mut expected_drops = h.drop_metric_value("unsupported_message");

    // Unsupported IA-only and IA-less stateful packets must not reach the API.
    for packet in [
        DHCPv6Factory::solicit_with_ia_ta(0x59),
        DHCPv6Factory::solicit_with_ia_pd(0x5a),
        DHCPv6Factory::request_without_ia_na(0x5b),
    ] {
        assert!(send_and_recv(&h.socket, packet).is_none());
        expected_drops += 1.0;
        assert!(h.wait_for_drop_metric_at_least("unsupported_message", expected_drops));
    }
    assert_eq!(h.api_server.calls_for(ENDPOINT_DISCOVER_DHCP), 0);

    Ok(())
}

#[test]
fn mixed_ia_na_and_unsupported_ia_is_dropped_before_api_call() -> Result<(), eyre::Report> {
    let h = Harness::new();
    let mut expected_drops = h.drop_metric_value("unsupported_message");

    // Mixed or multiple IA containers are ambiguous for one API allocation.
    for packet in [
        DHCPv6Factory::solicit_with_ia_na_and_ia_ta(0x5c),
        DHCPv6Factory::solicit_with_ia_na_and_ia_pd(0x5d),
        DHCPv6Factory::solicit_with_multiple_ia_na(0x5e),
    ] {
        assert!(send_and_recv(&h.socket, packet).is_none());
        expected_drops += 1.0;
        assert!(h.wait_for_drop_metric_at_least("unsupported_message", expected_drops));
    }
    assert_eq!(h.api_server.calls_for(ENDPOINT_DISCOVER_DHCP), 0);

    Ok(())
}
