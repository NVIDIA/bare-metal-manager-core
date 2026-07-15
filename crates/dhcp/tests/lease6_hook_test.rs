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
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::{Ipv6Addr, UdpSocket};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use dhcp::mock_api_server::{self, ENDPOINT_DISCOVER_DHCP, ENDPOINT_EXPIRE_DHCP_LEASE};
use dhcproto::v6::{self, DhcpOption, OptionCode, Status};
use rpc::forge as rpc;

mod common;

use common::{
    DHCPv6Factory, Kea6, Kea6Config, Kea6ExpiredLeasesProcessing, assert_api_v6_domain_search,
    assert_hook_v6_dns_servers, assert_hook_v6_ntp_servers, v6_drop_metric_value,
    wait_for_v6_drop_metric_at_least,
};

const READ_TIMEOUT: Duration = Duration::from_millis(500);
const MEMFILE_TIMEOUT: Duration = Duration::from_secs(2);
const EXPIRE_TIMEOUT: Duration = Duration::from_secs(15);
const METRIC_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone)]
struct Lease6Entry {
    address: Ipv6Addr,
    duid: String,
    valid_lifetime: u32,
    lease_type: u32,
    hwaddr: String,
    state: u32,
}

impl Lease6Entry {
    fn is_active_na_for(&self, address: Ipv6Addr, duid_hex: &str) -> bool {
        self.address == address
            && self.valid_lifetime > 0
            && self.lease_type == 0
            && self.state == 0
            && normalize_hex(&self.duid) == normalize_hex(duid_hex)
    }
}

fn normalize_hex(value: &str) -> String {
    value
        .chars()
        .filter(|ch| ch.is_ascii_hexdigit())
        .map(|ch| ch.to_ascii_lowercase())
        .collect()
}

fn same_mac_text(actual: &str, expected: &str) -> bool {
    actual.eq_ignore_ascii_case(expected)
}

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
    _lease_dir: tempfile::TempDir,
    lease_file_path: PathBuf,
}

impl Harness {
    fn new() -> Self {
        Self::new_with_config(Kea6Config::default())
    }

    fn new_with_config(config: Kea6Config) -> Self {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let api_server = rt.block_on(mock_api_server::MockAPIServer::start());
        let lease_dir = tempfile::tempdir().unwrap();
        let lease_file_path = lease_dir.path().join("kea-leases6.csv");

        let (kea, socket) =
            Kea6::start_with_config(api_server.local_http_addr(), Some(&lease_file_path), config)
                .unwrap();
        socket.set_read_timeout(Some(READ_TIMEOUT)).unwrap();

        Harness {
            _rt: rt,
            api_server,
            _kea: kea,
            socket,
            _lease_dir: lease_dir,
            lease_file_path,
        }
    }

    /// Read Kea's append-only lease journal as current lease state.
    fn read_leases(&self) -> Vec<Lease6Entry> {
        let Ok(file) = File::open(&self.lease_file_path) else {
            return Vec::new();
        };

        let mut current_by_address = BTreeMap::new();
        for lease in BufReader::new(file)
            .lines()
            .map_while(Result::ok)
            .filter_map(|line| {
                let columns = line.split(',').collect::<Vec<_>>();
                if columns.len() < 14 {
                    return None;
                }

                Some(Lease6Entry {
                    address: columns[0].parse().ok()?,
                    duid: columns[1].to_string(),
                    valid_lifetime: columns[2].parse().ok()?,
                    lease_type: columns[6].parse().ok()?,
                    hwaddr: columns[12].to_string(),
                    state: columns[13].parse().ok()?,
                })
            })
        {
            current_by_address.insert(lease.address, lease);
        }

        current_by_address
            .into_values()
            .filter(|lease| lease.valid_lifetime > 0)
            .collect()
    }

    fn active_leases(&self, address: Ipv6Addr, duid_hex: &str) -> Vec<Lease6Entry> {
        self.read_leases()
            .into_iter()
            .filter(|lease| lease.is_active_na_for(address, duid_hex))
            .collect()
    }

    fn wait_for_active_lease(&self, address: Ipv6Addr, duid_hex: &str) -> Option<Lease6Entry> {
        let deadline = Instant::now() + MEMFILE_TIMEOUT;
        loop {
            let leases = self.active_leases(address, duid_hex);
            assert!(
                leases.len() <= 1,
                "expected at most one active Kea lease for {address}/{duid_hex}, found {leases:?}"
            );
            if let Some(lease) = leases.into_iter().next() {
                return Some(lease);
            }
            if Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Assert that a lease-end message did not call discovery or expiry APIs.
    fn assert_no_lease_end_api_calls(&self, discover_calls: usize, context: &str) {
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(
            self.api_server.calls_for(ENDPOINT_DISCOVER_DHCP),
            discover_calls,
            "{context}: lease-end message should not call API discovery"
        );
        assert_eq!(
            self.api_server.calls_for(ENDPOINT_EXPIRE_DHCP_LEASE),
            0,
            "{context}"
        );
        assert!(
            self.api_server.expired_leases().is_empty(),
            "{context}: mock API recorded expiry payloads"
        );
    }

    /// Wait for one scoped expiry RPC and reject unsafe address-only expiry for the same IP.
    fn wait_for_scoped_expire_rpc(&self, address: Ipv6Addr, mac_address: &str) -> bool {
        let deadline = Instant::now() + EXPIRE_TIMEOUT;
        loop {
            let expired = self.api_server.expired_leases();
            assert!(
                expired
                    .iter()
                    .all(|request| request.ip_address == address.to_string()
                        && request
                            .mac_address
                            .as_deref()
                            .is_some_and(|actual| same_mac_text(actual, mac_address))),
                "lease6_expire sent an unexpected expiry RPC while waiting for {address}: {expired:?}"
            );
            if expired.len() == 1 {
                return true;
            }
            assert!(
                expired.len() <= 1,
                "lease6_expire sent duplicate expiry RPCs for {address}: {expired:?}"
            );
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

/// Assert that the Kea-to-API path preserved the Relay-Forward metadata.
fn assert_v6_discovery_metadata(
    h: &Harness,
    discovery_index: usize,
    idx: u8,
    expected_kind: rpc::MessageKind,
) {
    let discoveries = h.api_server.discoveries();
    let discovery = discoveries
        .get(discovery_index)
        .unwrap_or_else(|| panic!("missing DHCPv6 discovery #{discovery_index}: {discoveries:?}"));
    let expected_duid = DHCPv6Factory::duid_ll(idx);

    // The relay link-address is the API routing key for relayed DHCPv6.
    assert_eq!(discovery.relay_address, DHCPv6Factory::RELAY_LINK_ADDR);
    assert_eq!(
        discovery.link_address.as_deref(),
        Some(DHCPv6Factory::RELAY_LINK_ADDR)
    );

    // Opaque relay identifiers are hex-encoded before crossing the API boundary.
    assert_eq!(
        discovery.circuit_id.as_deref(),
        Some(DHCPv6Factory::RELAY_INTERFACE_ID_HEX)
    );
    assert_eq!(
        discovery.remote_id.as_deref(),
        Some(DHCPv6Factory::RELAY_REMOTE_ID_HEX)
    );

    // DHCPv6 identity must reach the API exactly, not just as a selected MAC.
    assert_eq!(discovery.duid.as_deref(), Some(expected_duid.as_slice()));
    assert_eq!(
        discovery.address_family,
        Some(rpc::AddressFamily::V6 as i32)
    );
    assert_eq!(discovery.message_kind, Some(expected_kind as i32));
}

fn establish_lease(h: &Harness, idx: u8) -> (Vec<u8>, std::net::Ipv6Addr) {
    let expected_addr = DHCPv6Factory::mock_addr(idx);

    // SOLICIT -> ADVERTISE should carry the address selected by Carbide.
    let advertise = send_and_recv(&h.socket, DHCPv6Factory::solicit(idx))
        .expect("kea did not respond to SOLICIT");
    assert_eq!(advertise.msg_type(), v6::MessageType::Advertise);
    assert_eq!(DHCPv6Factory::ia_addr(&advertise), Some(expected_addr));
    assert_default_ia_lifetimes(&advertise);
    assert_v6_service_options(&advertise);
    assert_v6_discovery_metadata(h, 0, idx, rpc::MessageKind::V6Solicit);
    let server_id = DHCPv6Factory::server_id(&advertise);

    // REQUEST asks for a different Kea-pool address; the hook must still
    // persist the API-assigned address from the cached discovery.
    let requested_addr = format!("2001:db8::f0{idx:02x}").parse().unwrap();
    assert_ne!(requested_addr, expected_addr);
    let reply = send_and_recv(
        &h.socket,
        DHCPv6Factory::request(idx, server_id.clone(), requested_addr),
    )
    .expect("kea did not respond to REQUEST");
    assert_eq!(reply.msg_type(), v6::MessageType::Reply);
    assert_eq!(DHCPv6Factory::ia_addr(&reply), Some(expected_addr));
    assert_default_ia_lifetimes(&reply);
    assert_v6_service_options(&reply);
    let expected_duid = DHCPv6Factory::duid_ll_hex(idx);
    h.wait_for_active_lease(expected_addr, &expected_duid)
        .unwrap_or_else(|| {
            panic!(
                "expected one active Kea memfile lease for address {expected_addr} and DUID {expected_duid}"
            )
        });
    assert_eq!(
        h.api_server.calls_for(ENDPOINT_DISCOVER_DHCP),
        1,
        "SOLICIT and REQUEST should share the coarse Lease cache entry"
    );

    (server_id, expected_addr)
}

/// Assert that the DHCPv6 response carries a specific top-level status code.
fn assert_status_code(response: &v6::Message, expected: Status) {
    match response.opts().get(OptionCode::StatusCode) {
        Some(DhcpOption::StatusCode(status)) => assert_eq!(status.status, expected),
        other => panic!("expected DHCPv6 status {expected:?}, got {other:?}"),
    }
}

/// Assert that Kea-owned IA_NA lifetimes remain tied to the default v6 config.
fn assert_default_ia_lifetimes(response: &v6::Message) {
    let expected = Kea6Config::default();
    match response.opts().get(OptionCode::IANA) {
        Some(DhcpOption::IANA(ia_na)) => match ia_na.opts.get(OptionCode::IAAddr) {
            Some(DhcpOption::IAAddr(addr)) => {
                assert_eq!(addr.preferred_life, expected.preferred_lifetime);
                assert_eq!(addr.valid_life, expected.valid_lifetime);
            }
            other => panic!("DHCPv6 response did not include IAADDR: {other:?}"),
        },
        other => panic!("DHCPv6 response did not include IA_NA: {other:?}"),
    }
}

/// Assert that stateful DHCPv6 replies carry the configured service options.
fn assert_v6_service_options(response: &v6::Message) {
    assert_hook_v6_dns_servers(response);
    assert_api_v6_domain_search(response);
    assert_hook_v6_ntp_servers(response);
}

/// Return a Kea6 config with short timers so lease expiry runs during tests.
fn short_expiry_config() -> Kea6Config {
    Kea6Config {
        preferred_lifetime: 3,
        valid_lifetime: 4,
        renew_timer: 1,
        rebind_timer: 2,
        mac_sources: None,
        expired_leases_processing: Some(Kea6ExpiredLeasesProcessing {
            reclaim_timer_wait_time: 1,
            flush_reclaimed_timer_wait_time: 1,
            hold_reclaimed_time: 0,
            max_reclaim_leases: 10,
            max_reclaim_time: 100,
            unwarned_reclaim_cycles: 1,
        }),
    }
}

/// Return short-expiry config that prevents Kea from persisting a derived hwaddr.
fn short_expiry_no_hwaddr_config() -> Kea6Config {
    Kea6Config {
        // Exclude DUID and RFC6939 option 79 so lease6_expire must use its
        // own DUID fallback or skip unsafe unscoped expiry.
        mac_sources: Some(&["ipv6-link-local"]),
        ..short_expiry_config()
    }
}

/// Return short-expiry config that makes Kea derive hwaddr from DUID.
fn short_expiry_duid_hwaddr_config() -> Kea6Config {
    Kea6Config {
        // Force the Kea-derived lease hwaddr to disagree with relay option 79.
        mac_sources: Some(&["duid"]),
        ..short_expiry_config()
    }
}

#[test]
fn lease6_select_renew_and_rebind_keep_kea_on_carbide_address() -> Result<(), eyre::Report> {
    let idx = 0x20;
    let h = Harness::new();
    let (server_id, expected_addr) = establish_lease(&h, idx);
    let discover_calls = h.api_server.calls_for(ENDPOINT_DISCOVER_DHCP);

    // RENEW should reuse the cached Machine and still reply with the same address.
    let renew = send_and_recv(
        &h.socket,
        DHCPv6Factory::renew(idx, server_id, expected_addr),
    )
    .expect("kea did not respond to RENEW");
    assert_eq!(renew.msg_type(), v6::MessageType::Reply);
    assert_eq!(DHCPv6Factory::ia_addr(&renew), Some(expected_addr));
    assert_v6_service_options(&renew);
    assert_eq!(
        h.api_server.calls_for(ENDPOINT_DISCOVER_DHCP),
        discover_calls,
        "RENEW should not make a fresh API call while the hook cache is valid"
    );

    // REBIND follows the same V6Request path and lease override behavior.
    let rebind = send_and_recv(&h.socket, DHCPv6Factory::rebind(idx, expected_addr))
        .expect("kea did not respond to REBIND");
    assert_eq!(rebind.msg_type(), v6::MessageType::Reply);
    assert_eq!(DHCPv6Factory::ia_addr(&rebind), Some(expected_addr));
    assert_v6_service_options(&rebind);
    assert_eq!(
        h.api_server.calls_for(ENDPOINT_DISCOVER_DHCP),
        discover_calls,
        "REBIND should not make a fresh API call while the hook cache is valid"
    );

    Ok(())
}

#[test]
fn renew_and_rebind_cache_misses_drop_address_migration() -> Result<(), eyre::Report> {
    let idx = 0x2a;
    let mut h = Harness::new();
    let (server_id, original_addr) = establish_lease(&h, idx);
    let expected_duid = DHCPv6Factory::duid_ll_hex(idx);
    let mac_address = DHCPv6Factory::mac_string(idx);

    // Restarting Kea clears the hook process cache while preserving memfile state.
    let renewed_addr = "2001:db8::aa20".parse::<Ipv6Addr>()?;
    h.api_server
        .set_address_override(&mac_address, &renewed_addr.to_string());
    h._kea.restart()?;
    let renew_discovery_index = h.api_server.discoveries().len();
    let discover_calls = h.api_server.calls_for(ENDPOINT_DISCOVER_DHCP);

    // RENEW should fetch a fresh V6Request record, then fail closed instead
    // of renewing Kea's existing address with an API-stale value.
    assert!(
        send_and_recv(
            &h.socket,
            DHCPv6Factory::renew(idx, server_id, original_addr),
        )
        .is_none(),
        "cache-miss RENEW address migration should be dropped"
    );
    assert_eq!(
        h.api_server.calls_for(ENDPOINT_DISCOVER_DHCP),
        discover_calls + 1
    );
    assert_v6_discovery_metadata(&h, renew_discovery_index, idx, rpc::MessageKind::V6Request);
    h.wait_for_active_lease(original_addr, &expected_duid)
        .unwrap_or_else(|| {
            panic!(
                "dropped RENEW migration should leave stale lease {original_addr} for DUID {expected_duid}"
            )
        });
    assert!(
        h.active_leases(renewed_addr, &expected_duid).is_empty(),
        "RENEW must not persist migrated API address {renewed_addr} during renewal"
    );
    drop(h);

    // Use an independent harness so establish_lease keeps its first-discovery
    // and single-cache-hit assertions while REBIND exercises the same guard.
    let idx = 0x2c;
    let mut h = Harness::new();
    let (_, original_addr) = establish_lease(&h, idx);
    let expected_duid = DHCPv6Factory::duid_ll_hex(idx);
    let mac_address = DHCPv6Factory::mac_string(idx);

    // Restarting Kea clears the hook process cache while preserving memfile state.
    let rebound_addr = "2001:db8::bb20".parse::<Ipv6Addr>()?;
    h.api_server
        .set_address_override(&mac_address, &rebound_addr.to_string());
    h._kea.restart()?;
    let rebind_discovery_index = h.api_server.discoveries().len();
    let discover_calls = h.api_server.calls_for(ENDPOINT_DISCOVER_DHCP);

    // REBIND should use the same fail-closed guard without persisting the API
    // address over Kea's existing address-indexed lease.
    assert!(
        send_and_recv(&h.socket, DHCPv6Factory::rebind(idx, original_addr)).is_none(),
        "cache-miss REBIND address migration should be dropped"
    );
    assert_eq!(
        h.api_server.calls_for(ENDPOINT_DISCOVER_DHCP),
        discover_calls + 1
    );
    assert_v6_discovery_metadata(&h, rebind_discovery_index, idx, rpc::MessageKind::V6Request);
    h.wait_for_active_lease(original_addr, &expected_duid)
        .unwrap_or_else(|| {
            panic!(
                "dropped REBIND migration should leave stale lease {original_addr} for DUID {expected_duid}"
            )
        });
    assert!(
        h.active_leases(rebound_addr, &expected_duid).is_empty(),
        "REBIND must not persist migrated API address {rebound_addr} during renewal"
    );

    Ok(())
}

#[test]
fn release_preserves_the_api_v6_allocation() -> Result<(), eyre::Report> {
    let idx = 0x21;
    let h = Harness::new();
    let (server_id, expected_addr) = establish_lease(&h, idx);
    let discover_calls = h.api_server.calls_for(ENDPOINT_DISCOVER_DHCP);
    let released_addr = expected_addr;
    let expected_addr = expected_addr.to_string();

    // RELEASE is a client lease-state signal, not an API deallocation; extra
    // unsupported IA_TA must still pass through to Kea protocol handling.
    let response = send_and_recv(
        &h.socket,
        DHCPv6Factory::release_with_ia_ta(idx, server_id, released_addr),
    )
    .expect("kea did not respond to RELEASE");
    assert_eq!(response.msg_type(), v6::MessageType::Reply);
    h.assert_no_lease_end_api_calls(
        discover_calls,
        &format!("RELEASE should not call API discovery or expiry for allocation {expected_addr}"),
    );

    Ok(())
}

#[test]
fn decline_preserves_the_api_v6_allocation() -> Result<(), eyre::Report> {
    let idx = 0x24;
    let h = Harness::new();
    let (server_id, expected_addr) = establish_lease(&h, idx);
    let discover_calls = h.api_server.calls_for(ENDPOINT_DISCOVER_DHCP);
    let declined_addr = expected_addr;
    let expected_addr = expected_addr.to_string();

    // DECLINE is a client conflict signal, not an API deallocation; extra
    // unsupported IA_PD must still pass through to Kea protocol handling.
    let response = send_and_recv(
        &h.socket,
        DHCPv6Factory::decline_with_ia_pd(idx, server_id, declined_addr),
    )
    .expect("kea did not respond to DECLINE");
    assert_eq!(response.msg_type(), v6::MessageType::Reply);
    h.assert_no_lease_end_api_calls(
        discover_calls,
        &format!("DECLINE should not call API discovery or expiry for allocation {expected_addr}"),
    );

    Ok(())
}

#[test]
fn lease6_expire_uses_duid_fallback_when_kea_lease_has_no_hwaddr() -> Result<(), eyre::Report> {
    let idx = 0x29;
    let h = Harness::new_with_config(short_expiry_no_hwaddr_config());
    let expected_addr = DHCPv6Factory::mock_addr(idx);

    let advertise = send_and_recv(
        &h.socket,
        DHCPv6Factory::solicit_without_relay_option79(idx),
    )
    .expect("kea did not respond to SOLICIT without relay option 79");
    assert_eq!(advertise.msg_type(), v6::MessageType::Advertise);
    assert_eq!(DHCPv6Factory::ia_addr(&advertise), Some(expected_addr));
    assert_v6_service_options(&advertise);
    assert_v6_discovery_metadata(&h, 0, idx, rpc::MessageKind::V6Solicit);
    let server_id = DHCPv6Factory::server_id(&advertise);

    let reply = send_and_recv(
        &h.socket,
        DHCPv6Factory::request_without_relay_option79(idx, server_id, expected_addr),
    )
    .expect("kea did not respond to REQUEST without relay option 79");
    assert_eq!(reply.msg_type(), v6::MessageType::Reply);
    assert_eq!(DHCPv6Factory::ia_addr(&reply), Some(expected_addr));
    assert_v6_service_options(&reply);

    let expected_duid = DHCPv6Factory::duid_ll_hex(idx);
    let lease = h
        .wait_for_active_lease(expected_addr, &expected_duid)
        .unwrap_or_else(|| {
            panic!(
                "expected active Kea memfile lease for address {expected_addr} and DUID {expected_duid}"
            )
        });
    assert!(
        lease.hwaddr.trim().is_empty(),
        "expected Kea lease to omit hwaddr so lease6_expire must fall back to DUID, got {lease:?}"
    );
    assert!(
        h.wait_for_scoped_expire_rpc(expected_addr, &DHCPv6Factory::mac_string(idx)),
        "lease6_expire should call API expiry for {expected_addr} scoped by DUID-derived MAC"
    );

    Ok(())
}

#[test]
fn lease6_expire_invalidates_v6_lease_cache_before_retry() -> Result<(), eyre::Report> {
    let idx = 0x2d;
    let h = Harness::new_with_config(short_expiry_config());
    let first_addr = DHCPv6Factory::mock_addr(idx);

    // Establish a short-lived lease and wait for expiry to release the API allocation.
    let advertise = send_and_recv(&h.socket, DHCPv6Factory::solicit(idx))
        .expect("kea did not respond to short-lived SOLICIT");
    assert_eq!(advertise.msg_type(), v6::MessageType::Advertise);
    assert_eq!(DHCPv6Factory::ia_addr(&advertise), Some(first_addr));
    let server_id = DHCPv6Factory::server_id(&advertise);

    let reply = send_and_recv(
        &h.socket,
        DHCPv6Factory::request(idx, server_id, first_addr),
    )
    .expect("kea did not respond to short-lived REQUEST");
    assert_eq!(reply.msg_type(), v6::MessageType::Reply);
    assert_eq!(DHCPv6Factory::ia_addr(&reply), Some(first_addr));
    assert!(
        h.wait_for_scoped_expire_rpc(first_addr, &DHCPv6Factory::mac_string(idx)),
        "lease6_expire should release {first_addr} before retry"
    );

    // A retry before the 60-second cache TTL must fetch the API again rather
    // than resurrect the released address from the hook cache.
    let retry_addr = "2001:db8::cc20".parse::<Ipv6Addr>()?;
    h.api_server
        .set_address_override(&DHCPv6Factory::mac_string(idx), &retry_addr.to_string());
    let discover_calls = h.api_server.calls_for(ENDPOINT_DISCOVER_DHCP);

    let retry_advertise = send_and_recv(&h.socket, DHCPv6Factory::solicit(idx))
        .expect("kea did not respond to retry SOLICIT after expiry");
    assert_eq!(retry_advertise.msg_type(), v6::MessageType::Advertise);
    assert_eq!(DHCPv6Factory::ia_addr(&retry_advertise), Some(retry_addr));
    assert_eq!(
        h.api_server.calls_for(ENDPOINT_DISCOVER_DHCP),
        discover_calls + 1,
        "expiry must invalidate the cached DHCPv6 Machine before retry"
    );
    let retry_server_id = DHCPv6Factory::server_id(&retry_advertise);

    let retry_reply = send_and_recv(
        &h.socket,
        DHCPv6Factory::request(idx, retry_server_id, retry_addr),
    )
    .expect("kea did not respond to retry REQUEST after expiry");
    assert_eq!(retry_reply.msg_type(), v6::MessageType::Reply);
    assert_eq!(DHCPv6Factory::ia_addr(&retry_reply), Some(retry_addr));

    Ok(())
}

#[test]
fn lease6_expire_uses_option79_mac_for_non_mac_duid() -> Result<(), eyre::Report> {
    let idx = 0x2b;
    let h = Harness::new_with_config(short_expiry_no_hwaddr_config());
    let duid = DHCPv6Factory::duid_en(12);
    let expected_duid = DHCPv6Factory::duid_hex(&duid);
    let expected_addr = DHCPv6Factory::mock_addr(idx);

    // A non-MAC DUID can be served through relay option 79; expiry must reuse
    // that hook-selected MAC rather than falling back to address-only deletion.
    let advertise = send_and_recv(
        &h.socket,
        DHCPv6Factory::solicit_with_duid(idx, duid.clone(), true),
    )
    .expect("kea did not respond to DUID-EN SOLICIT with relay option 79");
    assert_eq!(advertise.msg_type(), v6::MessageType::Advertise);
    assert_eq!(DHCPv6Factory::ia_addr(&advertise), Some(expected_addr));
    assert_v6_service_options(&advertise);
    let server_id = DHCPv6Factory::server_id(&advertise);

    let reply = send_and_recv(
        &h.socket,
        DHCPv6Factory::request_with_duid(idx, server_id, expected_addr, duid, true),
    )
    .expect("kea did not respond to DUID-EN REQUEST with relay option 79");
    assert_eq!(reply.msg_type(), v6::MessageType::Reply);
    assert_eq!(DHCPv6Factory::ia_addr(&reply), Some(expected_addr));
    assert_v6_service_options(&reply);

    let lease = h
        .wait_for_active_lease(expected_addr, &expected_duid)
        .unwrap_or_else(|| {
            panic!(
                "expected active Kea memfile lease for address {expected_addr} and DUID {expected_duid}"
            )
        });
    assert!(
        lease.hwaddr.trim() == DHCPv6Factory::mac_string(idx),
        "expected Kea lease to store hook-selected option79 MAC, got {lease:?}"
    );
    assert!(
        h.wait_for_scoped_expire_rpc(expected_addr, &DHCPv6Factory::mac_string(idx)),
        "lease6_expire should call API expiry for {expected_addr} scoped by option79 MAC"
    );

    Ok(())
}

#[test]
fn lease6_expire_uses_option79_mac_when_duid_mac_disagrees() -> Result<(), eyre::Report> {
    let option79_idx = 0x2e;
    let duid_idx = 0x2f;
    let h = Harness::new_with_config(short_expiry_duid_hwaddr_config());
    let duid = DHCPv6Factory::duid_ll(duid_idx);
    let expected_duid = DHCPv6Factory::duid_hex(&duid);
    let expected_addr = DHCPv6Factory::mock_addr(option79_idx);
    let option79_mac = DHCPv6Factory::mac_string(option79_idx);

    // Kea is configured to derive hwaddr from DUID, but Carbide identity
    // selection deliberately trusts relay option 79 when the two disagree.
    let advertise = send_and_recv(
        &h.socket,
        DHCPv6Factory::solicit_with_duid(option79_idx, duid.clone(), true),
    )
    .expect("kea did not respond to DUID/option79 disagreement SOLICIT");
    assert_eq!(advertise.msg_type(), v6::MessageType::Advertise);
    assert_eq!(DHCPv6Factory::ia_addr(&advertise), Some(expected_addr));
    assert!(
        same_mac_text(&h.api_server.discoveries()[0].mac_address, &option79_mac),
        "API allocation should be owned by relay option79 MAC"
    );
    let server_id = DHCPv6Factory::server_id(&advertise);

    let reply = send_and_recv(
        &h.socket,
        DHCPv6Factory::request_with_duid(option79_idx, server_id, expected_addr, duid, true),
    )
    .expect("kea did not respond to DUID/option79 disagreement REQUEST");
    assert_eq!(reply.msg_type(), v6::MessageType::Reply);
    assert_eq!(DHCPv6Factory::ia_addr(&reply), Some(expected_addr));
    let renew_server_id = DHCPv6Factory::server_id(&reply);

    // RENEW runs after Kea has copied its configured DUID-derived hwaddr onto
    // the lease; the hook must restore the option79 identity again.
    let renew = send_and_recv(
        &h.socket,
        DHCPv6Factory::renew_with_duid(
            option79_idx,
            renew_server_id,
            expected_addr,
            DHCPv6Factory::duid_ll(duid_idx),
            true,
        ),
    )
    .expect("kea did not respond to DUID/option79 disagreement RENEW");
    assert_eq!(renew.msg_type(), v6::MessageType::Reply);
    assert_eq!(DHCPv6Factory::ia_addr(&renew), Some(expected_addr));

    let lease = h
        .wait_for_active_lease(expected_addr, &expected_duid)
        .unwrap_or_else(|| {
            panic!(
                "expected active Kea memfile lease for address {expected_addr} and DUID {expected_duid}"
            )
        });
    assert!(
        same_mac_text(lease.hwaddr.trim(), &option79_mac),
        "lease expiry must use the same selected MAC as allocation"
    );
    assert!(
        h.wait_for_scoped_expire_rpc(expected_addr, &option79_mac),
        "lease6_expire should call API expiry for {expected_addr} scoped by option79 MAC"
    );

    Ok(())
}

#[test]
fn nested_relay_solicit_is_dropped_loudly_before_api_call() -> Result<(), eyre::Report> {
    let h = Harness::new();
    let mut expected_drops = v6_drop_metric_value(h._kea.metrics_endpoint(), "nested_relay");

    // Multi-hop and nested Relay-Forward packets must be rejected by the hook,
    // not silently lost before the required observability signal.
    for packet in [
        DHCPv6Factory::solicit_with_hop_count(0x2c, 2),
        DHCPv6Factory::solicit_with_nested_relay(0x2d),
    ] {
        assert!(send_and_recv(&h.socket, packet).is_none());
        expected_drops += 1.0;
        assert!(wait_for_v6_drop_metric_at_least(
            h._kea.metrics_endpoint(),
            "nested_relay",
            expected_drops,
            METRIC_TIMEOUT,
        ));
    }
    assert_eq!(h.api_server.calls_for(ENDPOINT_DISCOVER_DHCP), 0);

    Ok(())
}

#[test]
fn lease_end_messages_with_unsupported_hop_count_are_dropped() -> Result<(), eyre::Report> {
    let idx = 0x27;
    let h = Harness::new();
    let (server_id, expected_addr) = establish_lease(&h, idx);
    let discover_calls = h.api_server.calls_for(ENDPOINT_DISCOVER_DHCP);

    assert!(
        send_and_recv(
            &h.socket,
            DHCPv6Factory::release_with_hop_count(idx, server_id.clone(), expected_addr, 2),
        )
        .is_none()
    );
    h.assert_no_lease_end_api_calls(
        discover_calls,
        "unsupported-hop RELEASE should be dropped before API discovery or expiry",
    );

    assert!(
        send_and_recv(
            &h.socket,
            DHCPv6Factory::decline_with_hop_count(idx, server_id, expected_addr, 2),
        )
        .is_none()
    );
    h.assert_no_lease_end_api_calls(
        discover_calls,
        "unsupported-hop DECLINE should be dropped before API discovery or expiry",
    );

    Ok(())
}

#[test]
fn confirm_cache_hit_replies_without_not_on_link() -> Result<(), eyre::Report> {
    let idx = 0x22;
    let h = Harness::new();
    let (_, expected_addr) = establish_lease(&h, idx);
    let discover_calls = h.api_server.calls_for(ENDPOINT_DISCOVER_DHCP);

    // CONFIRM is cache-only: a matching cached lease should stay on-link.
    let response = send_and_recv(&h.socket, DHCPv6Factory::confirm(idx, expected_addr))
        .expect("kea did not respond to CONFIRM cache hit");
    assert_eq!(response.msg_type(), v6::MessageType::Reply);
    assert_status_code(&response, Status::Success);
    assert_eq!(
        h.api_server.calls_for(ENDPOINT_DISCOVER_DHCP),
        discover_calls,
        "CONFIRM cache hit should not make a fresh API call"
    );

    Ok(())
}

#[test]
fn confirm_cache_hit_tolerates_absent_optional_vendor_class() -> Result<(), eyre::Report> {
    let idx = 0x26;
    let h = Harness::new();

    let advertise = send_and_recv(
        &h.socket,
        DHCPv6Factory::solicit_with_vendor_class(idx, b"HTTPClient"),
    )
    .expect("kea did not respond to vendor-class SOLICIT");
    assert_eq!(advertise.msg_type(), v6::MessageType::Advertise);
    let expected_addr = DHCPv6Factory::mock_addr(idx);
    assert_eq!(DHCPv6Factory::ia_addr(&advertise), Some(expected_addr));
    let discover_calls = h.api_server.calls_for(ENDPOINT_DISCOVER_DHCP);

    // The vendor class is optional client metadata. CONFIRM often omits it,
    // so the cache hit should be accepted when the IA address remains on-link.
    let response = send_and_recv(&h.socket, DHCPv6Factory::confirm(idx, expected_addr))
        .expect("kea did not respond to CONFIRM without vendor class");
    assert_eq!(response.msg_type(), v6::MessageType::Reply);
    assert_status_code(&response, Status::Success);
    assert_eq!(
        h.api_server.calls_for(ENDPOINT_DISCOVER_DHCP),
        discover_calls
    );

    Ok(())
}

#[test]
fn confirm_cache_hit_tolerates_multiple_vendor_class_variants() -> Result<(), eyre::Report> {
    let idx = 0x28;
    let h = Harness::new();

    // Cache one API lease through a SOLICIT with one vendor class.
    let advertise = send_and_recv(
        &h.socket,
        DHCPv6Factory::solicit_with_vendor_class(idx, b"HTTPClient-A"),
    )
    .expect("kea did not respond to vendor-class SOLICIT");
    assert_eq!(advertise.msg_type(), v6::MessageType::Advertise);
    let expected_addr = DHCPv6Factory::mock_addr(idx);
    assert_eq!(DHCPv6Factory::ia_addr(&advertise), Some(expected_addr));
    let server_id = DHCPv6Factory::server_id(&advertise);

    // Cache the same API lease through a REQUEST with a different vendor class.
    let reply = send_and_recv(
        &h.socket,
        DHCPv6Factory::request_with_vendor_class(idx, server_id, expected_addr, b"HTTPClient-B"),
    )
    .expect("kea did not respond to vendor-class REQUEST");
    assert_eq!(reply.msg_type(), v6::MessageType::Reply);
    assert_eq!(DHCPv6Factory::ia_addr(&reply), Some(expected_addr));
    let discover_calls = h.api_server.calls_for(ENDPOINT_DISCOVER_DHCP);
    assert_eq!(discover_calls, 2);
    let discoveries = h.api_server.discoveries();
    assert_eq!(discoveries.len(), 2);
    assert_v6_discovery_metadata(&h, 0, idx, rpc::MessageKind::V6Solicit);
    assert_v6_discovery_metadata(&h, 1, idx, rpc::MessageKind::V6Request);
    assert_eq!(
        discoveries[0].vendor_string.as_deref(),
        Some("HTTPClient-A")
    );
    assert_eq!(
        discoveries[1].vendor_string.as_deref(),
        Some("HTTPClient-B")
    );

    // CONFIRM often omits vendor class; equivalent cache variants should not
    // force NotOnLink when they agree on the API lease context.
    let response = send_and_recv(&h.socket, DHCPv6Factory::confirm(idx, expected_addr))
        .expect("kea did not respond to CONFIRM without vendor class");
    assert_eq!(response.msg_type(), v6::MessageType::Reply);
    assert_status_code(&response, Status::Success);
    assert_eq!(
        h.api_server.calls_for(ENDPOINT_DISCOVER_DHCP),
        discover_calls
    );

    Ok(())
}

#[test]
/// CONFIRM must reject cached-client addresses outside the API-owned prefix.
fn confirm_cache_hit_with_off_prefix_address_replies_not_on_link() -> Result<(), eyre::Report> {
    let idx = 0x25;
    let h = Harness::new();
    let (_, _) = establish_lease(&h, idx);
    let discover_calls = h.api_server.calls_for(ENDPOINT_DISCOVER_DHCP);

    // Identity alone is not enough; the confirmed address must be on the
    // cached API prefix.
    let response = send_and_recv(
        &h.socket,
        DHCPv6Factory::confirm(idx, "2001:db9::1".parse()?),
    )
    .expect("kea did not respond to off-prefix CONFIRM");
    assert_eq!(response.msg_type(), v6::MessageType::Reply);
    assert_status_code(&response, Status::NotOnLink);
    assert_eq!(
        h.api_server.calls_for(ENDPOINT_DISCOVER_DHCP),
        discover_calls
    );

    Ok(())
}

#[test]
fn confirm_cache_miss_replies_not_on_link_without_api_call() -> Result<(), eyre::Report> {
    let idx = 0x23;
    let h = Harness::new();

    // Without a cached discovery, CONFIRM should fail closed as NotOnLink.
    let response = send_and_recv(
        &h.socket,
        DHCPv6Factory::confirm(idx, DHCPv6Factory::mock_addr(idx)),
    )
    .expect("kea did not respond to CONFIRM cache miss");
    assert_eq!(response.msg_type(), v6::MessageType::Reply);
    assert_status_code(&response, Status::NotOnLink);
    assert_eq!(h.api_server.calls_for(ENDPOINT_DISCOVER_DHCP), 0);

    Ok(())
}
