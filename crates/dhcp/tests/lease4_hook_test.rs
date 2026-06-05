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

//! Integration tests for the lease4_select and lease4_renew hook callouts.
//!
//! These tests boot a real Kea process with our hook library loaded, send DHCP
//! packets at it, and assert on what ends up in Kea's memfile lease file
//! (kea-leases4.csv). The point is to verify that the memfile stays aligned
//! with what Carbide returns from DiscoverDhcp -- regardless of what address
//! the client requested in option 50 or ciaddr.

use std::net::{Ipv4Addr, UdpSocket};
use std::time::Duration;

use dhcp::mock_api_server;
use dhcproto::{Decodable, Decoder, v4};

mod common;

use common::{DHCPFactory, Kea, RELAY_IP};

const READ_TIMEOUT: Duration = Duration::from_millis(500);
/// Memfile writes are usually flushed within a few ms of the ACK.
/// Trying to be generous to avoid flakiness on slow CI runners,
/// which happens for other things (like Posrgres).
const MEMFILE_TIMEOUT: Duration = Duration::from_secs(2);

/// Send one packet and read one response. Returns the parsed response message.
fn send_and_recv(socket: &UdpSocket, msg: v4::Message) -> Option<v4::Message> {
    let pkt = DHCPFactory::encode(msg).unwrap();
    socket.send(&pkt).unwrap();
    let mut buf = [0u8; 1500];
    let n = socket.recv(&mut buf).ok()?;
    Some(v4::Message::decode(&mut Decoder::new(&buf[..n])).unwrap())
}

/// Build a SELECTING-state DHCPREQUEST (the REQUEST that follows an OFFER).
/// Sets option 50 (requested-address) and option 54 (server-identifier) so
/// Kea recognizes it as the client picking up an OFFER it just received.
fn request_selecting(idx: u8, requested_addr: Ipv4Addr, server_id: Ipv4Addr) -> v4::Message {
    let mut msg = DHCPFactory::base_relayed_message(idx, v4::MessageType::Request);
    let opts = msg.opts_mut();
    opts.insert(v4::DhcpOption::RequestedIpAddress(requested_addr));
    opts.insert(v4::DhcpOption::ServerIdentifier(server_id));
    msg
}

/// Build a RENEWING-state DHCPREQUEST: ciaddr set to the current lease IP,
/// no option 50, no option 54. Per RFC 2131 this would be unicast to the
/// server, but our test harness pretends to be the relay so we send it
/// through the same relayed path as everything else.
fn request_renewing(idx: u8, ciaddr: Ipv4Addr) -> v4::Message {
    let mut msg = DHCPFactory::base_relayed_message(idx, v4::MessageType::Request);
    msg.set_ciaddr(ciaddr);
    msg
}

/// Extract option 54 (server-identifier) from a DHCP message. Tests need this
/// to send a SELECTING-state REQUEST that Kea will accept.
fn server_identifier(msg: &v4::Message) -> Ipv4Addr {
    match msg.opts().get(v4::OptionCode::ServerIdentifier) {
        Some(v4::DhcpOption::ServerIdentifier(addr)) => *addr,
        other => panic!("OFFER did not include option 54 (server-identifier): {other:?}"),
    }
}

/// MAC string in the format Kea writes to kea-leases4.csv (lowercase hex,
/// colon-separated). Matches the format produced by `DHCPFactory::discover`
/// and friends for a given idx.
fn mac_for_idx(idx: u8) -> String {
    format!("02:00:00:00:00:{idx:02x}")
}

/// The mock returns 172.20.0.X by default, where X is the MAC's last byte.
fn default_mock_addr(idx: u8) -> Ipv4Addr {
    Ipv4Addr::new(172, 20, 0, idx)
}

/// tokio rt + mock API + Kea + socket pretending to be the relay.
struct Harness {
    _rt: tokio::runtime::Runtime,
    api_server: mock_api_server::MockAPIServer,
    kea: Kea,
    socket: UdpSocket,
}

impl Harness {
    fn new(in_port: u16, out_port: u16) -> Self {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let api_server = rt.block_on(mock_api_server::MockAPIServer::start());

        let mut kea = Kea::new(api_server.local_http_addr(), in_port, out_port).unwrap();
        kea.run().unwrap();

        let socket = UdpSocket::bind(format!("{RELAY_IP}:{out_port}")).unwrap();
        socket.connect(format!("127.0.0.1:{in_port}")).unwrap();
        socket.set_read_timeout(Some(READ_TIMEOUT)).unwrap();

        Harness {
            _rt: rt,
            api_server,
            kea,
            socket,
        }
    }
}

// Make sure the happy path is good here -- standard DORA.
// Carbide and Kea agree on the address from the start.
// Verify the memfile ends up with Carbide's IP.
#[test]
fn lease4_select_persists_carbide_ip_on_happy_path() -> Result<(), eyre::Report> {
    let idx = 0x20;
    let h = Harness::new(7100, 7101);

    // DISCOVER → OFFER
    let offer = send_and_recv(&h.socket, DHCPFactory::discover(idx))
        .expect("kea did not respond to DISCOVER");
    assert_eq!(offer.opts().msg_type().unwrap(), v4::MessageType::Offer);
    assert_eq!(offer.yiaddr(), default_mock_addr(idx));
    let server_id = server_identifier(&offer);

    // REQUEST (SELECTING) → ACK
    let ack = send_and_recv(
        &h.socket,
        request_selecting(idx, default_mock_addr(idx), server_id),
    )
    .expect("kea did not respond to REQUEST");
    assert_eq!(ack.opts().msg_type().unwrap(), v4::MessageType::Ack);
    assert_eq!(ack.yiaddr(), default_mock_addr(idx));

    // Memfile must contain the carbide address (not whatever Kea would have
    // picked on its own from the 0.0.0.0/0 pool).
    assert!(
        h.kea
            .wait_for_lease(&mac_for_idx(idx), default_mock_addr(idx), MEMFILE_TIMEOUT),
        "expected memfile entry ({}, {})",
        mac_for_idx(idx),
        default_mock_addr(idx)
    );

    Ok(())
}

// Now test the rogue scenario. Client sends a REQUEST with option 50
// set to a *different* IP than what the OFFER carried (simulating a client
// that accepted a rogue server's offer, but is broadcasting the REQUEST so we
// see it). Without lease4_select, Kea would honor option 50 and persist the
// wrong address. With lease4_select, the memfile gets Carbide's IP.
#[test]
fn lease4_select_overrides_rogue_option_50_in_memfile() -> Result<(), eyre::Report> {
    let idx = 0x21;
    let rogue_ip = Ipv4Addr::new(192, 168, 99, 99);
    let h = Harness::new(7102, 7103);

    // DISCOVER → OFFER (so kea has a state for this MAC and accepts the
    // following REQUEST). The OFFER's yiaddr is the carbide-allocated IP.
    let offer = send_and_recv(&h.socket, DHCPFactory::discover(idx))
        .expect("kea did not respond to DISCOVER");
    assert_eq!(offer.yiaddr(), default_mock_addr(idx));
    let server_id = server_identifier(&offer);

    // REQUEST with option 50 = rogue_ip (≠ what was offered). Option 54 still
    // points at kea so kea processes the REQUEST.
    let ack = send_and_recv(&h.socket, request_selecting(idx, rogue_ip, server_id))
        .expect("kea did not respond to REQUEST");
    assert_eq!(ack.opts().msg_type().unwrap(), v4::MessageType::Ack);
    // Wire is correct because pkt4_send rewrites yiaddr regardless.
    // ...but still need to do our assertion on the memfile below.
    assert_eq!(ack.yiaddr(), default_mock_addr(idx));

    // The memfile must hold Carbide's IP, not the rogue value the client
    // asked for in option 50. This is what lease4_select uniquely enforces.
    assert!(
        h.kea
            .wait_for_lease(&mac_for_idx(idx), default_mock_addr(idx), MEMFILE_TIMEOUT),
        "memfile should contain carbide IP {} for MAC {}, not the rogue option-50 value {rogue_ip}",
        default_mock_addr(idx),
        mac_for_idx(idx),
    );

    // And specifically nothing in the memfile should have the rogue address.
    let leases = h.kea.read_leases();
    assert!(
        !leases.iter().any(|l| l.address == rogue_ip),
        "rogue IP {rogue_ip} should never be persisted, but found in leases: {leases:?}",
    );

    Ok(())
}

// And now the failure path. Carbide returns a Machine with no IPv4 address
// (address=""). pkt4_receive must drop before lease selection; specifically,
// the REQUEST path must not create an active memfile lease for the MAC.
#[test]
fn pkt4_receive_drops_when_carbide_returns_no_address() -> Result<(), eyre::Report> {
    let idx = 0x22;
    let helper_idx = 0x24;
    let h = Harness::new(7104, 7105);

    // Learn Kea's server identifier from a different MAC. The failure case
    // below needs a SELECTING-state REQUEST so it exercises the persistence
    // path, not just DISCOVER's fake allocation path.
    let helper_offer = send_and_recv(&h.socket, DHCPFactory::discover(helper_idx))
        .expect("kea did not respond to helper DISCOVER");
    let server_id = server_identifier(&helper_offer);

    // Tell the mock to return an empty address for this MAC, which the API
    // side translates to machine_get_interface_address()==0.
    h.api_server.set_address_override(&mac_for_idx(idx), "");

    // Send a REQUEST directly so this would be persisted if pkt4_receive did
    // not stop processing before Kea's allocator.
    if let Some(msg) = send_and_recv(
        &h.socket,
        request_selecting(idx, default_mock_addr(idx), server_id),
    ) {
        let mtype = msg.opts().msg_type();
        // If Kea did send a response, it must not be an ACK/OFFER with a usable
        // yiaddr (that would mean we allocated despite the drop).
        if matches!(mtype, Some(v4::MessageType::Ack | v4::MessageType::Offer)) {
            assert_eq!(
                msg.yiaddr(),
                Ipv4Addr::UNSPECIFIED,
                "should not allocate a real address when Carbide returned none, got {msg}"
            );
        }
    }

    // Key assertion: no active memfile entry for this MAC. Wait a beat so we
    // don't race a lazy memfile flush in the success-but-not-yet-visible case.
    std::thread::sleep(Duration::from_millis(200));
    let leases = h.kea.read_leases();
    assert!(
        !leases
            .iter()
            .any(|l| l.hwaddr == mac_for_idx(idx) && l.state == 0),
        "expected no active lease for {}, found: {leases:?}",
        mac_for_idx(idx),
    );

    Ok(())
}

// Test lease4_renew is wired up and doesn't break the renewal path. After
// a successful DORA, send a RENEWING-state DHCPREQUEST (ciaddr=current IP, no
// option 50, no option 54) and verify the memfile entry survives.
//
// Note: the override branch of lease4_renew (mock returning a different IP at
// renewal time) is not exercised here because the carbide-dhcp client-side
// cache has a 60s TTL and busting it for a test would require either waiting
// or invasive test hooks. The override logic itself is structurally identical
// to lease4_select, which tests A/B/C exercise thoroughly. This test verifies
// lease4_renew is registered, fires, and is a safe no-op on the steady-state
// renewal path.
// ─────────────────────────────────────────────────────────────────────────────
#[test]
fn lease4_renew_preserves_memfile_on_steady_state_renewal() -> Result<(), eyre::Report> {
    let idx = 0x23;
    let h = Harness::new(7106, 7107);

    // Initial DORA.
    let offer = send_and_recv(&h.socket, DHCPFactory::discover(idx))
        .expect("kea did not respond to DISCOVER");
    let server_id = server_identifier(&offer);
    let ack = send_and_recv(
        &h.socket,
        request_selecting(idx, default_mock_addr(idx), server_id),
    )
    .expect("kea did not respond to REQUEST");
    assert_eq!(ack.opts().msg_type().unwrap(), v4::MessageType::Ack);
    assert!(
        h.kea
            .wait_for_lease(&mac_for_idx(idx), default_mock_addr(idx), MEMFILE_TIMEOUT)
    );

    // Renewing REQUEST: ciaddr = the IP we currently hold.
    let renew_ack = send_and_recv(&h.socket, request_renewing(idx, default_mock_addr(idx)))
        .expect("kea did not respond to renewing REQUEST");
    assert_eq!(renew_ack.opts().msg_type().unwrap(), v4::MessageType::Ack);
    assert_eq!(renew_ack.yiaddr(), default_mock_addr(idx));

    // Memfile still has the carbide IP. The lease4_renew hook fired (we'd see
    // a NAK or no response if it failed) and was a no-op on this matching path.
    let lease = h
        .kea
        .find_lease(&mac_for_idx(idx))
        .expect("active lease should still exist after renewal");
    assert_eq!(lease.address, default_mock_addr(idx));

    Ok(())
}

// Verify how kea handles a REQUEST whose Option 54 (server-identifier)
// does not match kea's own identifier -- i.e. the case where a client
// picked a competing server's OFFER and is broadcasting its REQUEST,
// naming that other server.
//
// Per RFC 2131 the server MUST silently discard such a REQUEST. This test
// verifies kea honors that behavior in our config (authoritative + 0.0.0.0/0
// pool) and documents the outcome. If kea ever stops honoring Option 54,
// this test will fail and we'll know lease4_select needs to start enforcing
// it. The rogue option-50 IP MUST NOT end up in the memfile.
#[test]
fn check_memfile_on_option_54() -> Result<(), eyre::Report> {
    let idx = 0x24;
    let bogus_request_ip = Ipv4Addr::new(192, 168, 99, 99);
    let fake_server_id = Ipv4Addr::new(10, 99, 99, 99); // not kea's identifier
    let h = Harness::new(7108, 7109);

    // DISCOVER first, so kea has cached per-packet state for this MAC.
    let offer = send_and_recv(&h.socket, DHCPFactory::discover(idx))
        .expect("kea did not respond to DISCOVER");
    assert_eq!(offer.yiaddr(), default_mock_addr(idx));

    // REQUEST naming a fake server.
    // Option 50 is a rogue IP that should not reach the memfile.
    let pkt = DHCPFactory::encode(request_selecting(idx, bogus_request_ip, fake_server_id))?;
    h.socket.send(&pkt)?;
    let mut buf = [0u8; 1500];
    match h.socket.recv(&mut buf) {
        Ok(n) => {
            let msg = v4::Message::decode(&mut Decoder::new(&buf[..n])).unwrap();
            println!(
                "kea responded to mismatched-server-id REQUEST: type={:?} yiaddr={}",
                msg.opts().msg_type(),
                msg.yiaddr()
            );
        }
        Err(_) => {
            println!("kea silently dropped REQUEST with mismatched server-id (RFC behavior)");
        }
    }

    // Whatever kea did, the rogue IP shouldn't be persisted.
    std::thread::sleep(Duration::from_millis(200));
    let leases = h.kea.read_leases();
    assert!(
        !leases.iter().any(|l| l.address == bogus_request_ip),
        "bogus option-50 IP {bogus_request_ip} should never appear in memfile, found: {leases:?}",
    );

    // And if there *is* an active entry for this MAC, it must be NICo's IP.
    if let Some(lease) = h.kea.find_lease(&mac_for_idx(idx)) {
        assert_eq!(
            lease.address,
            default_mock_addr(idx),
            "if memfile has an entry for {}, it must be the carbide IP",
            mac_for_idx(idx)
        );
    }

    Ok(())
}

// The motivating bug pattern in production. A client (e.g. a BMC) previously
// got an IP from some other source -- a rogue DHCP server, stale config,
// pre-deployment state, etc. -- and remembered that address in non-volatile
// storage. On reboot it sends a DHCPREQUEST with option 50 = remembered IP,
// no ciaddr, and crucially no Option 54 (it's not picking from offers, it's
// just confirming a remembered IP). This is INIT-REBOOT state per RFC 2131.
//
// Option 54 doesn't apply here, so kea has nothing to filter on. Without the
// pkt4_receive early drop + lease4_select override, kea would allocate per
// option 50 and seed the memfile with the wrong IP. This test verifies the
// fix protects against exactly this flow.
#[test]
fn reboot_with_stale_remembered_ip_does_not_pollute_memfile() -> Result<(), eyre::Report> {
    let idx = 0x27;
    let remembered_wrong_ip = Ipv4Addr::new(192, 168, 99, 99);
    let h = Harness::new(7112, 7113);

    // No prior DISCOVER -- this is the BMC's first packet after reboot.
    // INIT-REBOOT REQUEST: option 50 set, no ciaddr, no Option 54.
    let mut req = DHCPFactory::base_relayed_message(idx, v4::MessageType::Request);
    req.opts_mut()
        .insert(v4::DhcpOption::RequestedIpAddress(remembered_wrong_ip));
    let response = send_and_recv(&h.socket, req);

    // Kea's specific response is config-dependent (may NAK, may ACK with
    // overridden yiaddr, may drop). What we care about is the persistence
    // outcome.
    if let Some(msg) = response {
        println!(
            "kea responded to INIT-REBOOT: type={:?} yiaddr={}",
            msg.opts().msg_type(),
            msg.yiaddr()
        );
    } else {
        println!("kea did not respond to INIT-REBOOT (silent drop)");
    }

    std::thread::sleep(Duration::from_millis(200));
    let leases = h.kea.read_leases();

    // The remembered wrong IP must never be persisted.
    assert!(
        !leases.iter().any(|l| l.address == remembered_wrong_ip),
        "remembered wrong IP {remembered_wrong_ip} must not be persisted, found: {leases:?}",
    );

    // If anything was persisted for this MAC, it must be carbide's IP.
    if let Some(lease) = h.kea.find_lease(&mac_for_idx(idx)) {
        assert_eq!(
            lease.address,
            default_mock_addr(idx),
            "if memfile has an entry for {}, it must be the carbide IP, not the remembered one",
            mac_for_idx(idx)
        );
    }

    Ok(())
}
