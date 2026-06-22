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
use std::io::ErrorKind;
use std::net::UdpSocket;
use std::time::{Duration, Instant};

use dhcp::mock_api_server;
use dhcproto::{Decodable, Decoder, v4};

mod common;

use common::{DHCPFactory, Kea};

const READ_TIMEOUT: Duration = Duration::from_millis(200);
const OFFER_TIMEOUT: Duration = Duration::from_secs(10);

fn recv_offer(socket: &UdpSocket, request: &[u8]) -> Result<v4::Message, eyre::Report> {
    let deadline = Instant::now() + OFFER_TIMEOUT;
    let mut recv_buf = [0u8; 1500]; // packet is 470 bytes, but allow for full MTU

    loop {
        // Retransmit on each receive timeout, matching DHCP-over-UDP retry
        // behavior and avoiding a race with Kea finishing startup.
        socket.send(request)?;
        match socket.recv(&mut recv_buf) {
            Ok(n) => {
                let msg = v4::Message::decode(&mut Decoder::new(&recv_buf[..n]))
                    .map_err(|err| eyre::eyre!("failed to decode DHCP response: {err}"))?;
                return Ok(msg);
            }
            Err(err)
                if matches!(
                    err.kind(),
                    ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                ) =>
            {
                if Instant::now() >= deadline {
                    return Err(eyre::eyre!(
                        "timed out waiting for DHCP offer after {OFFER_TIMEOUT:?}: {err}"
                    ));
                }
            }
            Err(err) => {
                return Err(eyre::eyre!("socket recv unhandled error: {err}"));
            }
        }
    }
}

#[test]
fn test_booturl_internal_with_mtu() -> Result<(), eyre::Report> {
    // Start multi-threaded mock API server. The hooks call this over the network.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let api_server = rt.block_on(mock_api_server::MockAPIServer::start());

    let (_kea, socket) = Kea::start(api_server.local_http_addr(), None)?;
    socket.set_read_timeout(Some(READ_TIMEOUT))?;

    let pkt = {
        let mut msg = DHCPFactory::discover(1);
        msg.set_xid(0);
        DHCPFactory::encode(msg)?
    };

    let msg = recv_offer(&socket, &pkt)?;
    let wanted_location = "http://127.0.0.1:8080/public/blobs/internal/x86_64/ipxe.efi"
        .to_string()
        .into_bytes();

    match msg.opts().get(v4::OptionCode::BootfileName) {
        Some(v4::DhcpOption::BootfileName(location)) => {
            assert_eq!(
                String::from_utf8(location.clone()).unwrap(),
                String::from_utf8(wanted_location).unwrap()
            );
        }
        _ => panic!("DHCP server did not return a filename DHCP option"),
    };

    assert_eq!(msg.opts().msg_type().unwrap(), v4::MessageType::Offer);

    // MTU should match what we send in mock_api_server.rs base_dhcp_response
    let Some(mtu_opt) = msg.opts().get(v4::OptionCode::InterfaceMtu) else {
        panic!("DHCP Option 26 'interface-mtu' missing from Offer");
    };
    assert!(matches!(mtu_opt, v4::DhcpOption::InterfaceMtu(1490)));

    Ok(())
}

#[test]
fn test_booturl_from_api() -> Result<(), eyre::Report> {
    // Start multi-threaded mock API server. The hooks call this over the network.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let api_server = rt.block_on(mock_api_server::MockAPIServer::start());

    let (_kea, socket) = Kea::start(api_server.local_http_addr(), None)?;
    socket.set_read_timeout(Some(READ_TIMEOUT))?;

    let pkt = {
        let mut msg = DHCPFactory::discover(0xAA);
        msg.set_xid(0);
        DHCPFactory::encode(msg)?
    };

    let msg = recv_offer(&socket, &pkt)?;

    let wanted_location =
        "https://api-specified-ipxe-url.forge/public/blobs/internal/x86_64/ipxe.efi"
            .to_string()
            .into_bytes();

    match msg.opts().get(v4::OptionCode::BootfileName) {
        Some(v4::DhcpOption::BootfileName(location)) => {
            assert_eq!(
                String::from_utf8(location.clone()).unwrap(),
                String::from_utf8(wanted_location).unwrap()
            );
        }
        _ => panic!("DHCP server did not return a filename DHCP option"),
    };

    assert_eq!(msg.opts().msg_type().unwrap(), v4::MessageType::Offer);

    Ok(())
}
