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

use dhcp::mock_api_server;
use dhcproto::v6;

mod common;

use common::{DHCPv6Factory, Kea6};

const READ_TIMEOUT: Duration = Duration::from_millis(500);

fn send_and_recv(socket: &UdpSocket, packet: Vec<u8>) -> Option<v6::Message> {
    socket.send(&packet).unwrap();
    let mut buf = [0u8; 1500];
    let n = socket.recv(&mut buf).ok()?;
    Some(DHCPv6Factory::decode_reply(&buf[..n]).unwrap())
}

#[test]
fn rapid_commit_option_is_ignored_while_hook_param_is_off() -> Result<(), eyre::Report> {
    // Start Kea with hook-rapid-commit-v6=false from the v6 harness config.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let api_server = rt.block_on(mock_api_server::MockAPIServer::start());
    let (_kea, socket) = Kea6::start(api_server.local_http_addr(), None)?;
    socket.set_read_timeout(Some(READ_TIMEOUT))?;

    // Rapid-commit is deferred, so SOLICIT still gets ADVERTISE instead of REPLY.
    let response = send_and_recv(&socket, DHCPv6Factory::rapid_commit_solicit(0x40))
        .expect("kea did not respond to rapid-commit SOLICIT");
    assert_eq!(response.msg_type(), v6::MessageType::Advertise);

    Ok(())
}
