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
use rpc::forge::DhcpRecord;
use tokio::net::UdpSocket;

use crate::Config;
use crate::errors::DhcpError;
use crate::vendor_class::{MachineArchitecture, VendorClass};

macro_rules! socket_opr {
    ($socket:expr, $statement:expr, $retry:expr) => {
        if let Err(e) = $statement {
            drop($socket);
            tracing::info!("Socket set option failed. Retry: {}, error: {e}", $retry);
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            continue;
        }
    };
}

pub fn u8_to_mac(data: &[u8]) -> String {
    data.iter()
        .map(|x| format!("{x:x}"))
        .collect::<Vec<String>>()
        .join(":")
}

pub fn u8_to_hex_string(data: &[u8]) -> Result<String, DhcpError> {
    Ok(std::str::from_utf8(data)?.to_string())
}

pub fn machine_get_filename(
    dhcp_response: &DhcpRecord,
    vendor_class: &VendorClass,
    config: &Config,
) -> Vec<u8> {
    // If the API sent us the URL we should boot from, just use it.
    let url = if let Some(url) = &dhcp_response.booturl {
        url.to_string()
    } else {
        if !vendor_class.is_netboot() {
            return vec![];
        }

        let VendorClass { arch, .. } = vendor_class;

        let base_url = config.dhcp_config.carbide_provisioning_server_ipv4;
        match arch {
            MachineArchitecture::EfiX64 => {
                format!("http://{base_url}:8080/public/blobs/internal/x86_64/ipxe.efi")
            }
            MachineArchitecture::Arm64 => {
                format!("http://{base_url}:8080/public/blobs/internal/aarch64/ipxe.efi")
            }
            MachineArchitecture::BiosX86 => {
                tracing::warn!(
                    "Matched an HTTP client on a Legacy BIOS client, cannot provide HTTP boot URL"
                );
                return vec![];
            }
            MachineArchitecture::Unknown => {
                tracing::warn!("Matched an unknown architecture, cannot provide HTTP boot URL",);
                return vec![];
            }
        }
    };

    url.into_bytes().to_vec()
}

/// Create a UDP socket and set non_blocking, broadcast and other options flag on it.
pub async fn get_socket(listen_address: core::net::SocketAddr, interface: String) -> UdpSocket {
    for retry in 0..10 {
        // Create a socket2.socket. std and tokio sockets do not support advance options like
        // reuseaddr to be set.
        let socket = match socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        ) {
            Ok(socket) => socket,
            Err(e) => {
                tracing::info!("Socket creation failed. Retry: {retry}, error: {e}");
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                continue;
            }
        };

        socket_opr!(socket, socket.set_reuse_address(true), retry);
        socket_opr!(socket, socket.set_nonblocking(true), retry);
        socket_opr!(socket, socket.bind(&listen_address.into()), retry);
        // Not for listening, but allowed for sending.
        socket_opr!(socket, socket.set_broadcast(true), retry);

        let mut retries_left = 10;
        while retries_left > 0 && socket.bind_device(Some(interface.as_bytes())).is_err() {
            retries_left -= 1;
            tracing::info!("Interface {interface} not ready, retrying {retries_left} more times");
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }
        if retries_left == 0 {
            panic!("Cannot bind interface {interface}.");
        }

        // Now create tokio UDPSocket from socket2, which has all needed advanced options set.
        return UdpSocket::from_std(socket.into()).unwrap();
    }
    panic!("Could not create socket successfully.");
}
