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
use std::net::SocketAddrV4;

use clap::{Parser, ValueEnum};

#[derive(Parser, Debug, Clone)]
#[clap(name = "forge-dhcp-server")]
#[clap(author = "Slack channel #swngc-forge-dev")]
pub struct Args {
    #[arg(long, help = "Interface name where to bind this server.")]
    pub interfaces: Vec<String>,

    #[arg(
        long,
        help = "UDP address where the DHCP server listens.",
        default_value = "0.0.0.0:67"
    )]
    pub listen_addr: SocketAddrV4,

    #[arg(
        long,
        help = "UDP destination port for responses to DHCP relays.",
        default_value_t = 67
    )]
    pub relay_response_port: u16,

    #[arg(
        long,
        help = "DHCP Config file path.",
        default_value = "/var/support/forge-dhcp/conf/dhcp.yaml"
    )]
    pub dhcp_config: String,

    #[arg(
        long,
        help = "DPU Agent provided input file path for IP selection. Defaults to \
                /var/support/forge-dhcp/conf/host.yaml when --grpc-listen-addr is set."
    )]
    pub host_config: Option<String>,

    #[arg(short, long, value_enum, default_value_t=ServerMode::Dpu)]
    pub mode: ServerMode,

    #[arg(
        long,
        help = "gRPC server listen address for config hot-reload (e.g. 0.0.0.0:50051). \
                When omitted the gRPC server is not started and config reload is disabled."
    )]
    pub grpc_listen_addr: Option<String>,

    #[arg(
        long,
        help = "HTTP listen address for the metrics/health endpoint (e.g. 0.0.0.0:9090). \
                When omitted the endpoint is not served; metrics are still collected."
    )]
    pub metrics_listen_addr: Option<String>,
}

#[derive(ValueEnum, Clone, Debug)]
pub enum ServerMode {
    Dpu,
    Controller,
}

impl Args {
    pub fn load() -> Self {
        Self::parse()
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddrV4};

    use clap::Parser;

    use super::Args;

    #[test]
    fn dhcp_port_arguments() {
        let defaults = Args::try_parse_from(["forge-dhcp-server"]).unwrap();
        assert_eq!(
            defaults.listen_addr,
            SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 67)
        );
        assert_eq!(defaults.relay_response_port, 67);

        let overridden = Args::try_parse_from([
            "forge-dhcp-server",
            "--listen-addr",
            "127.0.0.1:6767",
            "--relay-response-port",
            "6768",
        ])
        .unwrap();
        assert_eq!(
            overridden.listen_addr,
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, 6767)
        );
        assert_eq!(overridden.relay_response_port, 6768);

        assert!(
            Args::try_parse_from(["forge-dhcp-server", "--listen-addr", "[::]:6767",]).is_err()
        );
    }
}
