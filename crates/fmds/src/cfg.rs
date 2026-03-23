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

use clap::Parser;

#[derive(Parser)]
#[clap(name = "carbide-fmds")]
pub struct Options {
    #[clap(long, default_value = "false", help = "Print version number and exit")]
    pub version: bool,

    /// gRPC listen address for receiving config updates from
    /// carbide-dpu-agent. The tenant should not be able to
    /// communicate with this address.
    #[clap(long, default_value = "0.0.0.0:50052")]
    pub grpc_address: String,

    /// REST listen address for tenant OS metadata queries.
    #[clap(long, default_value = "0.0.0.0:80")]
    pub rest_address: String,

    /// Carbide API server address for phone_home.
    #[clap(long, default_value = "https://carbide-api.forge")]
    pub forge_api: String,

    /// Path to root CA certificate.
    /// This will probably be shared with the carbide-dpu-agent.
    #[clap(long)]
    pub root_ca: Option<String>,

    /// Path to client certificate.
    /// This will probably be shared with the carbide-dpu-agent.
    #[clap(long)]
    pub client_cert: Option<String>,

    /// Path to client key.
    /// This will probably be shared with the carbide-dpu-agent.
    #[clap(long)]
    pub client_key: Option<String>,
}

impl Options {
    pub fn load() -> Self {
        Self::parse()
    }
}
