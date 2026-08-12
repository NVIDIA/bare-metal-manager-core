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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    carbide_version::build();
    tonic_prost_build::configure()
        .build_server(false)
        .build_client(true)
        .compile_protos(
            &["../dhcp-server/proto/dhcp_server_control.proto"],
            &["../dhcp-server/proto"],
        )?;

    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&["proto/weave_ew_vpc.proto"], &["proto", "/usr/include"])?;

    // The agent owns and serves AgentLocal (issue #355) on its local unix
    // socket. Only the server is built here; `carbide-rpc` compiles the same
    // file for the client its `SocketTokenSource` needs, the way this crate
    // compiles dhcp-server's proto above.
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(false)
        .compile_protos(&["proto/agent_local.proto"], &["proto"])?;

    Ok(())
}
