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

//! Generates the in-process stub Forge server the nicoapi probe tests run
//! against. The probe itself uses the `carbide-rpc` crate's client and proto
//! types; only the *server* side is generated here, from a copy of
//! `forge.proto` filtered down to the probed RPCs so the stub does not need
//! hundreds of unimplemented methods (the ssh-console-mock-api-server
//! pattern). Everything lands in OUT_DIR — no generated code is committed.

use std::error::Error;
use std::path::PathBuf;
use std::{env, fs};

/// The RPCs the probe exercises — the only ones the stub server implements.
static KEEP_RPCS: &[&str] = &["FindMachineIds", "FindMachinesByIds"];

static RPC_PROTO_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../rpc/proto");

fn main() -> Result<(), Box<dyn Error>> {
    println!("cargo:rerun-if-changed=../rpc/proto");

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is set by cargo"));
    let proto_dir = out_dir.join("proto");
    fs::create_dir_all(&proto_dir)?;
    let filtered_forge = proto_dir.join("forge.proto");
    fs::write(&filtered_forge, filtered_forge_proto()?)?;

    tonic_prost_build::configure()
        .build_server(true)
        .build_client(false) // the probe uses the rpc crate's client
        .protoc_arg("--experimental_allow_proto3_optional")
        .compile_protos(
            &[filtered_forge],
            &[proto_dir, PathBuf::from(RPC_PROTO_DIR)],
        )?;

    Ok(())
}

/// `forge.proto` with every RPC except [`KEEP_RPCS`] removed. Message
/// definitions and imports are untouched; imports resolve against the rpc
/// crate's proto directory.
fn filtered_forge_proto() -> std::io::Result<String> {
    let source = fs::read_to_string(PathBuf::from(RPC_PROTO_DIR).join("forge.proto"))?;
    let mut in_rpc_section = false;
    Ok(source
        .lines()
        .filter(|line| match in_rpc_section {
            false => {
                if line.contains("service Forge {") {
                    in_rpc_section = true;
                }
                true
            }
            true => {
                if *line == "}" {
                    in_rpc_section = false;
                    true
                } else {
                    KEEP_RPCS
                        .iter()
                        .any(|keep_rpc| line.contains(&format!("rpc {keep_rpc}(")))
                }
            }
        })
        .collect::<Vec<_>>()
        .join("\n"))
}
