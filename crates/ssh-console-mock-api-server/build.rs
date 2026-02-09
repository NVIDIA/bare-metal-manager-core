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
use std::path::PathBuf;
use std::{fs, io};

// RPC methods mocked by ssh-console-mock-api-server. We don't implement all of forge.proto because
// we would need an unreasonably large number of stub functions.
static KEEP_RPCS: &[&str] = &[
    "Version",
    "ValidateTenantPublicKey",
    "FindInstancesByIds",
    "FindMachineIds",
    "FindMachinesByIds",
    "GetBMCMetaData",
];

static RPC_CRATE_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../rpc");

fn main() -> Result<(), Box<dyn std::error::Error>> {
    carbide_version::build();

    // Copy protos from the rpc crate first
    copy_protos_from_rpc_crate()?;
    println!("cargo:rerun-if-changed=../rpc/proto");

    // Then codegen them.
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(false) // we're using ForgeApiClient from rpc crate
        .extern_path(".common.MachineId", "::carbide_uuid::machine::MachineId")
        .extern_path(".common.RackId", "::carbide_uuid::rack::RackId")
        .protoc_arg("--experimental_allow_proto3_optional")
        .out_dir("src/generated")
        .compile_protos(
            &[
                "proto/common.proto",
                "proto/dns.proto",
                "proto/forge.proto",
                "proto/machine_discovery.proto",
                "proto/site_explorer.proto",
            ],
            &["proto"],
        )?;

    Ok(())
}

/// Take protos from the rpc crate, but omit all RPC methods except the ones we're mocking (so that
/// we don't have to stub out hundreds of methods.)
fn copy_protos_from_rpc_crate() -> io::Result<()> {
    let rpc_crate_path = PathBuf::from(RPC_CRATE_DIR).canonicalize()?;
    let this_crate_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).canonicalize()?;

    for source_proto in fs::read_dir(rpc_crate_path.join("proto"))? {
        let source_proto = source_proto?;
        let source = match source_proto.file_name().to_str() {
            Some("forge.proto") => {
                let mut in_rpc_section = false;
                fs::read_to_string(source_proto.path())?
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
                    .join("\n")
            }
            Some(fname) if fname.ends_with(".proto") => fs::read_to_string(source_proto.path())?,
            _ => continue,
        };

        let dest_path = this_crate_path.join("proto").join(source_proto.file_name());
        let do_rewrite = match fs::read_to_string(&dest_path) {
            Err(_) => true,
            // Don't write it unless it changed, we don't want to bump timestamps and cause rebuilds
            Ok(contents) => contents != source,
        };

        if do_rewrite {
            fs::write(dest_path, source)?;
        }
    }

    Ok(())
}
