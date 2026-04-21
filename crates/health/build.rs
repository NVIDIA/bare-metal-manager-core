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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    carbide_version::build();

    // vendored from opentelemetry-proto v1.5.0
    let proto_dir = PathBuf::from("proto");

    println!("cargo:rerun-if-changed=proto/");

    tonic_prost_build::configure()
        .build_server(false)
        .build_client(true)
        .compile_protos(
            &[proto_dir.join("opentelemetry/proto/collector/logs/v1/logs_service.proto")],
            &[proto_dir],
        )?;

    Ok(())
}
