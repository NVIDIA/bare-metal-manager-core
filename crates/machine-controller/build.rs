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
    let out_dir = PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    tonic_prost_build::configure()
        .out_dir(out_dir)
        .type_attribute(
            "scout_firmware_upgrade.ScoutFirmwareUpgradeTask",
            "#[derive(serde::Serialize, serde::Deserialize)]",
        )
        .type_attribute(
            "scout_firmware_upgrade.FileArtifact",
            "#[derive(serde::Serialize, serde::Deserialize)]",
        )
        .compile_protos(&["scout_firmware_upgrade.proto"], &["../rpc/proto"])?;

    Ok(())
}
