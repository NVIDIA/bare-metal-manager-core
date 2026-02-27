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

use std::collections::HashMap;

use carbide_uuid::rack::RackId;
use mac_address::MacAddress;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct ExpectedMachineJson {
    #[serde(default)]
    pub id: Option<String>,
    pub bmc_mac_address: MacAddress,
    pub bmc_username: String,
    pub bmc_password: String,
    pub chassis_serial_number: String,
    pub fallback_dpu_serial_numbers: Option<Vec<String>>,
    #[serde(default)]
    pub metadata: Option<rpc::forge::Metadata>,
    pub sku_id: Option<String>,
    #[serde(default)]
    pub host_nics: Vec<rpc::forge::ExpectedHostNic>,
    pub rack_id: Option<RackId>,
    pub default_pause_ingestion_and_poweron: Option<bool>,
    pub dpf_enabled: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct _ExpectedMachineMetadata {
    pub name: Option<String>,
    pub description: Option<String>,
    pub labels: HashMap<String, Option<String>>,
}
