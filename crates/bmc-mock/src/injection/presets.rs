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

use serde_json::json;

use super::{Action, Rule, Selector};

/// BlueField PCIe devices vanish from the chassis collections (and 404 on direct GET)
/// NetworkAdapter resources report blank vendor strings with no NetworkDeviceFunctions
pub fn all_dpu_lost_on_host() -> Vec<Rule> {
    vec![
        Rule {
            id: "all_dpu_lost__pcie_hide".into(),
            selector: Selector::OdataId("/redfish/v1/Chassis/*/PCIeDevices/Bluefield*".into()),
            action: Action::Status(404),
            remaining: None,
        },
        Rule {
            id: "all_dpu_lost__netadapter_blank".into(),
            selector: Selector::OdataId("/redfish/v1/Chassis/*/NetworkAdapters/Bluefield*".into()),
            action: Action::JsonMerge(json!({
                "Model": "",
                "SerialNumber": "",
                "Manufacturer": "",
                "PartNumber": "",
                "SKU": "",
                "NetworkDeviceFunctions": {
                    "Members": [],
                    "Members@odata.count": 0,
                },
                "Status": { "State": "Enabled", "Health": "OK" }
            })),
            remaining: None,
        },
    ]
}
