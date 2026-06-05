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

use carbide_uuid::rack::RackId;
use forge_secrets::credentials::CredentialKey;
use model::rack_type::{RackHardwareType, RackProfile};

pub const ANY_RACK_HARDWARE_TYPE: &str = "any";

pub fn hardware_type_wire_value(value: Option<&RackHardwareType>) -> String {
    value.map(|value| value.0.clone()).unwrap_or_default()
}

pub fn profile_hardware_type_wire_value(profile: &RackProfile) -> String {
    hardware_type_wire_value(profile.rack_hardware_type.as_ref())
}

pub fn rack_maintenance_access_token_key(rack_id: &RackId) -> CredentialKey {
    CredentialKey::RackMaintenanceAccessToken {
        rack_id: rack_id.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_rack_hardware_type_serializes_empty() {
        assert_eq!(hardware_type_wire_value(None), "");
    }
}
