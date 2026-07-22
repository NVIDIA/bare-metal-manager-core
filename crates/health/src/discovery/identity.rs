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

use std::sync::Arc;

use nv_redfish::ServiceRoot;

use crate::HealthError;
use crate::endpoint::{BmcEndpoint, EndpointMetadata};

struct SystemIdentity {
    id: String,
    uuid: Option<uuid::Uuid>,
    bios_version: Option<String>,
}

fn select_primary_system(systems: &[SystemIdentity]) -> Option<&SystemIdentity> {
    systems
        .iter()
        .find(|system| {
            system
                .bios_version
                .as_deref()
                .is_some_and(|version| !version.trim().is_empty())
        })
        .or_else(|| systems.first())
}

/// Resolves the primary ComputerSystem UUID before collectors start.
///
/// A system with a non-empty BIOS version is preferred because BMCs may expose
/// auxiliary systems alongside the host. This matches the primary-system rule
/// used by Fleet Intelligence inventory; when no system has BIOS metadata, the
/// first collection member is used.
pub(super) async fn with_primary_system_uuid(
    endpoint: &Arc<BmcEndpoint>,
) -> Result<Arc<BmcEndpoint>, HealthError> {
    if !matches!(endpoint.metadata, Some(EndpointMetadata::Machine(_))) {
        return Ok(Arc::clone(endpoint));
    }

    let root = ServiceRoot::new(Arc::clone(endpoint.bmc())).await?;
    let systems = root.systems().await?.ok_or_else(|| {
        HealthError::GenericError(format!(
            "BMC {:?} does not expose a ComputerSystem collection",
            endpoint.addr
        ))
    })?;
    let systems = systems.members().await?;
    let identities: Vec<SystemIdentity> = systems
        .iter()
        .map(|system| {
            let raw = system.raw();
            SystemIdentity {
                id: raw.base.id.clone(),
                uuid: raw.uuid.flatten(),
                bios_version: raw.bios_version.clone().flatten(),
            }
        })
        .collect();
    let primary = select_primary_system(&identities).ok_or_else(|| {
        HealthError::GenericError(format!(
            "BMC {:?} exposes an empty ComputerSystem collection",
            endpoint.addr
        ))
    })?;
    let system_uuid = primary.uuid.ok_or_else(|| {
        HealthError::GenericError(format!(
            "primary ComputerSystem {} on BMC {:?} does not expose a UUID",
            primary.id, endpoint.addr
        ))
    })?;

    let mut enriched = endpoint.as_ref().clone();
    let Some(EndpointMetadata::Machine(machine)) = enriched.metadata.as_mut() else {
        unreachable!("machine endpoint checked above")
    };
    machine.system_uuid = Some(system_uuid);

    Ok(Arc::new(enriched))
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIRST_UUID: uuid::Uuid = uuid::uuid!("11111111-1111-1111-1111-111111111111");
    const BIOS_UUID: uuid::Uuid = uuid::uuid!("22222222-2222-2222-2222-222222222222");

    #[test]
    fn primary_system_prefers_first_system_with_bios() {
        let systems = [
            SystemIdentity {
                id: "auxiliary".to_string(),
                uuid: Some(FIRST_UUID),
                bios_version: None,
            },
            SystemIdentity {
                id: "host".to_string(),
                uuid: Some(BIOS_UUID),
                bios_version: Some("1.2.3".to_string()),
            },
        ];

        let primary = select_primary_system(&systems).expect("primary system");

        assert_eq!(primary.id, "host");
        assert_eq!(primary.uuid, Some(BIOS_UUID));
    }

    #[test]
    fn primary_system_falls_back_to_first_member() {
        let systems = [
            SystemIdentity {
                id: "first".to_string(),
                uuid: Some(FIRST_UUID),
                bios_version: None,
            },
            SystemIdentity {
                id: "second".to_string(),
                uuid: Some(BIOS_UUID),
                bios_version: Some("  ".to_string()),
            },
        ];

        let primary = select_primary_system(&systems).expect("primary system");

        assert_eq!(primary.id, "first");
        assert_eq!(primary.uuid, Some(FIRST_UUID));
    }

    #[test]
    fn primary_system_is_absent_for_empty_collection() {
        assert!(select_primary_system(&[]).is_none());
    }
}
