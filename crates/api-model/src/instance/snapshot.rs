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

use ::rpc::errors::RpcDataConversionError;
use carbide_uuid::instance::InstanceId;
use carbide_uuid::instance_type::InstanceTypeId;
use carbide_uuid::machine::MachineId;
use carbide_uuid::network_security_group::NetworkSecurityGroupId;
use chrono::{DateTime, Utc};
use config_version::{ConfigVersion, Versioned};
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgRow;
use sqlx::{FromRow, Row};

use super::config::network::{InstanceNetworkConfig, InstanceNetworkConfigUpdate};
use crate::instance::config::InstanceConfig;
use crate::instance::config::extension_services::InstanceExtensionServicesConfig;
use crate::instance::config::infiniband::InstanceInfinibandConfig;
use crate::instance::config::nvlink::InstanceNvLinkConfig;
use crate::instance::config::tenant_config::TenantConfig;
use crate::instance::status::{InstanceStatus, InstanceStatusObservations};
use crate::machine::infiniband::MachineInfinibandStatusObservation;
use crate::machine::nvlink::MachineNvLinkStatusObservation;
use crate::machine::{ManagedHostState, ReprovisionRequest};
use crate::metadata::Metadata;
use crate::os::{InlineIpxe, OperatingSystem, OperatingSystemVariant};
use crate::tenant::TenantOrganizationId;

/// Represents a snapshot view of an `Instance`
///
/// This snapshot is a state-in-time representation of everything that
/// carbide knows about an instance.
/// In order to provide a tenant accurate state of an instance, the state of the
/// host that is hosting the instance also needs to be known.
#[derive(Debug, Clone)]
pub struct InstanceSnapshot {
    /// Instance ID
    pub id: InstanceId,
    /// Machine ID
    pub machine_id: MachineId,

    /// InstanceType ID
    pub instance_type_id: Option<InstanceTypeId>,

    /// Instance Metadata
    pub metadata: Metadata,

    /// Instance configuration. This represents the desired status of the Instance
    /// The Instance might not yet be in that state, but work would be underway
    /// to get the Instance into this state
    pub config: InstanceConfig,
    /// Current version of all instance configurations except the networking related ones
    pub config_version: ConfigVersion,

    /// Current version of the networking configuration that is stored as part
    /// of [InstanceConfig::network]
    pub network_config_version: ConfigVersion,

    /// Current version of the infiniband configuration that is stored as part
    /// of [InstanceConfig::infiniband]
    pub ib_config_version: ConfigVersion,

    pub storage_config_version: ConfigVersion,

    /// Current version of the extension services configuration that is stored as part
    /// of [InstanceConfig::extension_services]
    pub extension_services_config_version: ConfigVersion,

    pub nvlink_config_version: ConfigVersion,

    /// Observed status of the instance
    pub observations: InstanceStatusObservations,

    /// Whether the next boot attempt should run the tenants iPXE script.
    /// This flag is checked by the iPXE handler to determine whether to serve
    /// the tenant's custom script or exit instructions.
    pub use_custom_pxe_on_boot: bool,

    /// Whether a custom PXE reboot has been requested via the API.
    /// This flag is set by the API when a tenant requests a reboot with custom iPXE.
    /// The Ready handler checks this to initiate the HostPlatformConfiguration flow.
    /// The WaitingForRebootToReady handler clears this flag.
    pub custom_pxe_reboot_requested: bool,

    /// The timestamp when deletion for this instance was requested
    pub deleted: Option<chrono::DateTime<chrono::Utc>>,

    /// Update instance network config request.
    pub update_network_config_request: Option<InstanceNetworkConfigUpdate>,
    // There are columns for these but they're unused as of today.
    // pub(crate) requested: chrono::DateTime<chrono::Utc>,
    // pub(crate) started: chrono::DateTime<chrono::Utc>,
    // pub(crate) finished: Option<chrono::DateTime<chrono::Utc>>,
}

impl InstanceSnapshot {
    /// Derives the tenant and site-admin facing [`InstanceStatus`] from the
    /// snapshot information about the instance
    pub fn derive_status(
        &self,
        dpu_id_to_device_map: HashMap<String, Vec<MachineId>>,
        managed_host_state: ManagedHostState,
        reprovision_request: Option<ReprovisionRequest>,
        ib_status: Option<&MachineInfinibandStatusObservation>,
        nvlink_status: Option<&MachineNvLinkStatusObservation>,
    ) -> Result<InstanceStatus, RpcDataConversionError> {
        InstanceStatus::from_config_and_observation(
            dpu_id_to_device_map,
            Versioned::new(&self.config, self.config_version),
            Versioned::new(&self.config.network, self.network_config_version),
            Versioned::new(&self.config.infiniband, self.ib_config_version),
            Versioned::new(
                &self.config.extension_services,
                self.extension_services_config_version,
            ),
            Versioned::new(&self.config.nvlink, self.nvlink_config_version),
            &self.observations,
            managed_host_state,
            self.deleted.is_some(),
            reprovision_request,
            ib_status,
            nvlink_status,
            self.update_network_config_request.is_some(),
        )
    }
}

/// This represents the structure of an instance we get from postgres via the row_to_json or
/// JSONB_AGG functions. Its fields need to match the column names of the instances table exactly.
/// It's expected that we read this directly from the JSON returned by the query, and then
/// convert it into an InstanceSnapshot.
#[derive(Serialize, Deserialize)]
pub struct InstanceSnapshotPgJson {
    id: InstanceId,
    machine_id: MachineId,
    name: String,
    description: String,
    labels: HashMap<String, String>,
    network_config: InstanceNetworkConfig,
    network_config_version: String,
    ib_config: InstanceInfinibandConfig,
    ib_config_version: String,
    storage_config_version: String,
    nvlink_config: InstanceNvLinkConfig,
    nvlink_config_version: String,
    config_version: String,
    phone_home_last_contact: Option<DateTime<Utc>>,
    use_custom_pxe_on_boot: bool,
    #[serde(default)]
    custom_pxe_reboot_requested: bool,
    tenant_org: Option<String>,
    keyset_ids: Vec<String>,
    hostname: Option<String>,
    os_user_data: Option<String>,
    os_ipxe_script: String,
    os_always_boot_with_ipxe: bool,
    os_phone_home_enabled: bool,
    os_image_id: Option<uuid::Uuid>,
    instance_type_id: Option<InstanceTypeId>,
    network_security_group_id: Option<NetworkSecurityGroupId>,
    extension_services_config: InstanceExtensionServicesConfig,
    extension_services_config_version: String,
    requested: DateTime<Utc>,
    started: DateTime<Utc>,
    finished: Option<DateTime<Utc>>,
    deleted: Option<DateTime<Utc>>,
    update_network_config_request: Option<InstanceNetworkConfigUpdate>,
}

impl<'r> FromRow<'r, PgRow> for InstanceSnapshot {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let json: serde_json::value::Value = row.try_get(0)?;
        InstanceSnapshotPgJson::deserialize(json)
            .map_err(|err| sqlx::Error::Decode(err.into()))?
            .try_into()
    }
}

impl TryFrom<InstanceSnapshotPgJson> for InstanceSnapshot {
    type Error = sqlx::Error;

    fn try_from(value: InstanceSnapshotPgJson) -> Result<Self, Self::Error> {
        let metadata = Metadata {
            name: value.name,
            description: value.description,
            labels: value.labels,
        };

        let tenant_organization_id =
            TenantOrganizationId::try_from(value.tenant_org.unwrap_or_default())
                .map_err(|e| sqlx::Error::Decode(Box::new(e)))?;

        let os = OperatingSystem {
            variant: match value.os_image_id {
                Some(x) => OperatingSystemVariant::OsImage(x),
                None => OperatingSystemVariant::Ipxe(InlineIpxe {
                    ipxe_script: value.os_ipxe_script,
                }),
            },
            run_provisioning_instructions_on_every_boot: value.os_always_boot_with_ipxe,
            phone_home_enabled: value.os_phone_home_enabled,
            user_data: value.os_user_data,
        };

        let config = InstanceConfig {
            tenant: TenantConfig {
                tenant_organization_id,
                tenant_keyset_ids: value.keyset_ids,
                hostname: value.hostname,
            },
            os,
            network: value.network_config,
            infiniband: value.ib_config,
            nvlink: value.nvlink_config,
            network_security_group_id: value.network_security_group_id,
            extension_services: value.extension_services_config,
        };

        Ok(InstanceSnapshot {
            id: value.id,
            machine_id: value.machine_id,
            instance_type_id: value.instance_type_id,
            metadata,
            config,
            config_version: value.config_version.parse().map_err(|e| {
                sqlx::error::Error::ColumnDecode {
                    index: "config_version".to_string(),
                    source: Box::new(e),
                }
            })?,
            network_config_version: value.network_config_version.parse().map_err(|e| {
                sqlx::error::Error::ColumnDecode {
                    index: "network_config_version".to_string(),
                    source: Box::new(e),
                }
            })?,
            ib_config_version: value.ib_config_version.parse().map_err(|e| {
                sqlx::error::Error::ColumnDecode {
                    index: "ib_config_version".to_string(),
                    source: Box::new(e),
                }
            })?,
            nvlink_config_version: value.nvlink_config_version.parse().map_err(|e| {
                sqlx::error::Error::ColumnDecode {
                    index: "nvl_config_version".to_string(),
                    source: Box::new(e),
                }
            })?,
            storage_config_version: value.storage_config_version.parse().map_err(|e| {
                sqlx::error::Error::ColumnDecode {
                    index: "storage_config_version".to_string(),
                    source: Box::new(e),
                }
            })?,
            extension_services_config_version: value
                .extension_services_config_version
                .parse()
                .map_err(|e| sqlx::error::Error::ColumnDecode {
                    index: "extension_services_config_version".to_string(),
                    source: Box::new(e),
                })?,
            observations: InstanceStatusObservations {
                network: HashMap::default(),
                extension_services: HashMap::default(),
                phone_home_last_contact: value.phone_home_last_contact,
            },
            use_custom_pxe_on_boot: value.use_custom_pxe_on_boot,
            custom_pxe_reboot_requested: value.custom_pxe_reboot_requested,
            deleted: value.deleted,
            update_network_config_request: value.update_network_config_request,
            // Unused as of today
            // requested: value.requested,
            // started: value.started,
            // finished: value.finished,
        })
    }
}
