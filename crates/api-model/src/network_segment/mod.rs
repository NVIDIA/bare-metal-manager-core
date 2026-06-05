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
use std::fmt;
use std::str::FromStr;

use carbide_uuid::domain::DomainId;
use carbide_uuid::network::NetworkSegmentId;
use carbide_uuid::vpc::VpcId;
use chrono::{DateTime, Utc};
use config_version::{ConfigVersion, Versioned};
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgRow;
use sqlx::{Column, FromRow, Row};

use crate::StateSla;
use crate::controller_outcome::PersistentStateHandlerOutcome;
use crate::errors::ModelError;
use crate::network_prefix::{NetworkPrefix, NewNetworkPrefix};
use crate::state_history::StateHistoryRecord;

mod slas;

#[derive(Clone, Debug, Default)]
pub struct NetworkSegmentSearchFilter {
    pub name: Option<String>,
    pub tenant_org_id: Option<String>,
}

/// State of a network segment as tracked by the controller
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum NetworkSegmentControllerState {
    Provisioning,
    /// The network segment is ready. Instances can be created
    Ready,
    /// The network segment is in the process of being deleted.
    Deleting {
        deletion_state: NetworkSegmentDeletionState,
    },
}

/// Possible states during deletion of a network segment
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum NetworkSegmentDeletionState {
    /// The segment is waiting until all IPs that had been allocated on the segment
    /// have been released - plus an additional grace period to avoid any race
    /// conditions.
    DrainAllocatedIps {
        /// Denotes the time at which the network segment will be deleted,
        /// assuming no IPs are detected to be in use until then.
        delete_at: DateTime<Utc>,
    },
    /// In this state we release the VNI and VLAN ID allocations and delete the segment from the
    /// database. This is the final state.
    DBDelete,
}

// How we specifiy a network segment in the config file
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
pub struct NetworkDefinition {
    #[serde(rename = "type")]
    pub segment_type: NetworkDefinitionSegmentType,
    /// CIDR notation
    pub prefix: String,
    /// Usually the first IP in the prefix range
    pub gateway: String,
    /// Typically 9000 for admin network, 1500 for underlay
    pub mtu: i32,
    /// How many addresses to skip before allocating
    pub reserve_first: i32,
    /// Controls whether DHCP allocates IPs dynamically from the pool
    /// for this specific network (with the ability to have per-IP static
    /// reservations), or ONLY serves pre-configured static reservations.
    ///
    /// Defaults to dynamic if not specified, which is the traditional
    /// behavior of Carbide + carbide-dhcp.
    #[serde(default)]
    pub allocation_strategy: AllocationStrategy,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum NetworkDefinitionSegmentType {
    Admin,
    Underlay,
    HostInband,
    // Tenant networks are created via the API, not the config file
}

/// Returns the SLA for the current state
pub fn state_sla(state: &NetworkSegmentControllerState, state_version: &ConfigVersion) -> StateSla {
    let time_in_state = chrono::Utc::now()
        .signed_duration_since(state_version.timestamp())
        .to_std()
        .unwrap_or(std::time::Duration::from_secs(60 * 60 * 24));
    match state {
        NetworkSegmentControllerState::Provisioning => {
            StateSla::with_sla(slas::PROVISIONING, time_in_state)
        }
        NetworkSegmentControllerState::Ready => StateSla::no_sla(),
        NetworkSegmentControllerState::Deleting {
            deletion_state: NetworkSegmentDeletionState::DrainAllocatedIps { .. },
        } => {
            // Draining can take an indefinite time if the subnet is referenced
            // by an instance
            StateSla::no_sla()
        }
        NetworkSegmentControllerState::Deleting {
            deletion_state: NetworkSegmentDeletionState::DBDelete,
        } => StateSla::with_sla(slas::DELETING_DBDELETE, time_in_state),
    }
}

#[derive(Debug, Copy, Clone, Default)]
pub struct NetworkSegmentSearchConfig {
    pub include_history: bool,
    pub include_num_free_ips: bool,
}

/// User-controlled configuration for a network segment.
#[derive(Debug, Clone)]
pub struct NetworkSegmentConfig {
    pub name: String,
    pub subdomain_id: Option<DomainId>,
    pub mtu: i32,
    pub segment_type: NetworkSegmentType,
    pub allocation_strategy: AllocationStrategy,
    pub vpc_id: Option<VpcId>,
}

/// System-observed status for a network segment.
#[derive(Debug, Clone)]
pub struct NetworkSegmentStatus {
    pub controller_state: Versioned<NetworkSegmentControllerState>,
    /// The result of the last attempt to change state
    pub controller_state_outcome: Option<PersistentStateHandlerOutcome>,
    /// History of state changes.
    pub history: Vec<StateHistoryRecord>,
    pub vlan_id: Option<i16>, // vlan_id are [0-4096) range, enforced via DB constraint
    pub vni: Option<i32>,
    pub can_stretch: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct NetworkSegment {
    pub id: NetworkSegmentId,
    pub version: ConfigVersion,
    pub config: NetworkSegmentConfig,
    pub status: NetworkSegmentStatus,

    /// Prefixes are kept top-level because each NetworkPrefix contains both
    /// user-specified fields (CIDR, gateway, reserve_first) and system-populated
    /// fields (id, svi_ip, free_ip_count).
    pub prefixes: Vec<NetworkPrefix>,

    pub created: DateTime<Utc>,
    pub updated: DateTime<Utc>,
    pub deleted: Option<DateTime<Utc>>,
}

impl NetworkSegment {
    /// Returns whether the segment was deleted by the user
    pub fn is_marked_as_deleted(&self) -> bool {
        self.deleted.is_some()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::Type, Serialize, Deserialize)]
#[sqlx(rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "network_segment_type_t")]
pub enum NetworkSegmentType {
    Tenant = 0,
    Admin,
    Underlay,
    HostInband,
}

impl NetworkSegmentType {
    pub fn is_tenant(&self) -> bool {
        matches!(
            self,
            NetworkSegmentType::Tenant | NetworkSegmentType::HostInband
        )
    }
}

/// Controls how IP addresses are assigned via DHCP on a network segment,
/// giving us support for segment-wide dynamic DHCP allocations or static
/// DHCP leases/reservations. It is worth noting that even if the entire
/// network segment is configured as `Dynamic`, an operator can still
/// do per-IP static reservation overrides within that segment.
///
/// - `Dynamic`: The DHCP allocator hands out IPs from the pool (default).
/// - `Reserved`: Only pre-existing static reservations are served.
///
/// Devices without a reservation get no DHCP response.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, sqlx::Type, Serialize, Deserialize)]
#[sqlx(type_name = "text", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum AllocationStrategy {
    #[default]
    Dynamic,
    Reserved,
}

#[derive(Debug)]
pub struct NewNetworkSegment {
    pub id: NetworkSegmentId,
    pub name: String,
    pub subdomain_id: Option<DomainId>,
    pub vpc_id: Option<VpcId>,
    pub mtu: i32,
    pub prefixes: Vec<NewNetworkPrefix>,
    pub vlan_id: Option<i16>,
    pub vni: Option<i32>,
    pub segment_type: NetworkSegmentType,
    pub can_stretch: Option<bool>,
    pub allocation_strategy: AllocationStrategy,
}

impl FromStr for NetworkSegmentType {
    type Err = ModelError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "tenant" => NetworkSegmentType::Tenant,
            "admin" => NetworkSegmentType::Admin,
            "tor" => NetworkSegmentType::Underlay,
            "host_inband" => NetworkSegmentType::HostInband,
            _ => {
                return Err(ModelError::DatabaseTypeConversionError(format!(
                    "Invalid segment type {s} reveived from Database."
                )));
            }
        })
    }
}

impl fmt::Display for NetworkSegmentType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tenant => write!(f, "tenant"),
            Self::Admin => write!(f, "admin"),
            Self::Underlay => write!(f, "tor"),
            Self::HostInband => write!(f, "host_inband"),
        }
    }
}

// We need to implement FromRow because we can't associate dependent tables with the default derive
// (i.e. it can't default unknown fields)
impl<'r> FromRow<'r, PgRow> for NetworkSegment {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let controller_state: sqlx::types::Json<NetworkSegmentControllerState> =
            row.try_get("controller_state")?;
        let state_outcome: Option<sqlx::types::Json<PersistentStateHandlerOutcome>> =
            row.try_get("controller_state_outcome")?;

        let prefixes_json: sqlx::types::Json<Vec<Option<NetworkPrefix>>> =
            row.try_get("prefixes")?;
        let prefixes = prefixes_json.0.into_iter().flatten().collect();

        let history = if let Some(column) = row.columns().iter().find(|c| c.name() == "history") {
            let value: sqlx::types::Json<Vec<Option<StateHistoryRecord>>> =
                row.try_get(column.ordinal())?;
            value.0.into_iter().flatten().collect()
        } else {
            Vec::new()
        };

        Ok(NetworkSegment {
            id: row.try_get("id")?,
            version: row.try_get("version")?,
            config: NetworkSegmentConfig {
                name: row.try_get("name")?,
                subdomain_id: row.try_get("subdomain_id")?,
                mtu: row.try_get("mtu")?,
                segment_type: row.try_get("network_segment_type")?,
                allocation_strategy: row.try_get("allocation_strategy").unwrap_or_default(),
                vpc_id: row.try_get("vpc_id")?,
            },
            status: NetworkSegmentStatus {
                controller_state: Versioned::new(
                    controller_state.0,
                    row.try_get("controller_state_version")?,
                ),
                controller_state_outcome: state_outcome.map(|x| x.0),
                history,
                vlan_id: row.try_get("vlan_id").unwrap_or_default(),
                vni: row.try_get("vni_id").unwrap_or_default(),
                can_stretch: row.try_get("can_stretch")?,
            },
            prefixes,
            created: row.try_get("created")?,
            updated: row.try_get("updated")?,
            deleted: row.try_get("deleted")?,
        })
    }
}

impl NewNetworkSegment {
    pub fn build_from(
        name: &str,
        domain_id: DomainId,
        value: &NetworkDefinition,
    ) -> Result<Self, ModelError> {
        let prefix = NewNetworkPrefix {
            prefix: value.prefix.parse().map_err(|_| {
                ModelError::InvalidArgument(format!("Invalid network prefix: {}", value.prefix))
            })?,
            gateway: Some(value.gateway.parse().map_err(|_| {
                ModelError::InvalidArgument(format!("Invalid gateway address: {}", value.gateway))
            })?),
            num_reserved: value.reserve_first,
        };
        Ok(NewNetworkSegment {
            id: uuid::Uuid::new_v4().into(),
            name: name.to_string(), // Set by the caller later
            subdomain_id: Some(domain_id),
            vpc_id: None,
            mtu: value.mtu,
            prefixes: vec![prefix],
            vlan_id: None,
            vni: None,
            segment_type: match value.segment_type {
                NetworkDefinitionSegmentType::Admin => NetworkSegmentType::Admin,
                NetworkDefinitionSegmentType::Underlay => NetworkSegmentType::Underlay,
                NetworkDefinitionSegmentType::HostInband => NetworkSegmentType::HostInband,
            },
            can_stretch: None,
            allocation_strategy: value.allocation_strategy,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_controller_state() {
        let state = NetworkSegmentControllerState::Provisioning {};
        let serialized = serde_json::to_string(&state).unwrap();
        assert_eq!(serialized, "{\"state\":\"provisioning\"}");
        assert_eq!(
            serde_json::from_str::<NetworkSegmentControllerState>(&serialized).unwrap(),
            state
        );

        let state = NetworkSegmentControllerState::Ready {};
        let serialized = serde_json::to_string(&state).unwrap();
        assert_eq!(serialized, "{\"state\":\"ready\"}");
        assert_eq!(
            serde_json::from_str::<NetworkSegmentControllerState>(&serialized).unwrap(),
            state
        );

        let deletion_time: DateTime<Utc> = "2022-12-13T04:41:38Z".parse().unwrap();
        let state = NetworkSegmentControllerState::Deleting {
            deletion_state: NetworkSegmentDeletionState::DrainAllocatedIps {
                delete_at: deletion_time,
            },
        };
        let serialized = serde_json::to_string(&state).unwrap();
        assert_eq!(
            serialized,
            "{\"state\":\"deleting\",\"deletion_state\":{\"state\":\"drainallocatedips\",\"delete_at\":\"2022-12-13T04:41:38Z\"}}"
        );
        assert_eq!(
            serde_json::from_str::<NetworkSegmentControllerState>(&serialized).unwrap(),
            state
        );
    }
}
