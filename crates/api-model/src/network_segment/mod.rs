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
use itertools::Itertools;
use rpc::TenantState;
use rpc::errors::RpcDataConversionError;
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgRow;
use sqlx::{Column, FromRow, Row};

use crate::StateSla;
use crate::controller_outcome::PersistentStateHandlerOutcome;
use crate::errors::ModelError;
use crate::network_prefix::{NetworkPrefix, NewNetworkPrefix};
use crate::network_segment_state_history::NetworkSegmentStateHistory;

mod slas;

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
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum NetworkDefinitionSegmentType {
    Admin,
    Underlay,
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

const DEFAULT_MTU_TENANT: i32 = 9000;
const DEFAULT_MTU_OTHER: i32 = 1500;

#[derive(Debug, Copy, Clone, Default)]
pub struct NetworkSegmentSearchConfig {
    pub include_history: bool,
    pub include_num_free_ips: bool,
}

impl From<rpc::forge::NetworkSegmentSearchConfig> for NetworkSegmentSearchConfig {
    fn from(value: rpc::forge::NetworkSegmentSearchConfig) -> Self {
        NetworkSegmentSearchConfig {
            include_history: value.include_history,
            include_num_free_ips: value.include_num_free_ips,
        }
    }
}

#[derive(Debug, Clone)]
pub struct NetworkSegment {
    pub id: NetworkSegmentId,
    pub version: ConfigVersion,
    pub name: String,
    pub subdomain_id: Option<DomainId>,
    pub vpc_id: Option<VpcId>,
    pub mtu: i32,

    pub controller_state: Versioned<NetworkSegmentControllerState>,

    /// The result of the last attempt to change state
    pub controller_state_outcome: Option<PersistentStateHandlerOutcome>,

    pub created: DateTime<Utc>,
    pub updated: DateTime<Utc>,
    pub deleted: Option<DateTime<Utc>>,

    pub prefixes: Vec<NetworkPrefix>,
    /// History of state changes.
    pub history: Vec<NetworkSegmentStateHistory>,

    pub vlan_id: Option<i16>, // vlan_id are [0-4096) range, enforced via DB constraint
    pub vni: Option<i32>,

    pub segment_type: NetworkSegmentType,

    pub can_stretch: Option<bool>,
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
}

impl TryFrom<i32> for NetworkSegmentType {
    type Error = RpcDataConversionError;
    fn try_from(value: i32) -> Result<Self, Self::Error> {
        Ok(match value {
            x if x == rpc::forge::NetworkSegmentType::Tenant as i32 => NetworkSegmentType::Tenant,
            x if x == rpc::forge::NetworkSegmentType::Admin as i32 => NetworkSegmentType::Admin,
            x if x == rpc::forge::NetworkSegmentType::Underlay as i32 => {
                NetworkSegmentType::Underlay
            }
            x if x == rpc::forge::NetworkSegmentType::HostInband as i32 => {
                NetworkSegmentType::HostInband
            }
            _ => {
                return Err(RpcDataConversionError::InvalidNetworkSegmentType(value));
            }
        })
    }
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
            let value: sqlx::types::Json<Vec<Option<NetworkSegmentStateHistory>>> =
                row.try_get(column.ordinal())?;
            value.0.into_iter().flatten().collect()
        } else {
            Vec::new()
        };

        Ok(NetworkSegment {
            id: row.try_get("id")?,
            version: row.try_get("version")?,
            name: row.try_get("name")?,
            subdomain_id: row.try_get("subdomain_id")?,
            vpc_id: row.try_get("vpc_id")?,
            controller_state: Versioned::new(
                controller_state.0,
                row.try_get("controller_state_version")?,
            ),
            controller_state_outcome: state_outcome.map(|x| x.0),
            created: row.try_get("created")?,
            updated: row.try_get("updated")?,
            deleted: row.try_get("deleted")?,
            mtu: row.try_get("mtu")?,
            prefixes,
            history,
            vlan_id: row.try_get("vlan_id").unwrap_or_default(),
            vni: row.try_get("vni_id").unwrap_or_default(),
            segment_type: row.try_get("network_segment_type")?,
            can_stretch: row.try_get("can_stretch")?,
        })
    }
}

/// Converts from Protobuf NetworkSegmentCreationRequest into NewNetworkSegment
///
/// subdomain_id - Converting from Protobuf UUID(String) to Rust UUID type can fail.
/// Use try_from in order to return a Result where Result is an error if the conversion
/// from String -> UUID fails
///
impl TryFrom<rpc::forge::NetworkSegmentCreationRequest> for NewNetworkSegment {
    type Error = RpcDataConversionError;

    fn try_from(value: rpc::forge::NetworkSegmentCreationRequest) -> Result<Self, Self::Error> {
        if value.prefixes.is_empty() {
            return Err(RpcDataConversionError::InvalidArgument(
                "Prefixes are empty.".to_string(),
            ));
        }

        let prefixes = value
            .prefixes
            .into_iter()
            .map(NewNetworkPrefix::try_from)
            .collect::<Result<Vec<NewNetworkPrefix>, RpcDataConversionError>>()?;

        if prefixes.iter().any(|ip| ip.prefix.ip().is_ipv6()) {
            return Err(RpcDataConversionError::InvalidArgument(
                "IPv6 is not yet supported.".to_string(),
            ));
        }

        let id = value.id.unwrap_or_else(|| uuid::Uuid::new_v4().into());

        let segment_type: NetworkSegmentType = value.segment_type.try_into()?;
        if segment_type == NetworkSegmentType::Tenant
            && prefixes.iter().any(|ip| ip.prefix.prefix() >= 31)
        {
            return Err(RpcDataConversionError::InvalidArgument(
                "Prefix 31 and 32 are not allowed.".to_string(),
            ));
        }

        // This TryFrom implementation is part of the API handler logic for
        // network segment creation, and is not used by FNN. Therefore, the only
        // type of tenant segment we could be creating is a stretchable one.
        let can_stretch = matches!(segment_type, NetworkSegmentType::Tenant).then_some(true);

        Ok(NewNetworkSegment {
            id,
            name: value.name,
            subdomain_id: value.subdomain_id,
            vpc_id: value.vpc_id,
            mtu: value.mtu.unwrap_or(match segment_type {
                NetworkSegmentType::Tenant => DEFAULT_MTU_TENANT,
                _ => DEFAULT_MTU_OTHER,
            }),
            prefixes,
            vlan_id: None,
            vni: None,
            segment_type,
            can_stretch,
        })
    }
}

///
/// Marshal a Data Object (NetworkSegment) into an RPC NetworkSegment
///
/// subdomain_id - Rust UUID -> ProtoBuf UUID(String) cannot fail, so convert it or return None
///
impl TryFrom<NetworkSegment> for rpc::NetworkSegment {
    type Error = RpcDataConversionError;
    fn try_from(src: NetworkSegment) -> Result<Self, Self::Error> {
        // Note that even thought the segment might already be ready,
        // we only return `Ready` after
        // the state machine also noticed that. Otherwise we would need to also
        // allow address allocation before the controller state is ready, which
        // spreads out the state mismatch to a lot more places.
        let mut state = match &src.controller_state.value {
            NetworkSegmentControllerState::Provisioning => TenantState::Provisioning,
            NetworkSegmentControllerState::Ready => TenantState::Ready,
            NetworkSegmentControllerState::Deleting { .. } => TenantState::Terminating,
        };
        // If deletion is requested, we immediately overwrite the state to terminating.
        // Even though the state controller hasn't caught up - it eventually will
        if src.is_marked_as_deleted() {
            state = TenantState::Terminating;
        }

        let mut history = Vec::with_capacity(src.history.len());

        for state in src.history {
            history.push(rpc::forge::NetworkSegmentStateHistory::try_from(state)?);
        }

        let flags: Vec<i32> = {
            use rpc::forge::NetworkSegmentFlag::*;

            let mut flags = vec![];

            let can_stretch = src.can_stretch.unwrap_or_else(|| {
                // If the segment's can_stretch flag is NULL in the database,
                // we're going to have to go off of what an FNN-created
                // segment's prefixes would look like, and then assume any such
                // FNN segment is _not_ stretchable.
                src.prefixes.iter().all(|p| !p.smells_like_fnn())
            });
            if can_stretch {
                flags.push(CanStretch);
            }

            // Just so a gRPC client can tell the difference between a missing
            // `flags` field and an empty one.
            if flags.is_empty() {
                flags.push(NoOp);
            }

            flags.into_iter().map(|flag| flag as i32).collect()
        };

        Ok(rpc::NetworkSegment {
            id: Some(src.id),
            version: src.version.version_string(),
            name: src.name,
            subdomain_id: src.subdomain_id,
            mtu: Some(src.mtu),
            created: Some(src.created.into()),
            updated: Some(src.updated.into()),
            deleted: src.deleted.map(|t| t.into()),
            prefixes: src
                .prefixes
                .into_iter()
                .map(rpc::forge::NetworkPrefix::from)
                .collect_vec(),
            vpc_id: src.vpc_id,
            state: state as i32,
            state_reason: src.controller_state_outcome.map(|r| r.into()),
            state_sla: Some(
                state_sla(&src.controller_state.value, &src.controller_state.version).into(),
            ),
            history,
            segment_type: src.segment_type as i32,
            flags,
        })
    }
}

impl NewNetworkSegment {
    pub fn build_from(
        name: &str,
        domain_id: DomainId,
        value: &NetworkDefinition,
    ) -> Result<Self, RpcDataConversionError> {
        let prefix =
            NewNetworkPrefix {
                prefix: value.prefix.parse()?,
                gateway: Some(value.gateway.parse().map_err(|_| {
                    RpcDataConversionError::InvalidIpAddress(value.gateway.clone())
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
            },
            can_stretch: None,
        })
    }
}
