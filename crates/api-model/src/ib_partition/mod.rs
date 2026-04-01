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
use std::str::FromStr;

use ::rpc::forge as rpc_forge;
use carbide_uuid::infiniband::IBPartitionId;
use chrono::{DateTime, Utc};
use config_version::{ConfigVersion, Versioned};
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgRow;
use sqlx::{FromRow, Row};

use crate::StateSla;
use crate::controller_outcome::PersistentStateHandlerOutcome;
use crate::ib::{IBMtu, IBNetwork, IBQosConf, IBRateLimit, IBServiceLevel};
use crate::metadata::Metadata;
use crate::tenant::TenantOrganizationId;

mod slas;

#[derive(Clone, Debug, Default)]
pub struct IbPartitionSearchFilter {
    pub tenant_org_id: Option<String>,
    pub name: Option<String>,
}

impl From<rpc::forge::IbPartitionSearchFilter> for IbPartitionSearchFilter {
    fn from(filter: rpc::forge::IbPartitionSearchFilter) -> Self {
        IbPartitionSearchFilter {
            tenant_org_id: filter.tenant_org_id,
            name: filter.name,
        }
    }
}

/// Represents an InfiniBand Partition Key
/// Partition Keys are 16 bit values valid up to a value of 0x7fff
/// Partition Keys are serialized as strings, since the hex represenation is
/// their canonical representation.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct PartitionKey(u16);

impl PartitionKey {
    /// Returns the partition key associated with the default partition
    pub const fn for_default_partition() -> Self {
        Self(0x7fff)
    }

    /// Returns whether the partition key describes the default partition
    pub fn is_default_partition(self) -> bool {
        self == Self::for_default_partition()
    }
}

#[derive(thiserror::Error, Debug, Clone)]
#[error("Partition Key \"{0}\" is not valid")]
pub struct InvalidPartitionKeyError(String);

impl serde::Serialize for PartitionKey {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.to_string().serialize(s)
    }
}

impl<'de> serde::Deserialize<'de> for PartitionKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;
        let str_value = String::deserialize(deserializer)?;
        let version =
            PartitionKey::from_str(&str_value).map_err(|err| Error::custom(err.to_string()))?;
        Ok(version)
    }
}

impl TryFrom<u16> for PartitionKey {
    type Error = InvalidPartitionKeyError;

    fn try_from(pkey: u16) -> Result<Self, Self::Error> {
        if pkey != (pkey & 0x7fff) {
            return Err(InvalidPartitionKeyError(pkey.to_string()));
        }

        Ok(PartitionKey(pkey))
    }
}

impl FromStr for PartitionKey {
    type Err = InvalidPartitionKeyError;

    fn from_str(pkey: &str) -> Result<Self, Self::Err> {
        let pkey = pkey.to_lowercase();
        let base = if pkey.starts_with("0x") { 16 } else { 10 };
        let p = pkey.trim_start_matches("0x");
        let k = u16::from_str_radix(p, base);

        match k {
            Ok(v) => Ok(PartitionKey(v)),
            Err(_e) => Err(InvalidPartitionKeyError(pkey.to_string())),
        }
    }
}

impl TryFrom<String> for PartitionKey {
    type Error = InvalidPartitionKeyError;

    fn try_from(pkey: String) -> Result<Self, Self::Error> {
        PartitionKey::from_str(&pkey)
    }
}

impl TryFrom<&String> for PartitionKey {
    type Error = InvalidPartitionKeyError;

    fn try_from(pkey: &String) -> Result<Self, Self::Error> {
        PartitionKey::try_from(pkey.to_string())
    }
}

impl TryFrom<&str> for PartitionKey {
    type Error = InvalidPartitionKeyError;

    fn try_from(pkey: &str) -> Result<Self, Self::Error> {
        PartitionKey::try_from(pkey.to_string())
    }
}

impl std::fmt::Display for PartitionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "0x{:x}", self.0)
    }
}

impl From<PartitionKey> for u16 {
    fn from(v: PartitionKey) -> u16 {
        v.0
    }
}

#[derive(Debug, Clone)]
pub struct NewIBPartition {
    pub id: IBPartitionId,
    pub config: IBPartitionConfig,
    pub metadata: Metadata,
}

impl TryFrom<rpc_forge::IbPartitionCreationRequest> for NewIBPartition {
    type Error = rpc::errors::RpcDataConversionError;
    fn try_from(value: rpc_forge::IbPartitionCreationRequest) -> Result<Self, Self::Error> {
        let conf = value.config.ok_or_else(|| {
            rpc::errors::RpcDataConversionError::InvalidArgument(
                "IBPartition configuration is empty".to_string(),
            )
        })?;

        let id = value.id.unwrap_or(uuid::Uuid::new_v4().into());
        let name = conf.name.clone();

        Ok(NewIBPartition {
            id,
            config: IBPartitionConfig::try_from(conf)?,
            metadata: match value.metadata {
                Some(m) => Metadata::try_from(m)?,
                // Deprecated field handling
                None => Metadata {
                    name,
                    ..Default::default()
                },
            },
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct IBPartitionConfig {
    pub name: String,
    pub pkey: Option<PartitionKey>,
    pub tenant_organization_id: TenantOrganizationId,
    pub mtu: Option<IBMtu>,
    pub rate_limit: Option<IBRateLimit>,
    pub service_level: Option<IBServiceLevel>,
}

impl From<IBPartitionConfig> for rpc_forge::IbPartitionConfig {
    fn from(conf: IBPartitionConfig) -> Self {
        rpc_forge::IbPartitionConfig {
            name: conf.name, // Deprecated field
            tenant_organization_id: conf.tenant_organization_id.to_string(),
            pkey: conf.pkey.map(|k| k.to_string()),
        }
    }
}

impl TryFrom<rpc_forge::IbPartitionConfig> for IBPartitionConfig {
    type Error = rpc::errors::RpcDataConversionError;

    fn try_from(conf: rpc_forge::IbPartitionConfig) -> Result<Self, Self::Error> {
        if conf.tenant_organization_id.is_empty() {
            return Err(rpc::errors::RpcDataConversionError::InvalidArgument(
                "IBPartition organization_id is empty".to_string(),
            ));
        }

        let tenant_organization_id =
            TenantOrganizationId::try_from(conf.tenant_organization_id.clone()).map_err(|_| {
                rpc::errors::RpcDataConversionError::InvalidArgument(conf.tenant_organization_id)
            })?;

        Ok(IBPartitionConfig {
            name: conf.name,
            pkey: None,
            tenant_organization_id,
            mtu: None,
            rate_limit: None,
            service_level: None,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IBPartitionStatus {
    pub partition: Option<String>,
    pub mtu: Option<IBMtu>,
    pub rate_limit: Option<IBRateLimit>,
    pub service_level: Option<IBServiceLevel>,
    pub pkey: Option<PartitionKey>,
}

#[derive(Debug, Clone)]
pub struct IBPartition {
    pub id: IBPartitionId,
    pub version: ConfigVersion,

    pub config: IBPartitionConfig,
    pub status: Option<IBPartitionStatus>,

    pub deleted: Option<DateTime<Utc>>,

    pub controller_state: Versioned<IBPartitionControllerState>,

    /// The result of the last attempt to change state
    pub controller_state_outcome: Option<PersistentStateHandlerOutcome>,
    // Columns for these exist, but are unused in rust code
    // pub created: DateTime<Utc>,
    // pub updated: DateTime<Utc>,
    pub metadata: Metadata,
}

impl IBPartition {
    /// Returns whether the IB partition was deleted by the user
    pub fn is_marked_as_deleted(&self) -> bool {
        self.deleted.is_some()
    }
}

impl From<&IBPartition> for IBNetwork {
    fn from(ib: &IBPartition) -> IBNetwork {
        Self {
            name: ib.metadata.name.clone(),
            pkey: ib
                .status
                .as_ref()
                .and_then(|s| s.pkey)
                .map(u16::from)
                .unwrap_or(0u16),
            ipoib: true,
            associated_guids: None,
            membership: None,
            qos_conf: Some(IBQosConf {
                mtu: ib.config.mtu.clone().unwrap_or_default(),
                rate_limit: ib.config.rate_limit.clone().unwrap_or_default(),
                service_level: ib.config.service_level.clone().unwrap_or_default(),
            }),
        }
    }
}

impl<'r> FromRow<'r, PgRow> for IBPartition {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let controller_state: sqlx::types::Json<IBPartitionControllerState> =
            row.try_get("controller_state")?;
        let state_outcome: Option<sqlx::types::Json<PersistentStateHandlerOutcome>> =
            row.try_get("controller_state_outcome")?;

        let status: Option<sqlx::types::Json<IBPartitionStatus>> = row.try_get("status")?;
        let status = status.map(|s| s.0);

        let tenant_organization_id_str: &str = row.try_get("organization_id")?;
        let tenant_organization_id =
            TenantOrganizationId::try_from(tenant_organization_id_str.to_string())
                .map_err(|e| sqlx::Error::Decode(Box::new(e)))?;

        let pkey: Option<i32> = row.try_get("pkey")?;
        let mtu: i32 = row.try_get("mtu")?;
        let rate_limit: i32 = row.try_get("rate_limit")?;
        let service_level: i32 = row.try_get("service_level")?;
        let labels: sqlx::types::Json<HashMap<String, String>> = row.try_get("labels")?;
        let description: String = row.try_get("description")?;
        let name: String = row.try_get("name")?;

        Ok(IBPartition {
            id: row.try_get("id")?,
            version: row.try_get("config_version")?,
            config: IBPartitionConfig {
                name: name.clone(), // Derprecated field
                pkey: pkey
                    .map(|p| PartitionKey::try_from(p as u16))
                    .transpose()
                    .map_err(|_| {
                        let err = eyre::eyre!("Pkey {} is not valid", pkey.unwrap_or_default());
                        sqlx::Error::Decode(err.into())
                    })?,
                tenant_organization_id,
                mtu: IBMtu::try_from(mtu).ok(),
                rate_limit: IBRateLimit::try_from(rate_limit).ok(),
                service_level: IBServiceLevel::try_from(service_level).ok(),
            },
            status,
            metadata: Metadata {
                name,
                labels: labels.0,
                description,
            },
            deleted: row.try_get("deleted")?,

            controller_state: Versioned::new(
                controller_state.0,
                row.try_get("controller_state_version")?,
            ),
            controller_state_outcome: state_outcome.map(|x| x.0),
        })
    }
}

impl TryFrom<IBPartition> for rpc_forge::IbPartition {
    type Error = rpc::errors::RpcDataConversionError;
    fn try_from(src: IBPartition) -> Result<Self, Self::Error> {
        let mut state = match &src.controller_state.value {
            IBPartitionControllerState::Provisioning => rpc_forge::TenantState::Provisioning,
            IBPartitionControllerState::Ready => rpc_forge::TenantState::Ready,
            IBPartitionControllerState::Error { cause: _cause } => rpc_forge::TenantState::Failed,
            IBPartitionControllerState::Deleting => rpc_forge::TenantState::Terminating,
        };

        if src.is_marked_as_deleted() {
            state = rpc_forge::TenantState::Terminating;
        }

        let pkey = src
            .status
            .as_ref()
            .and_then(|s| s.pkey.map(|k| k.to_string()));

        let (partition, rate_limit, mtu, service_level) = match src.status {
            Some(s) => (
                s.partition,
                s.rate_limit.map(IBRateLimit::into),
                s.mtu.map(IBMtu::into),
                s.service_level.map(IBServiceLevel::into),
            ),
            None => (None, None, None, None),
        };

        let status = Some(rpc_forge::IbPartitionStatus {
            state: state as i32,
            state_reason: src.controller_state_outcome.map(|r| r.into()),
            state_sla: Some(
                state_sla(&src.controller_state.value, &src.controller_state.version).into(),
            ),
            enable_sharp: Some(false),
            partition,
            pkey,
            rate_limit,
            mtu,
            service_level,
        });

        let meatadata = src.metadata.into();

        Ok(rpc_forge::IbPartition {
            id: Some(src.id),
            config_version: src.version.version_string(),
            config: Some(src.config.into()),
            status,
            metadata: Some(meatadata),
        })
    }
}

/// State of a IB subnet as tracked by the controller
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum IBPartitionControllerState {
    /// The IB subnet is created in Carbide, waiting for provisioning in IB Fabric.
    Provisioning,
    /// The IB subnet is ready for IB ports.
    Ready,
    /// There is error in IB subnet; IB ports can not be added into IB subnet if it's error.
    Error { cause: String },
    /// The IB subnet is in the process of deleting.
    Deleting,
}

/// Returns the SLA for the current state
pub fn state_sla(state: &IBPartitionControllerState, state_version: &ConfigVersion) -> StateSla {
    let time_in_state = chrono::Utc::now()
        .signed_duration_since(state_version.timestamp())
        .to_std()
        .unwrap_or(std::time::Duration::from_secs(60 * 60 * 24));

    match state {
        IBPartitionControllerState::Provisioning => {
            StateSla::with_sla(slas::PROVISIONING, time_in_state)
        }
        IBPartitionControllerState::Ready => StateSla::no_sla(),
        IBPartitionControllerState::Error { .. } => StateSla::no_sla(),
        IBPartitionControllerState::Deleting => StateSla::with_sla(slas::DELETING, time_in_state),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_and_format_pkey() {
        let pkey = PartitionKey::from_str("0xf").unwrap();
        let serialized = serde_json::to_string(&pkey).unwrap();
        assert_eq!(serialized, "\"0xf\"");
        assert_eq!(pkey.to_string(), "0xf");
        let deserialized = serde_json::from_str(&serialized).unwrap();
        assert_eq!(pkey, deserialized);
        let deserialized = serde_json::from_str("\"15\"").unwrap();
        assert_eq!(pkey, deserialized);
        let deserialized = serde_json::from_str("\"0xf\"").unwrap();
        assert_eq!(pkey, deserialized);
    }

    #[test]
    fn serialize_controller_state() {
        let state = IBPartitionControllerState::Provisioning {};
        let serialized = serde_json::to_string(&state).unwrap();
        assert_eq!(serialized, "{\"state\":\"provisioning\"}");
        assert_eq!(
            serde_json::from_str::<IBPartitionControllerState>(&serialized).unwrap(),
            state
        );
        let state = IBPartitionControllerState::Ready {};
        let serialized = serde_json::to_string(&state).unwrap();
        assert_eq!(serialized, "{\"state\":\"ready\"}");
        assert_eq!(
            serde_json::from_str::<IBPartitionControllerState>(&serialized).unwrap(),
            state
        );
        let state = IBPartitionControllerState::Error {
            cause: "cause goes here".to_string(),
        };
        let serialized = serde_json::to_string(&state).unwrap();
        assert_eq!(serialized, r#"{"state":"error","cause":"cause goes here"}"#);
        assert_eq!(
            serde_json::from_str::<IBPartitionControllerState>(&serialized).unwrap(),
            state
        );
        let state = IBPartitionControllerState::Deleting {};
        let serialized = serde_json::to_string(&state).unwrap();
        assert_eq!(serialized, "{\"state\":\"deleting\"}");
        assert_eq!(
            serde_json::from_str::<IBPartitionControllerState>(&serialized).unwrap(),
            state
        );
    }
}
