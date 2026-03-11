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
use ::rpc::forge as rpc;
use carbide_uuid::compute_allocation::ComputeAllocationId;
use carbide_uuid::instance_type::InstanceTypeId;
use chrono::prelude::*;
use config_version::ConfigVersion;
use sqlx::Row;
use sqlx::postgres::PgRow;

use super::tenant::TenantOrganizationId;
use crate::metadata::Metadata;

pub const MAX_COMPUTE_ALLOCATION_SIZE: u32 = 100000;

/* ********************************** */
/*          ComputeAllocation         */
/* ********************************** */

/// ComputeAllocation represents an amount of compute
/// resources that should be made available to a tenant.
#[derive(Clone, Debug, PartialEq)]
pub struct ComputeAllocation {
    pub id: ComputeAllocationId,
    pub version: ConfigVersion,
    pub tenant_organization_id: TenantOrganizationId,
    pub instance_type_id: InstanceTypeId,
    pub count: u32,
    pub created: DateTime<Utc>,
    pub deleted: Option<DateTime<Utc>>,
    pub created_by: Option<String>,
    pub updated_by: Option<String>,
    pub metadata: Metadata,
}

impl<'r> sqlx::FromRow<'r, PgRow> for ComputeAllocation {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let labels: sqlx::types::Json<HashMap<String, String>> = row.try_get("labels")?;

        let metadata = Metadata {
            name: row.try_get("name")?,
            description: row.try_get("description")?,
            labels: labels.0,
        };

        let count: i32 = row.try_get("count")?;

        let tenant_organization_id: String = row.try_get("tenant_organization_id")?;

        Ok(ComputeAllocation {
            id: row.try_get("id")?,
            version: row.try_get("version")?,
            tenant_organization_id: tenant_organization_id
                .parse::<TenantOrganizationId>()
                .map_err(|e| sqlx::Error::Decode(Box::new(e)))?,
            instance_type_id: row.try_get("instance_type_id")?,
            created_by: row.try_get("created_by")?,
            updated_by: row.try_get("updated_by")?,
            created: row.try_get("created")?,
            deleted: row.try_get("deleted")?,
            metadata,
            count: count
                .try_into()
                .map_err(|e| sqlx::Error::Decode(Box::new(e)))?,
        })
    }
}

impl TryFrom<ComputeAllocation> for rpc::ComputeAllocation {
    type Error = RpcDataConversionError;

    fn try_from(compute_alloc: ComputeAllocation) -> Result<Self, Self::Error> {
        let attributes = rpc::ComputeAllocationAttributes {
            instance_type_id: compute_alloc.instance_type_id.to_string(),
            count: compute_alloc.count,
        };

        Ok(rpc::ComputeAllocation {
            id: Some(compute_alloc.id),
            tenant_organization_id: compute_alloc.tenant_organization_id.to_string(),
            version: compute_alloc.version.to_string(),
            attributes: Some(attributes),
            created_at: Some(compute_alloc.created.to_string()),
            created_by: compute_alloc.created_by,
            updated_by: compute_alloc.updated_by,
            metadata: Some(rpc::Metadata {
                name: compute_alloc.metadata.name,
                description: compute_alloc.metadata.description,
                labels: compute_alloc
                    .metadata
                    .labels
                    .iter()
                    .map(|(key, value)| rpc::Label {
                        key: key.to_owned(),
                        value: if value.is_empty() {
                            None
                        } else {
                            Some(value.to_owned())
                        },
                    })
                    .collect(),
            }),
        })
    }
}

/* ********************************** */
/*              Tests                 */
/* ********************************** */

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use ::rpc::forge as rpc;
    use config_version::ConfigVersion;

    use super::*;

    #[test]
    fn test_model_compute_allocation_to_rpc_conversion() {
        let version = ConfigVersion::initial();

        let req_type = rpc::ComputeAllocation {
            id: Some("dbe71f32-1bdc-11f1-8101-3b10d91c938c".parse().unwrap()),
            version: version.to_string(),
            metadata: Some(rpc::Metadata {
                name: "fancy name".to_string(),
                description: "".to_string(),
                labels: vec![],
            }),
            tenant_organization_id: "theorg".to_string(),
            attributes: Some(rpc::ComputeAllocationAttributes {
                instance_type_id: "12345".to_string(),
                count: 10,
            }),
            created_at: Some("2023-01-01 00:00:00 UTC".to_string()),
            created_by: Some("user1".to_string()),
            updated_by: Some("user2".to_string()),
        };

        let compute_alloc = ComputeAllocation {
            id: "dbe71f32-1bdc-11f1-8101-3b10d91c938c".parse().unwrap(),
            deleted: None,
            created: "2023-01-01 00:00:00 UTC".parse().unwrap(),
            version,
            metadata: Metadata {
                name: "fancy name".to_string(),
                description: "".to_string(),
                labels: HashMap::new(),
            },
            tenant_organization_id: "theorg".parse().unwrap(),

            instance_type_id: "12345".parse().unwrap(),
            count: 10,
            created_by: Some("user1".to_string()),
            updated_by: Some("user2".to_string()),
        };

        // Verify that we can go from an internal compute allocation to the
        // protobuf ComputeAllocation message
        assert_eq!(
            req_type,
            rpc::ComputeAllocation::try_from(compute_alloc).unwrap()
        );
    }
}
