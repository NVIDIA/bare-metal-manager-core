/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use carbide_uuid::instance_type::InstanceTypeId;
use rpc::errors::RpcDataConversionError;

/// MachineSearchConfig: Search parameters
#[derive(Default, Debug, Clone)]
pub struct MachineSearchConfig {
    pub include_dpus: bool,
    pub include_history: bool,
    pub include_predicted_host: bool,
    /// Only include machines in maintenance mode
    pub only_maintenance: bool,
    /// Only include quarantined machines
    pub only_quarantine: bool,
    pub exclude_hosts: bool,
    pub instance_type_id: Option<InstanceTypeId>,

    /// Whether the query results will be later
    /// used for updates in the same transaction.
    ///
    /// Triggers one or more locking behaviors in the DB.
    ///
    /// This applies *only* to the immediate machines records
    /// and any joined tables.  The value is *not*
    /// propagated to any additional underlying queries.
    pub for_update: bool,
    // Only include NVLink capable machines (GB200/GB300 etc)
    pub mnnvl_only: bool,
}

impl TryFrom<rpc::forge::MachineSearchConfig> for MachineSearchConfig {
    type Error = RpcDataConversionError;

    fn try_from(value: rpc::forge::MachineSearchConfig) -> Result<Self, Self::Error> {
        Ok(MachineSearchConfig {
            include_dpus: value.include_dpus,
            include_history: value.include_history,
            include_predicted_host: value.include_predicted_host,
            only_maintenance: value.only_maintenance,
            only_quarantine: value.only_quarantine,
            exclude_hosts: value.exclude_hosts,
            instance_type_id: value
                .instance_type_id
                .map(|t| {
                    t.parse::<InstanceTypeId>()
                        .map_err(|_| RpcDataConversionError::InvalidInstanceTypeId(t.clone()))
                })
                .transpose()?,
            for_update: false, // This isn't exposed to API callers
            mnnvl_only: value.mnnvl_only,
        })
    }
}
