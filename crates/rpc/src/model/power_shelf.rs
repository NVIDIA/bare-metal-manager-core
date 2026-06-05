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

use mac_address::MacAddress;
use model::power_shelf::{
    NewPowerShelf, PowerShelf, PowerShelfConfig, PowerShelfSearchFilter,
    derive_power_shelf_aggregate_health,
};

use crate::errors::RpcDataConversionError;
use crate::forge::{self as rpc, LifecycleStatus};

impl TryFrom<rpc::PowerShelfCreationRequest> for NewPowerShelf {
    type Error = RpcDataConversionError;
    fn try_from(value: rpc::PowerShelfCreationRequest) -> Result<Self, Self::Error> {
        let conf = match value.config {
            Some(c) => c,
            None => {
                return Err(RpcDataConversionError::InvalidArgument(
                    "PowerShelf configuration is empty".to_string(),
                ));
            }
        };

        let id = value.id.unwrap_or_else(|| uuid::Uuid::new_v4().into());

        let config = PowerShelfConfig::try_from(conf)?;

        Ok(NewPowerShelf {
            id,
            config,
            bmc_mac_address: None,
            metadata: None,
            rack_id: None,
        })
    }
}

impl TryFrom<rpc::PowerShelfConfig> for PowerShelfConfig {
    type Error = RpcDataConversionError;

    fn try_from(conf: rpc::PowerShelfConfig) -> Result<Self, Self::Error> {
        Ok(PowerShelfConfig {
            name: conf.name,
            capacity: conf.capacity.map(|c| c as u32),
            voltage: conf.voltage.map(|v| v as u32),
        })
    }
}

impl TryFrom<PowerShelf> for rpc::PowerShelf {
    type Error = RpcDataConversionError;

    fn try_from(src: PowerShelf) -> Result<Self, Self::Error> {
        let health = derive_power_shelf_aggregate_health(&src.health_reports);
        let health_sources = src
            .health_reports
            .iter()
            .map(|(hr, m)| rpc::HealthSourceOrigin {
                mode: m as i32,
                source: hr.source.clone(),
            })
            .collect();

        let lifecycle = LifecycleStatus {
            state: serde_json::to_string(&src.controller_state.value).unwrap_or_default(),
            version: src.controller_state.version.version_string(),
            state_reason: src.controller_state_outcome.map(Into::into),
            sla: Some(rpc::StateSla {
                sla: None, // TODO: Calculate SLA properly
                time_in_state_above_sla: false,
            }),
        };
        let controller_state = lifecycle.state.clone();

        let status = Some(match src.status {
            Some(s) => rpc::PowerShelfStatus {
                state_reason: None, // TODO: implement state_reason
                state_sla: Some(rpc::StateSla {
                    sla: None,
                    time_in_state_above_sla: false,
                }),
                shelf_name: Some(s.shelf_name),
                power_state: Some(s.power_state),
                health_status: Some(s.health_status),
                controller_state: Some(controller_state.clone()),
                health: Some(health.into()),
                health_sources,
                lifecycle: Some(lifecycle),
            },
            None => rpc::PowerShelfStatus {
                state_reason: None,
                state_sla: Some(rpc::StateSla {
                    sla: None,
                    time_in_state_above_sla: false,
                }),
                shelf_name: None,
                power_state: None,
                health_status: None,
                controller_state: Some(controller_state.clone()),
                health: Some(health.into()),
                health_sources,
                lifecycle: Some(lifecycle),
            },
        });

        let config = rpc::PowerShelfConfig {
            name: src.config.name,
            capacity: src.config.capacity.map(|c| c as i32),
            voltage: src.config.voltage.map(|v| v as i32),
        };

        let deleted = src.deleted.map(Into::into);
        let state_version = src.controller_state.version.to_string();
        Ok(rpc::PowerShelf {
            id: Some(src.id),
            config: Some(config),
            status,
            deleted,
            controller_state,
            metadata: Some(src.metadata.into()),
            version: src.version.version_string(),
            bmc_info: None,
            state_version,
            rack_id: src.rack_id,
        })
    }
}

impl From<rpc::PowerShelfSearchFilter> for PowerShelfSearchFilter {
    fn from(filter: rpc::PowerShelfSearchFilter) -> Self {
        PowerShelfSearchFilter {
            rack_id: filter.rack_id,
            deleted: model::DeletedFilter::from(filter.deleted),
            controller_state: filter.controller_state,
            bmc_mac: filter.bmc_mac.and_then(|m| m.parse::<MacAddress>().ok()),
        }
    }
}
