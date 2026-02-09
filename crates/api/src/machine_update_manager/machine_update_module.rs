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

use std::collections::{HashMap, HashSet};
use std::fmt;

use async_trait::async_trait;
use carbide_uuid::machine::MachineId;
use model::machine::ManagedHostStateSnapshot;
use model::machine_update_module::{
    AutomaticFirmwareUpdateReference, DPU_FIRMWARE_UPDATE_TARGET, DpuReprovisionInitiator,
    HOST_FW_UPDATE_HEALTH_REPORT_SOURCE, HOST_UPDATE_HEALTH_PROBE_ID,
    HOST_UPDATE_HEALTH_REPORT_SOURCE,
};
use sqlx::PgConnection;

use crate::CarbideResult;

/// Used by [MachineUpdateManager](crate::machine_update_manager::MachineUpdateManager) to initiate
/// machine updates.  A module is responsible for managing its own updates and accurately reporting
/// the number of outstanding updates.
///
/// NOTE: Updating machines are treated as managed hosts and identified by the host machine id.  DPU
/// updates are identified by using the host machine id, and the host/DPU pair should be treated as one.
#[async_trait]
pub trait MachineUpdateModule: Send + Sync + fmt::Display {
    async fn get_updates_in_progress(
        &self,
        txn: &mut PgConnection,
    ) -> CarbideResult<HashSet<MachineId>>;

    async fn start_updates(
        &self,
        txn: &mut PgConnection,
        available_updates: i32,
        updating_host_machines: &HashSet<MachineId>,
        snapshots: &HashMap<MachineId, ManagedHostStateSnapshot>,
    ) -> CarbideResult<HashSet<MachineId>>;

    async fn clear_completed_updates(&self, txn: &mut PgConnection) -> CarbideResult<()>;

    async fn update_metrics(
        &self,
        txn: &mut PgConnection,
        snapshots: &HashMap<MachineId, ManagedHostStateSnapshot>,
    );
}

/// Creates a Health override report that indicates that a host update is in progress
pub fn create_host_update_health_report(
    target: Option<String>,
    message: String,
    for_host_fw: bool,
) -> health_report::HealthReport {
    let source = match for_host_fw {
        false => HOST_UPDATE_HEALTH_REPORT_SOURCE,
        true => HOST_FW_UPDATE_HEALTH_REPORT_SOURCE,
    }
    .to_string();

    health_report::HealthReport {
        source,
        observed_at: Some(chrono::Utc::now()),
        successes: vec![],
        alerts: vec![health_report::HealthProbeAlert {
            id: HOST_UPDATE_HEALTH_PROBE_ID.clone(),
            target,
            in_alert_since: Some(chrono::Utc::now()),
            message,
            tenant_message: None,
            // While the Machine is in process of being updated, no tenant should be
            // able to acquire the Machine.
            // If the Machine becomes unhealthy during updates (which might happen
            // e.g. due to powering the host down and up), no pages should be triggered
            classifications: vec![
                health_report::HealthAlertClassification::prevent_allocations(),
                health_report::HealthAlertClassification::suppress_external_alerting(),
            ],
        }],
    }
}

pub fn create_host_update_health_report_hostfw() -> health_report::HealthReport {
    create_host_update_health_report(
        Some("HostFirmware".to_string()),
        "Host firmware update".to_string(),
        true,
    )
}

pub fn create_host_update_health_report_dpufw() -> health_report::HealthReport {
    let initiator_host = DpuReprovisionInitiator::Automatic(AutomaticFirmwareUpdateReference {
        // In case of multidpu, DPUs can have different versions.
        from: "".to_string(),
        to: "".to_string(),
    });

    create_host_update_health_report(
        Some(DPU_FIRMWARE_UPDATE_TARGET.to_string()),
        initiator_host.to_string(),
        false,
    )
}
