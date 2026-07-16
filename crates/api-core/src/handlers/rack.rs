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
use std::collections::HashSet;
use std::str::FromStr;

use ::rpc::errors::RpcDataConversionError;
use ::rpc::forge::{self as rpc, HealthReportEntry};
use carbide_rack::firmware_object::{
    rack_maintenance_access_token_key, rms_access_token_or_noauth,
};
use carbide_secrets::credentials::Credentials;
use carbide_uuid::machine::MachineId;
use carbide_uuid::power_shelf::PowerShelfId;
use carbide_uuid::rack::RackId;
use carbide_uuid::switch::SwitchId;
use db::{
    ObjectColumnFilter, WithTransaction, machine as db_machine, power_shelf as db_power_shelf,
    rack as db_rack, switch as db_switch,
};
use futures_util::FutureExt;
use health_report::HealthReportApplyMode;
use model::machine::machine_search_config::MachineSearchConfig;
use model::metadata::Metadata;
use model::rack::{MaintenanceActivity, MaintenanceScope, RackState};
use tonic::{Request, Response, Status};

use crate::CarbideError;
use crate::api::{Api, log_request_data, log_request_data_redacted};
use crate::auth::AuthContext;

pub async fn get_rack(
    api: &Api,
    request: Request<rpc::GetRackRequest>,
) -> Result<Response<rpc::GetRackResponse>, Status> {
    log_request_data(&request);

    let req = request.into_inner();

    let mut reader = api.db_reader();

    let racks = if let Some(id) = req.id {
        let rack_id = RackId::from_str(&id)
            .map_err(|e| CarbideError::InvalidArgument(format!("invalid rack ID: {}", e)))?;
        db_rack::find_by(
            reader.as_mut(),
            ObjectColumnFilter::One(db_rack::IdColumn, &rack_id),
        )
        .await
        .map_err(CarbideError::from)?
    } else {
        db_rack::find_by(
            reader.as_mut(),
            ObjectColumnFilter::All::<db_rack::IdColumn>,
        )
        .await
        .map_err(CarbideError::from)?
    };

    let mut result = Vec::with_capacity(racks.len());
    for r in racks {
        let rpc_rack: rpc::Rack = r.into();
        result.push(rpc_rack);
    }

    Ok(Response::new(rpc::GetRackResponse { rack: result }))
}

pub async fn find_ids(
    api: &Api,
    request: Request<rpc::RackSearchFilter>,
) -> Result<Response<rpc::RackIdList>, Status> {
    log_request_data(&request);

    let filter: model::rack::RackSearchFilter = request.into_inner().into();

    let rack_ids = db::rack::find_ids(&api.database_connection, filter).await?;

    Ok(Response::new(rpc::RackIdList { rack_ids }))
}

pub async fn find_by_ids(
    api: &Api,
    request: Request<rpc::RacksByIdsRequest>,
) -> Result<Response<rpc::RackList>, Status> {
    log_request_data(&request);

    let rack_ids = request.into_inner().rack_ids;

    let max_find_by_ids = api.runtime_config.max_find_by_ids as usize;
    if rack_ids.len() > max_find_by_ids {
        return Err(CarbideError::InvalidArgument(format!(
            "no more than {max_find_by_ids} IDs can be accepted"
        ))
        .into());
    } else if rack_ids.is_empty() {
        return Err(
            CarbideError::InvalidArgument("at least one ID must be provided".to_string()).into(),
        );
    }

    let mut txn = api.txn_begin().await?;

    let racks = db::rack::find_by(
        &mut txn,
        ObjectColumnFilter::List(db::rack::IdColumn, &rack_ids),
    )
    .await?;

    let mut result = Vec::with_capacity(racks.len());
    for rack in racks {
        result.push(rack.into());
    }

    let _ = txn.rollback().await;

    Ok(Response::new(rpc::RackList { racks: result }))
}

pub async fn find_rack_state_histories(
    api: &Api,
    request: Request<rpc::RackStateHistoriesRequest>,
) -> Result<Response<rpc::StateHistories>, Status> {
    log_request_data(&request);
    let request = request.into_inner();
    let rack_ids = request.rack_ids;

    let max_find_by_ids = api.runtime_config.max_find_by_ids as usize;
    if rack_ids.len() > max_find_by_ids {
        return Err(CarbideError::InvalidArgument(format!(
            "no more than {max_find_by_ids} IDs can be accepted"
        ))
        .into());
    } else if rack_ids.is_empty() {
        return Err(
            CarbideError::InvalidArgument("at least one ID must be provided".to_string()).into(),
        );
    }

    let mut txn = api.txn_begin().await?;

    let results = db::state_history::find_by_object_ids(
        &mut txn,
        db::state_history::StateHistoryTableId::Rack,
        &rack_ids,
    )
    .await
    .map_err(CarbideError::from)?;

    let mut response = rpc::StateHistories::default();
    for (rack_id, records) in results {
        response.histories.insert(
            rack_id,
            ::rpc::forge::StateHistoryRecords {
                records: records.into_iter().map(Into::into).collect(),
            },
        );
    }

    txn.commit().await?;

    Ok(tonic::Response::new(response))
}

pub async fn delete_rack(
    api: &Api,
    request: Request<rpc::DeleteRackRequest>,
) -> Result<Response<()>, Status> {
    log_request_data(&request);

    let req = request.into_inner();
    api.with_txn(|txn| {
        async move {
            let rack_id = RackId::from_str(&req.id)
                .map_err(|e| CarbideError::InvalidArgument(format!("invalid rack ID: {}", e)))?;
            let _rack = db_rack::find_by(
                txn.as_mut(),
                ObjectColumnFilter::One(db_rack::IdColumn, &rack_id),
            )
            .await
            .map_err(CarbideError::from)?
            .pop()
            .ok_or_else(|| CarbideError::NotFoundError {
                kind: "rack",
                id: rack_id.to_string(),
            })?;

            db_rack::mark_as_deleted(&rack_id, txn)
                .await
                .map_err(|e| CarbideError::Internal {
                    message: format!("Marking rack deleted {}", e),
                })?;
            Ok::<_, Status>(())
        }
        .boxed()
    })
    .await??;
    Ok(Response::new(()))
}

/// Force deletes a rack from the database.
/// Unlike `delete_rack` (soft delete), this immediately hard-deletes the rack
/// while retaining its state history.
pub async fn admin_force_delete_rack(
    api: &Api,
    request: Request<rpc::AdminForceDeleteRackRequest>,
) -> Result<Response<rpc::AdminForceDeleteRackResponse>, Status> {
    log_request_data(&request);
    let request = request.into_inner();

    let rack_id = request
        .rack_id
        .ok_or_else(|| CarbideError::InvalidArgument("rack_id is required".to_string()))?;

    let mut txn = api.txn_begin().await?;

    let rack_list = db_rack::find_by(
        &mut txn,
        ObjectColumnFilter::One(db_rack::IdColumn, &rack_id),
    )
    .await
    .map_err(CarbideError::from)?;

    if rack_list.is_empty() {
        return Err(CarbideError::NotFoundError {
            kind: "rack",
            id: rack_id.to_string(),
        }
        .into());
    }

    db_rack::final_delete(&mut txn, &rack_id)
        .await
        .map_err(CarbideError::from)?;

    txn.commit().await?;

    if let Err(error) = api
        .credential_manager
        .delete_credentials(&rack_maintenance_access_token_key(&rack_id))
        .await
    {
        tracing::warn!(
            rack_id = %rack_id,
            error = %error,
            "failed to delete rack maintenance access token during force delete",
        );
    }

    Ok(Response::new(rpc::AdminForceDeleteRackResponse {
        rack_id: rack_id.to_string(),
    }))
}

pub async fn list_rack_health_reports(
    api: &Api,
    request: Request<rpc::ListRackHealthReportsRequest>,
) -> Result<Response<rpc::ListHealthReportResponse>, Status> {
    log_request_data(&request);

    let req = request.into_inner();
    let rack_id = req
        .rack_id
        .ok_or_else(|| CarbideError::MissingArgument("rack_id"))?;

    let rack = db_rack::find_by(
        api.db_reader().as_mut(),
        ObjectColumnFilter::One(db_rack::IdColumn, &rack_id),
    )
    .await
    .map_err(CarbideError::from)?
    .pop()
    .ok_or_else(|| CarbideError::NotFoundError {
        kind: "rack",
        id: rack_id.to_string(),
    })?;

    Ok(Response::new(rpc::ListHealthReportResponse {
        health_report_entries: rack
            .health_reports
            .into_iter()
            .map(|o| HealthReportEntry {
                report: Some(o.0.into()),
                mode: o.1 as i32,
            })
            .collect(),
    }))
}

pub async fn insert_rack_health_report(
    api: &Api,
    request: Request<rpc::InsertRackHealthReportRequest>,
) -> Result<Response<()>, Status> {
    log_request_data(&request);

    let triggered_by = request
        .extensions()
        .get::<AuthContext>()
        .and_then(|ctx| ctx.get_external_user_name())
        .map(String::from);

    let rpc::InsertRackHealthReportRequest {
        rack_id,
        health_report_entry: Some(rpc::HealthReportEntry { report, mode }),
    } = request.into_inner()
    else {
        return Err(CarbideError::MissingArgument("override").into());
    };
    let rack_id = rack_id.ok_or_else(|| CarbideError::MissingArgument("rack_id"))?;

    let Some(report) = report else {
        return Err(CarbideError::MissingArgument("report").into());
    };
    let Ok(mode) = rpc::HealthReportApplyMode::try_from(mode) else {
        return Err(CarbideError::InvalidArgument("mode".to_string()).into());
    };
    let mode: HealthReportApplyMode = mode.into();

    let mut txn = api.txn_begin().await?;

    let rack = db_rack::find_by(
        &mut txn,
        ObjectColumnFilter::One(db_rack::IdColumn, &rack_id),
    )
    .await
    .map_err(CarbideError::from)?
    .pop()
    .ok_or_else(|| CarbideError::NotFoundError {
        kind: "rack",
        id: rack_id.to_string(),
    })?;

    let mut report = health_report::HealthReport::try_from(report.clone())
        .map_err(|e| CarbideError::internal(e.to_string()))?;
    if report.observed_at.is_none() {
        report.observed_at = Some(chrono::Utc::now());
    }
    report.triggered_by = triggered_by;
    report.update_in_alert_since(None);

    match remove_rack_override_by_source(&rack, &mut txn, report.source.clone()).await {
        Ok(_) | Err(CarbideError::NotFoundError { .. }) => {}
        Err(e) => return Err(e.into()),
    }

    db_rack::insert_health_report(&mut txn, &rack.id, mode, &report).await?;

    txn.commit().await?;

    if let Some(handle) = api.bms_client.get() {
        handle.update_rack_leak_state(&rack.id, &report).await;
    }

    Ok(Response::new(()))
}

pub async fn remove_rack_health_report(
    api: &Api,
    request: Request<rpc::RemoveRackHealthReportRequest>,
) -> Result<Response<()>, Status> {
    log_request_data(&request);

    let rpc::RemoveRackHealthReportRequest { rack_id, source } = request.into_inner();
    let rack_id = rack_id.ok_or_else(|| CarbideError::MissingArgument("rack_id"))?;

    let mut txn = api.txn_begin().await?;

    let rack = db_rack::find_by(
        &mut txn,
        ObjectColumnFilter::One(db_rack::IdColumn, &rack_id),
    )
    .await
    .map_err(CarbideError::from)?
    .pop()
    .ok_or_else(|| CarbideError::NotFoundError {
        kind: "rack",
        id: rack_id.to_string(),
    })?;

    remove_rack_override_by_source(&rack, &mut txn, source).await?;
    txn.commit().await?;

    Ok(Response::new(()))
}

async fn remove_rack_override_by_source(
    rack: &model::rack::Rack,
    txn: &mut db::Transaction<'_>,
    source: String,
) -> Result<(), CarbideError> {
    let mode = if rack.health_reports.replace.as_ref().map(|o| &o.source) == Some(&source) {
        HealthReportApplyMode::Replace
    } else if rack.health_reports.merges.contains_key(&source) {
        HealthReportApplyMode::Merge
    } else {
        return Err(CarbideError::NotFoundError {
            kind: "rack override with source",
            id: source,
        });
    };

    db_rack::remove_health_report(&mut *txn, &rack.id, mode, &source).await?;

    Ok(())
}

pub async fn get_rack_profile(
    api: &Api,
    request: Request<rpc::GetRackProfileRequest>,
) -> Result<Response<rpc::GetRackProfileResponse>, Status> {
    log_request_data(&request);

    let req = request.into_inner();
    let rack_id = req
        .rack_id
        .ok_or_else(|| CarbideError::MissingArgument("rack_id"))?;

    let rack = db_rack::find_by(
        api.db_reader().as_mut(),
        ObjectColumnFilter::One(db_rack::IdColumn, &rack_id),
    )
    .await
    .map_err(CarbideError::from)?
    .pop()
    .ok_or_else(|| CarbideError::NotFoundError {
        kind: "rack",
        id: rack_id.to_string(),
    })?;

    let rack_profile_id =
        rack.rack_profile_id
            .as_ref()
            .ok_or_else(|| CarbideError::NotFoundError {
                kind: "rack_profile_id for rack",
                id: rack_id.to_string(),
            })?;

    let profile = api
        .runtime_config
        .rack_profiles
        .get(rack_profile_id.as_str())
        .ok_or_else(|| CarbideError::NotFoundError {
            kind: "rack profile for rack_profile_id",
            id: rack_profile_id.to_string(),
        })?;

    let rpc_profile: rpc::RackProfile = profile.into();

    Ok(Response::new(rpc::GetRackProfileResponse {
        rack_id: Some(rack_id),
        rack_profile_id: Some(rack_profile_id.clone()),
        profile: Some(rpc_profile),
    }))
}

pub(crate) async fn update_rack_metadata(
    api: &Api,
    request: Request<rpc::RackMetadataUpdateRequest>,
) -> std::result::Result<tonic::Response<()>, tonic::Status> {
    log_request_data(&request);
    let request = request.into_inner();
    let rack_id = request
        .rack_id
        .ok_or_else(|| CarbideError::from(RpcDataConversionError::MissingArgument("rack_id")))?;

    let metadata = match request.metadata {
        Some(m) => Metadata::try_from(m).map_err(CarbideError::from)?,
        _ => {
            return Err(
                CarbideError::from(RpcDataConversionError::MissingArgument("metadata")).into(),
            );
        }
    };
    metadata.validate(true).map_err(CarbideError::from)?;

    let mut txn = api.txn_begin().await?;

    let rack = db_rack::find_by(
        &mut txn,
        ObjectColumnFilter::One(db_rack::IdColumn, &rack_id),
    )
    .await
    .map_err(CarbideError::from)?
    .pop()
    .ok_or_else(|| CarbideError::NotFoundError {
        kind: "rack",
        id: rack_id.to_string(),
    })?;

    let expected_version: config_version::ConfigVersion = match request.if_version_match {
        Some(version) => version.parse().map_err(CarbideError::from)?,
        None => rack.version,
    };

    db_rack::update_metadata(&mut txn, &rack_id, expected_version, metadata).await?;

    txn.commit().await?;

    Ok(tonic::Response::new(()))
}

fn non_empty_string(value: &str) -> Option<String> {
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_string())
}

fn set_maintenance_access_token(
    maintenance_access_token: &mut Option<String>,
    access_token: Option<String>,
) -> Result<(), CarbideError> {
    let Some(access_token) = access_token else {
        return Ok(());
    };

    if let Some(existing) = maintenance_access_token {
        if existing != &access_token {
            return Err(CarbideError::InvalidArgument(
                "rack maintenance activities must use the same access_token".into(),
            ));
        }
        return Ok(());
    }

    *maintenance_access_token = Some(access_token);
    Ok(())
}

pub(crate) async fn on_demand_rack_maintenance(
    api: &Api,
    request: Request<rpc::RackMaintenanceOnDemandRequest>,
) -> Result<Response<rpc::RackMaintenanceOnDemandResponse>, Status> {
    log_request_data_redacted("RackMaintenanceOnDemandRequest { redacted }");

    let req = request.into_inner();

    let rack_id = req
        .rack_id
        .ok_or_else(|| CarbideError::InvalidArgument("rack_id is required".into()))?;

    let rack = db_rack::find_by(
        api.db_reader().as_mut(),
        ObjectColumnFilter::One(db_rack::IdColumn, &rack_id),
    )
    .await
    .map_err(CarbideError::from)?
    .pop()
    .ok_or_else(|| CarbideError::NotFoundError {
        kind: "rack",
        id: rack_id.to_string(),
    })?;

    if !matches!(
        *rack.controller_state,
        RackState::Ready | RackState::Error { .. }
    ) {
        return Err(CarbideError::InvalidArgument(format!(
            "rack {} is not in ready or error state (current: {:?}). maintenance can only be requested when the rack is ready or in error",
            rack_id, *rack.controller_state
        ))
        .into());
    }

    if rack.config.maintenance_requested.is_some() {
        return Err(CarbideError::InvalidArgument(format!(
            "on-demand maintenance for rack {} is already scheduled",
            rack_id,
        ))
        .into());
    }

    use rpc::maintenance_activity_config::Activity as ProtoActivity;

    let proto_scope = req.scope.unwrap_or_default();

    let mut activities = Vec::with_capacity(proto_scope.activities.len());
    let mut maintenance_access_token = None;
    for entry in &proto_scope.activities {
        let activity = match &entry.activity {
            Some(ProtoActivity::FirmwareUpgrade(fw)) => {
                let firmware_version = non_empty_string(&fw.firmware_version);
                let access_token = rms_access_token_or_noauth(fw.access_token.as_deref());

                if firmware_version.is_none() {
                    return Err(CarbideError::InvalidArgument(
                        "firmware-upgrade rack maintenance requires SOT JSON in firmware_version"
                            .into(),
                    )
                    .into());
                }
                if let Some(config_json) = firmware_version.as_deref() {
                    serde_json::from_str::<serde_json::Value>(config_json).map_err(|error| {
                        CarbideError::InvalidArgument(format!(
                            "firmware-upgrade firmware_version must contain valid SOT JSON: {error}"
                        ))
                    })?;
                }
                set_maintenance_access_token(&mut maintenance_access_token, Some(access_token))?;

                MaintenanceActivity::FirmwareUpgrade {
                    firmware_version,
                    components: fw.components.clone(),
                    force_update: fw.force_update,
                }
            }
            Some(ProtoActivity::NvosUpdate(nvos)) => {
                let config_json = non_empty_string(&nvos.config_json);
                let access_token = rms_access_token_or_noauth(nvos.access_token.as_deref());

                if config_json.is_none() {
                    return Err(CarbideError::InvalidArgument(
                        "nvos-update rack maintenance requires SOT JSON in config_json".into(),
                    )
                    .into());
                }
                let config_json = config_json.expect("validated above");
                serde_json::from_str::<serde_json::Value>(&config_json).map_err(|error| {
                    CarbideError::InvalidArgument(format!(
                        "nvos-update config_json must contain valid SOT JSON: {error}"
                    ))
                })?;
                set_maintenance_access_token(&mut maintenance_access_token, Some(access_token))?;

                MaintenanceActivity::NvosUpdate { config_json }
            }
            Some(ProtoActivity::ConfigureNmxCluster(_)) => MaintenanceActivity::ConfigureNmxCluster,
            Some(ProtoActivity::PowerSequence(_)) => MaintenanceActivity::PowerSequence,
            None => {
                return Err(CarbideError::InvalidArgument(
                    "maintenance activity entry has no activity set".into(),
                )
                .into());
            }
        };
        activities.push(activity);
    }

    let scope = MaintenanceScope {
        machine_ids: proto_scope
            .machine_ids
            .iter()
            .map(|s| MachineId::from_str(s))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| CarbideError::InvalidArgument(format!("invalid machine_id: {e}")))?,
        switch_ids: proto_scope
            .switch_ids
            .iter()
            .map(|s| SwitchId::from_str(s))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| CarbideError::InvalidArgument(format!("invalid switch_id: {e}")))?,
        power_shelf_ids: proto_scope
            .power_shelf_ids
            .iter()
            .map(|s| PowerShelfId::from_str(s))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| CarbideError::InvalidArgument(format!("invalid power_shelf_id: {e}")))?,
        activities,
    };

    if !scope.is_full_rack() {
        let mut reader = api.db_reader();

        if !scope.machine_ids.is_empty() {
            let rack_machines: HashSet<MachineId> = db_machine::find_machine_ids(
                reader.as_mut(),
                MachineSearchConfig {
                    rack_id: Some(rack_id.clone()),
                    ..Default::default()
                },
            )
            .await
            .map_err(CarbideError::from)?
            .into_iter()
            .collect();

            let foreign: Vec<_> = scope
                .machine_ids
                .iter()
                .filter(|id| !rack_machines.contains(id))
                .collect();
            if !foreign.is_empty() {
                return Err(CarbideError::InvalidArgument(format!(
                    "machine(s) [{}] do not belong to rack {rack_id}",
                    foreign
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(", "),
                ))
                .into());
            }
        }

        if !scope.switch_ids.is_empty() {
            let rack_switches: HashSet<SwitchId> = db_switch::find_ids(
                reader.as_mut(),
                model::switch::SwitchSearchFilter {
                    rack_id: Some(rack_id.clone()),
                    ..Default::default()
                },
            )
            .await
            .map_err(CarbideError::from)?
            .into_iter()
            .collect();

            let foreign: Vec<_> = scope
                .switch_ids
                .iter()
                .filter(|id| !rack_switches.contains(id))
                .collect();
            if !foreign.is_empty() {
                return Err(CarbideError::InvalidArgument(format!(
                    "switch(es) [{}] do not belong to rack {rack_id}",
                    foreign
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(", "),
                ))
                .into());
            }
        }

        if !scope.power_shelf_ids.is_empty() {
            let rack_power_shelves: HashSet<PowerShelfId> = db_power_shelf::find_ids(
                reader.as_mut(),
                model::power_shelf::PowerShelfSearchFilter {
                    rack_id: Some(rack_id.clone()),
                    ..Default::default()
                },
            )
            .await
            .map_err(CarbideError::from)?
            .into_iter()
            .collect();

            let foreign: Vec<_> = scope
                .power_shelf_ids
                .iter()
                .filter(|id| !rack_power_shelves.contains(id))
                .collect();
            if !foreign.is_empty() {
                return Err(CarbideError::InvalidArgument(format!(
                    "power shelf/shelves [{}] do not belong to rack {rack_id}",
                    foreign
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(", "),
                ))
                .into());
            }
        }
    }

    let access_token_stored = maintenance_access_token.is_some();
    if let Some(token) = maintenance_access_token {
        api.credential_manager
            .set_credentials(
                &rack_maintenance_access_token_key(&rack_id),
                &Credentials::UsernamePassword {
                    username: "access_token".into(),
                    password: token,
                },
            )
            .await
            .map_err(|error| CarbideError::Internal {
                message: format!("failed to store rack maintenance access token: {error}"),
            })?;
    }

    let mut updated_config = rack.config.clone();
    updated_config.maintenance_requested = Some(scope);

    let db_result: Result<(), Status> = async {
        let mut txn = api.txn_begin().await?;
        db_rack::update(&mut txn, &rack_id, &updated_config).await?;
        if updated_config
            .maintenance_requested
            .as_ref()
            .is_some_and(|scope| {
                scope.should_run(&MaintenanceActivity::FirmwareUpgrade {
                    firmware_version: None,
                    components: vec![],
                    force_update: false,
                })
            })
        {
            db_rack::update_firmware_upgrade_job(txn.as_mut(), &rack_id, None).await?;
        }
        txn.commit().await?;
        Ok(())
    }
    .await;
    if let Err(status) = db_result {
        if access_token_stored
            && let Err(error) = api
                .credential_manager
                .delete_credentials(&rack_maintenance_access_token_key(&rack_id))
                .await
        {
            tracing::warn!(
                rack_id = %rack_id,
                error = %error,
                "failed to delete rack maintenance access token after DB error",
            );
        }
        return Err(status);
    }

    tracing::info!(
        rack_id = %rack_id,
        "On-demand maintenance scheduled",
    );

    Ok(Response::new(rpc::RackMaintenanceOnDemandResponse {}))
}
