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

use ::rpc::errors::RpcDataConversionError;
use ::rpc::forge::{self as rpc, HealthReportEntry};
use db::{ObjectColumnFilter, switch as db_switch};
use health_report::HealthReportApplyMode;
use model::metadata::Metadata;
use tonic::{Request, Response, Status};

use crate::CarbideError;
use crate::api::{Api, log_request_data};
use crate::auth::AuthContext;

pub async fn find_switch(
    api: &Api,
    request: Request<rpc::SwitchQuery>,
) -> Result<Response<rpc::SwitchList>, Status> {
    let query = request.into_inner();
    let mut txn = api
        .database_connection
        .begin()
        .await
        .map_err(|e| CarbideError::Internal {
            message: format!("Database error: {}", e),
        })?;

    // Handle ID search (takes precedence)
    let switch_list = if let Some(id) = query.switch_id {
        db_switch::find_by(
            &mut txn,
            db::ObjectColumnFilter::One(db_switch::IdColumn, &id),
        )
        .await
        .map_err(|e| CarbideError::Internal {
            message: format!("Failed to find switch: {}", e),
        })?
    } else if let Some(name) = query.name {
        // Handle name search
        db_switch::find_by(
            &mut txn,
            db::ObjectColumnFilter::One(db_switch::NameColumn, &name),
        )
        .await
        .map_err(|e| CarbideError::Internal {
            message: format!("Failed to find switch: {}", e),
        })?
    } else {
        // No filter - return all
        db_switch::find_by(&mut txn, db::ObjectColumnFilter::<db_switch::IdColumn>::All)
            .await
            .map_err(|e| CarbideError::Internal {
                message: format!("Failed to find switch: {}", e),
            })?
    };

    let bmc_info_map: std::collections::HashMap<String, rpc::BmcInfo> = {
        let rows = db_switch::list_switch_bmc_info(&mut txn)
            .await
            .map_err(|e| CarbideError::Internal {
                message: format!("Failed to get switch BMC info: {}", e),
            })?;

        rows.into_iter()
            .map(|row| {
                (
                    row.serial_number,
                    rpc::BmcInfo {
                        ip: Some(row.ip_address.to_string()),
                        mac: Some(row.bmc_mac_address.to_string()),
                        version: None,
                        firmware_version: None,
                        port: None,
                    },
                )
            })
            .collect()
    };

    txn.commit().await.map_err(|e| CarbideError::Internal {
        message: format!("Failed to commit transaction: {}", e),
    })?;

    let switches: Vec<rpc::Switch> = switch_list
        .into_iter()
        .map(|s| {
            let serial = s.config.name.clone();
            let bmc_info = bmc_info_map.get(&serial).cloned();

            rpc::Switch::try_from(s).map(|mut rpc_switch| {
                rpc_switch.bmc_info = bmc_info;
                rpc_switch
            })
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| CarbideError::Internal {
            message: format!("Failed to convert switch: {}", e),
        })?;

    Ok(Response::new(rpc::SwitchList { switches }))
}

pub async fn find_ids(
    api: &Api,
    request: Request<rpc::SwitchSearchFilter>,
) -> Result<Response<rpc::SwitchIdList>, Status> {
    log_request_data(&request);

    let filter: model::switch::SwitchSearchFilter = request.into_inner().into();

    let switch_ids = db_switch::find_ids(&api.database_connection, filter).await?;

    Ok(Response::new(rpc::SwitchIdList { ids: switch_ids }))
}

pub async fn find_by_ids(
    api: &Api,
    request: Request<rpc::SwitchesByIdsRequest>,
) -> Result<Response<rpc::SwitchList>, Status> {
    log_request_data(&request);

    let switch_ids = request.into_inner().switch_ids;

    let max_find_by_ids = api.runtime_config.max_find_by_ids as usize;
    if switch_ids.len() > max_find_by_ids {
        return Err(CarbideError::InvalidArgument(format!(
            "no more than {max_find_by_ids} IDs can be accepted"
        ))
        .into());
    } else if switch_ids.is_empty() {
        return Err(
            CarbideError::InvalidArgument("at least one ID must be provided".to_string()).into(),
        );
    }

    let mut txn = api.txn_begin().await?;

    let switch_list = db_switch::find_by(
        &mut txn,
        ObjectColumnFilter::List(db_switch::IdColumn, &switch_ids),
    )
    .await?;

    let bmc_info_map: std::collections::HashMap<_, _> = {
        let rows = db_switch::find_bmc_info_by_switch_ids(&mut txn, &switch_ids)
            .await
            .map_err(|e| CarbideError::Internal {
                message: format!("Failed to get switch BMC info: {}", e),
            })?;

        rows.into_iter()
            .map(|row| {
                (
                    row.switch_id,
                    rpc::BmcInfo {
                        ip: Some(row.bmc_ip.to_string()),
                        mac: Some(row.bmc_mac.to_string()),
                        version: None,
                        firmware_version: None,
                        port: None,
                    },
                )
            })
            .collect()
    };

    let _ = txn.rollback().await;

    let switches: Vec<rpc::Switch> = switch_list
        .into_iter()
        .map(|s| {
            let id = s.id;
            let bmc_info = bmc_info_map.get(&id).cloned();

            rpc::Switch::try_from(s).map(|mut rpc_switch| {
                rpc_switch.bmc_info = bmc_info;
                rpc_switch
            })
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| CarbideError::Internal {
            message: format!("Failed to convert switch: {}", e),
        })?;

    Ok(Response::new(rpc::SwitchList { switches }))
}

pub async fn find_switch_state_histories(
    api: &Api,
    request: Request<rpc::SwitchStateHistoriesRequest>,
) -> Result<Response<rpc::StateHistories>, Status> {
    log_request_data(&request);
    let request = request.into_inner();
    let switch_ids = request.switch_ids;

    let max_find_by_ids = api.runtime_config.max_find_by_ids as usize;
    if switch_ids.len() > max_find_by_ids {
        return Err(CarbideError::InvalidArgument(format!(
            "no more than {max_find_by_ids} IDs can be accepted"
        ))
        .into());
    } else if switch_ids.is_empty() {
        return Err(
            CarbideError::InvalidArgument("at least one ID must be provided".to_string()).into(),
        );
    }

    let mut txn = api.txn_begin().await?;

    let results = db::switch_state_history::find_by_switch_ids(&mut txn, &switch_ids)
        .await
        .map_err(CarbideError::from)?;

    let mut response = rpc::StateHistories::default();
    for (switch_id, records) in results {
        response.histories.insert(
            switch_id.to_string(),
            ::rpc::forge::StateHistoryRecords {
                records: records.into_iter().map(Into::into).collect(),
            },
        );
    }

    txn.commit().await?;

    Ok(tonic::Response::new(response))
}

// TODO: block if switch is in use (firmware update, etc.)
pub async fn delete_switch(
    api: &Api,
    request: Request<rpc::SwitchDeletionRequest>,
) -> Result<Response<rpc::SwitchDeletionResult>, Status> {
    let req = request.into_inner();

    let switch_id = match req.id {
        Some(id) => id,
        None => {
            return Err(CarbideError::InvalidArgument("Switch ID is required".to_string()).into());
        }
    };

    let mut txn = api
        .database_connection
        .begin()
        .await
        .map_err(|e| CarbideError::Internal {
            message: format!("Database error: {}", e),
        })?;

    let mut switch_list = db_switch::find_by(
        &mut txn,
        db::ObjectColumnFilter::One(db_switch::IdColumn, &switch_id),
    )
    .await
    .map_err(|e| CarbideError::Internal {
        message: format!("Failed to find switch: {}", e),
    })?;

    if switch_list.is_empty() {
        return Err(CarbideError::NotFoundError {
            kind: "switch",
            id: switch_id.to_string(),
        }
        .into());
    }

    let switch = switch_list.first_mut().unwrap();
    db_switch::mark_as_deleted(switch, &mut txn)
        .await
        .map_err(|e| CarbideError::Internal {
            message: format!("Failed to delete switch: {}", e),
        })?;

    txn.commit().await.map_err(|e| CarbideError::Internal {
        message: format!("Failed to commit transaction: {}", e),
    })?;

    Ok(Response::new(rpc::SwitchDeletionResult {}))
}

/// Force deletes a switch and optionally its associated interfaces from the database.
/// Unlike `delete_switch` (soft delete), this immediately hard-deletes the switch,
/// its state history, and optionally its machine interfaces.
pub async fn admin_force_delete_switch(
    api: &Api,
    request: Request<rpc::AdminForceDeleteSwitchRequest>,
) -> Result<Response<rpc::AdminForceDeleteSwitchResponse>, Status> {
    log_request_data(&request);
    let request = request.into_inner();

    let switch_id = request
        .switch_id
        .ok_or_else(|| CarbideError::InvalidArgument("switch_id is required".to_string()))?;

    let mut txn = api.txn_begin().await?;

    // Verify the switch exists.
    let switch_list = db_switch::find_by(
        &mut txn,
        ObjectColumnFilter::One(db_switch::IdColumn, &switch_id),
    )
    .await
    .map_err(CarbideError::from)?;

    if switch_list.is_empty() {
        return Err(CarbideError::NotFoundError {
            kind: "switch",
            id: switch_id.to_string(),
        }
        .into());
    }

    // Optionally delete associated machine interfaces.
    let mut interfaces_deleted: u32 = 0;
    if request.delete_interfaces {
        let interface_ids = db::machine_interface::find_ids_by_switch_id(&mut txn, &switch_id)
            .await
            .map_err(CarbideError::from)?;
        for interface_id in &interface_ids {
            db::machine_interface::delete(interface_id, &mut txn)
                .await
                .map_err(CarbideError::from)?;
        }
        interfaces_deleted = interface_ids.len() as u32;
    }

    // Delete state history.
    db::switch_state_history::delete_by_switch_id(&mut txn, &switch_id)
        .await
        .map_err(CarbideError::from)?;

    // Hard-delete the switch.
    db_switch::final_delete(switch_id, &mut txn)
        .await
        .map_err(CarbideError::from)?;

    txn.commit().await?;

    Ok(Response::new(rpc::AdminForceDeleteSwitchResponse {
        switch_id: switch_id.to_string(),
        interfaces_deleted,
    }))
}

pub(crate) async fn update_switch_metadata(
    api: &Api,
    request: Request<rpc::SwitchMetadataUpdateRequest>,
) -> std::result::Result<tonic::Response<()>, tonic::Status> {
    log_request_data(&request);
    let request = request.into_inner();
    let switch_id = request
        .switch_id
        .ok_or_else(|| CarbideError::from(RpcDataConversionError::MissingArgument("switch_id")))?;

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

    let switches = db_switch::find_by(
        &mut txn,
        db::ObjectColumnFilter::One(db_switch::IdColumn, &switch_id),
    )
    .await
    .map_err(CarbideError::from)?;

    let switch = switches
        .into_iter()
        .next()
        .ok_or_else(|| CarbideError::NotFoundError {
            kind: "switch",
            id: switch_id.to_string(),
        })?;

    let expected_version: config_version::ConfigVersion = match request.if_version_match {
        Some(version) => version.parse().map_err(CarbideError::from)?,
        None => switch.version,
    };

    db_switch::update_metadata(&mut txn, &switch_id, expected_version, metadata).await?;

    txn.commit().await?;

    Ok(tonic::Response::new(()))
}

pub async fn list_switch_health_reports(
    api: &Api,
    request: Request<rpc::ListSwitchHealthReportsRequest>,
) -> Result<Response<rpc::ListHealthReportResponse>, Status> {
    log_request_data(&request);

    let req = request.into_inner();
    let switch_id = req
        .switch_id
        .ok_or_else(|| CarbideError::MissingArgument("switch_id"))?;

    let mut conn = api
        .database_connection
        .acquire()
        .await
        .map_err(|e| CarbideError::Internal {
            message: format!("Database error: {}", e),
        })?;

    let switch = db_switch::find_by_id(&mut conn, &switch_id)
        .await
        .map_err(CarbideError::from)?
        .ok_or_else(|| CarbideError::NotFoundError {
            kind: "switch",
            id: switch_id.to_string(),
        })?;

    Ok(Response::new(rpc::ListHealthReportResponse {
        health_report_entries: switch
            .health_reports
            .into_iter()
            .map(|o| HealthReportEntry {
                report: Some(o.0.into()),
                mode: o.1 as i32,
            })
            .collect(),
    }))
}

pub async fn insert_switch_health_report(
    api: &Api,
    request: Request<rpc::InsertSwitchHealthReportRequest>,
) -> Result<Response<()>, Status> {
    log_request_data(&request);

    let triggered_by = request
        .extensions()
        .get::<AuthContext>()
        .and_then(|ctx| ctx.get_external_user_name())
        .map(String::from);

    let rpc::InsertSwitchHealthReportRequest {
        switch_id,
        health_report_entry: Some(rpc::HealthReportEntry { report, mode }),
    } = request.into_inner()
    else {
        return Err(CarbideError::MissingArgument("override").into());
    };
    let switch_id = switch_id.ok_or_else(|| CarbideError::MissingArgument("switch_id"))?;

    let Some(report) = report else {
        return Err(CarbideError::MissingArgument("report").into());
    };
    let Ok(mode) = rpc::HealthReportApplyMode::try_from(mode) else {
        return Err(CarbideError::InvalidArgument("mode".to_string()).into());
    };
    let mode: HealthReportApplyMode = mode.into();

    let mut txn = api.txn_begin().await?;

    let switch = db_switch::find_by_id(&mut txn, &switch_id)
        .await
        .map_err(CarbideError::from)?
        .ok_or_else(|| CarbideError::NotFoundError {
            kind: "switch",
            id: switch_id.to_string(),
        })?;

    let mut report = health_report::HealthReport::try_from(report.clone())
        .map_err(|e| CarbideError::internal(e.to_string()))?;
    if report.observed_at.is_none() {
        report.observed_at = Some(chrono::Utc::now());
    }
    report.triggered_by = triggered_by;
    report.update_in_alert_since(None);

    match remove_switch_health_report_by_source(&switch, &mut txn, report.source.clone()).await {
        Ok(_) | Err(CarbideError::NotFoundError { .. }) => {}
        Err(e) => return Err(e.into()),
    }

    db_switch::insert_health_report(&mut txn, &switch_id, mode, &report).await?;

    txn.commit().await?;

    Ok(Response::new(()))
}

pub async fn remove_switch_health_report(
    api: &Api,
    request: Request<rpc::RemoveSwitchHealthReportRequest>,
) -> Result<Response<()>, Status> {
    log_request_data(&request);

    let rpc::RemoveSwitchHealthReportRequest { switch_id, source } = request.into_inner();
    let switch_id = switch_id.ok_or_else(|| CarbideError::MissingArgument("switch_id"))?;

    let mut txn = api.txn_begin().await?;

    let switch = db_switch::find_by_id(&mut txn, &switch_id)
        .await
        .map_err(CarbideError::from)?
        .ok_or_else(|| CarbideError::NotFoundError {
            kind: "switch",
            id: switch_id.to_string(),
        })?;

    remove_switch_health_report_by_source(&switch, &mut txn, source).await?;
    txn.commit().await?;

    Ok(Response::new(()))
}

async fn remove_switch_health_report_by_source(
    switch: &model::switch::Switch,
    txn: &mut db::Transaction<'_>,
    source: String,
) -> Result<(), CarbideError> {
    let mode = if switch.health_reports.replace.as_ref().map(|o| &o.source) == Some(&source) {
        HealthReportApplyMode::Replace
    } else if switch.health_reports.merges.contains_key(&source) {
        HealthReportApplyMode::Merge
    } else {
        return Err(CarbideError::NotFoundError {
            kind: "switch health report with source",
            id: source,
        });
    };

    db_switch::remove_health_report(&mut *txn, &switch.id, mode, &source).await?;

    Ok(())
}
