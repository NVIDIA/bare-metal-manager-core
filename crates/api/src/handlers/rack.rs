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
use std::str::FromStr;

use ::rpc::errors::RpcDataConversionError;
use ::rpc::forge::{self as rpc, HealthReportEntry};
use carbide_uuid::rack::RackId;
use db::{
    ObjectColumnFilter, WithTransaction, expected_machine as db_expected_machine,
    expected_power_shelf as db_expected_power_shelf, expected_switch as db_expected_switch,
    machine as db_machine, power_shelf as db_power_shelf, rack as db_rack, switch as db_switch,
};
use futures_util::FutureExt;
use health_report::HealthReportApplyMode;
use model::machine::machine_search_config::MachineSearchConfig;
use model::metadata::Metadata;
use tonic::{Request, Response, Status};

use crate::CarbideError;
use crate::api::{Api, log_request_data};
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
            .map_err(|e| CarbideError::InvalidArgument(format!("Invalid rack ID: {}", e)))?;
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
        let machine_ids = db_machine::find_machine_ids(
            reader.as_mut(),
            MachineSearchConfig {
                rack_id: Some(r.id.clone()),
                ..Default::default()
            },
        )
        .await?;
        let switch_ids = db_switch::find_ids(
            reader.as_mut(),
            model::switch::SwitchSearchFilter {
                rack_id: Some(r.id.clone()),
                ..Default::default()
            },
        )
        .await?;
        let power_shelf_ids = db_power_shelf::find_ids(
            reader.as_mut(),
            model::power_shelf::PowerShelfSearchFilter {
                rack_id: Some(r.id.clone()),
                ..Default::default()
            },
        )
        .await?;

        let mut rpc_rack: rpc::Rack = r.into();
        rpc_rack.compute_trays = machine_ids;
        rpc_rack.switches = switch_ids;
        rpc_rack.power_shelves = power_shelf_ids;
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
        let machine_ids = db_machine::find_machine_ids(
            &mut txn,
            MachineSearchConfig {
                rack_id: Some(rack.id.clone()),
                ..Default::default()
            },
        )
        .await?;
        let switch_ids = db_switch::find_ids(
            &mut txn,
            model::switch::SwitchSearchFilter {
                rack_id: Some(rack.id.clone()),
                ..Default::default()
            },
        )
        .await?;
        let power_shelf_ids = db_power_shelf::find_ids(
            &mut txn,
            model::power_shelf::PowerShelfSearchFilter {
                rack_id: Some(rack.id.clone()),
                ..Default::default()
            },
        )
        .await?;

        let expected_compute_trays =
            db_expected_machine::find_all_by_rack_id(&mut txn, &rack.id).await?;
        let expected_power_shelves =
            db_expected_power_shelf::find_all_by_rack_id(&mut txn, &rack.id).await?;
        let expected_nvlink_switches =
            db_expected_switch::find_all_by_rack_id(&mut txn, &rack.id).await?;
        let mut rpc_rack: rpc::Rack = rack.into();
        rpc_rack.compute_trays = machine_ids;
        rpc_rack.switches = switch_ids;
        rpc_rack.power_shelves = power_shelf_ids;
        rpc_rack.expected_compute_trays = expected_compute_trays
            .into_iter()
            .map(|e| e.bmc_mac_address.to_string())
            .collect();
        rpc_rack.expected_power_shelves = expected_power_shelves
            .into_iter()
            .map(|e| e.bmc_mac_address.to_string())
            .collect();
        rpc_rack.expected_nvlink_switches = expected_nvlink_switches
            .into_iter()
            .map(|e| e.bmc_mac_address.to_string())
            .collect();

        result.push(rpc_rack);
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

    let results = db::rack_state_history::find_by_rack_ids(&mut txn, &rack_ids)
        .await
        .map_err(CarbideError::from)?;

    let mut response = rpc::StateHistories::default();
    for (rack_id, records) in results {
        response.histories.insert(
            rack_id.to_string(),
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
                .map_err(|e| CarbideError::InvalidArgument(format!("Invalid rack ID: {}", e)))?;
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

pub async fn list_rack_health_report_overrides(
    api: &Api,
    request: Request<rpc::ListRackHealthReportOverridesRequest>,
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

pub async fn insert_rack_health_report_override(
    api: &Api,
    request: Request<rpc::InsertRackHealthReportOverrideRequest>,
) -> Result<Response<()>, Status> {
    log_request_data(&request);

    let triggered_by = request
        .extensions()
        .get::<AuthContext>()
        .and_then(|ctx| ctx.get_external_user_name())
        .map(String::from);

    let rpc::InsertRackHealthReportOverrideRequest {
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

    db_rack::insert_health_report_override(&mut txn, &rack.id, mode, &report).await?;

    txn.commit().await?;

    Ok(Response::new(()))
}

pub async fn remove_rack_health_report_override(
    api: &Api,
    request: Request<rpc::RemoveRackHealthReportOverrideRequest>,
) -> Result<Response<()>, Status> {
    log_request_data(&request);

    let rpc::RemoveRackHealthReportOverrideRequest { rack_id, source } = request.into_inner();
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

    db_rack::remove_health_report_override(&mut *txn, &rack.id, mode, &source).await?;

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
