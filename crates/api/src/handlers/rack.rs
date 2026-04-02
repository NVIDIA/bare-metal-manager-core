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

use futures_util::FutureExt;
use nico_api_db::{ObjectColumnFilter, WithTransaction, rack as db_rack};
use nico_api_model::metadata::Metadata;
use nico_health_report::OverrideMode;
use nico_rpc::errors::RpcDataConversionError;
use nico_rpc::forge;
use nico_rpc::forge::HealthReportOverride;
use nico_uuid::rack::RackId;
use tonic::{Request, Response, Status};

use crate::CarbideError;
use crate::api::{Api, log_request_data};
use crate::auth::AuthContext;

pub async fn get_rack(
    api: &Api,
    request: Request<forge::GetRackRequest>,
) -> Result<Response<forge::GetRackResponse>, Status> {
    log_request_data(&request);

    let req = request.into_inner();
    let rack = if let Some(id) = req.id {
        let rack_id = RackId::from_str(&id)
            .map_err(|e| CarbideError::InvalidArgument(format!("Invalid rack ID: {}", e)))?;
        let r = db_rack::get(&api.database_connection, &rack_id)
            .await
            .map_err(CarbideError::from)?;
        vec![r.into()]
    } else {
        db_rack::list(&api.database_connection)
            .await
            .map_err(CarbideError::from)?
            .into_iter()
            .map(|x| x.into())
            .collect()
    };
    Ok(Response::new(forge::GetRackResponse { rack }))
}

pub async fn find_ids(
    api: &Api,
    request: Request<forge::RackSearchFilter>,
) -> Result<Response<forge::RackIdList>, Status> {
    log_request_data(&request);

    let filter: nico_api_model::rack::RackSearchFilter = request.into_inner().into();

    let rack_ids = nico_api_db::rack::find_ids(&api.database_connection, filter).await?;

    Ok(Response::new(forge::RackIdList { rack_ids }))
}

pub async fn find_by_ids(
    api: &Api,
    request: Request<forge::RacksByIdsRequest>,
) -> Result<Response<forge::RackList>, Status> {
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

    let racks = nico_api_db::rack::find_by(
        &mut txn,
        ObjectColumnFilter::List(nico_api_db::rack::IdColumn, &rack_ids),
    )
    .await?;

    let _ = txn.rollback().await;

    let mut result = Vec::with_capacity(racks.len());
    for rack in racks {
        result.push(rack.into());
    }

    Ok(Response::new(forge::RackList { racks: result }))
}

pub async fn find_rack_state_histories(
    api: &Api,
    request: Request<forge::RackStateHistoriesRequest>,
) -> Result<Response<forge::RackStateHistories>, Status> {
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

    let results = nico_api_db::rack_state_history::find_by_rack_ids(&mut txn, &rack_ids)
        .await
        .map_err(CarbideError::from)?;

    let mut response = forge::RackStateHistories::default();
    for (rack_id, records) in results {
        response.histories.insert(
            rack_id.to_string(),
            forge::RackStateHistoryRecords {
                records: records.into_iter().map(Into::into).collect(),
            },
        );
    }

    txn.commit().await?;

    Ok(tonic::Response::new(response))
}

pub async fn delete_rack(
    api: &Api,
    request: Request<forge::DeleteRackRequest>,
) -> Result<Response<()>, Status> {
    log_request_data(&request);

    let req = request.into_inner();
    api.with_txn(|txn| {
        async move {
            let rack_id = RackId::from_str(&req.id)
                .map_err(|e| CarbideError::InvalidArgument(format!("Invalid rack ID: {}", e)))?;
            let _rack =
                db_rack::get(txn.as_mut(), &rack_id)
                    .await
                    .map_err(|e| CarbideError::Internal {
                        message: format!("Getting rack {}", e),
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
    request: Request<forge::ListRackHealthReportOverridesRequest>,
) -> Result<Response<forge::ListHealthReportOverrideResponse>, Status> {
    log_request_data(&request);

    let req = request.into_inner();
    let rack_id = req
        .rack_id
        .ok_or_else(|| CarbideError::MissingArgument("rack_id"))?;

    let rack = db_rack::get(&api.database_connection, &rack_id)
        .await
        .map_err(CarbideError::from)?;

    Ok(Response::new(forge::ListHealthReportOverrideResponse {
        overrides: rack
            .health_report_overrides
            .into_iter()
            .map(|o| HealthReportOverride {
                report: Some(o.0.into()),
                mode: o.1 as i32,
            })
            .collect(),
    }))
}

pub async fn insert_rack_health_report_override(
    api: &Api,
    request: Request<forge::InsertRackHealthReportOverrideRequest>,
) -> Result<Response<()>, Status> {
    log_request_data(&request);

    let triggered_by = request
        .extensions()
        .get::<AuthContext>()
        .and_then(|ctx| ctx.get_external_user_name())
        .map(String::from);

    let forge::InsertRackHealthReportOverrideRequest {
        rack_id,
        r#override: Some(forge::HealthReportOverride { report, mode }),
    } = request.into_inner()
    else {
        return Err(CarbideError::MissingArgument("override").into());
    };
    let rack_id = rack_id.ok_or_else(|| CarbideError::MissingArgument("rack_id"))?;

    let Some(report) = report else {
        return Err(CarbideError::MissingArgument("report").into());
    };
    let Ok(mode) = forge::OverrideMode::try_from(mode) else {
        return Err(CarbideError::InvalidArgument("mode".to_string()).into());
    };
    let mode: OverrideMode = mode.into();

    let mut txn = api.txn_begin().await?;

    let rack = db_rack::get(&mut txn, &rack_id)
        .await
        .map_err(CarbideError::from)?;

    let mut report = nico_health_report::HealthReport::try_from(report.clone())
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
    request: Request<forge::RemoveRackHealthReportOverrideRequest>,
) -> Result<Response<()>, Status> {
    log_request_data(&request);

    let forge::RemoveRackHealthReportOverrideRequest { rack_id, source } = request.into_inner();
    let rack_id = rack_id.ok_or_else(|| CarbideError::MissingArgument("rack_id"))?;

    let mut txn = api.txn_begin().await?;

    let rack = db_rack::get(&mut txn, &rack_id)
        .await
        .map_err(CarbideError::from)?;

    remove_rack_override_by_source(&rack, &mut txn, source).await?;
    txn.commit().await?;

    Ok(Response::new(()))
}

async fn remove_rack_override_by_source(
    rack: &nico_api_model::rack::Rack,
    txn: &mut nico_api_db::Transaction<'_>,
    source: String,
) -> Result<(), CarbideError> {
    let mode = if rack
        .health_report_overrides
        .replace
        .as_ref()
        .map(|o| &o.source)
        == Some(&source)
    {
        OverrideMode::Replace
    } else if rack.health_report_overrides.merges.contains_key(&source) {
        OverrideMode::Merge
    } else {
        return Err(CarbideError::NotFoundError {
            kind: "rack override with source",
            id: source,
        });
    };

    db_rack::remove_health_report_override(&mut *txn, &rack.id, mode, &source).await?;

    Ok(())
}

pub(crate) async fn update_rack_metadata(
    api: &Api,
    request: Request<forge::RackMetadataUpdateRequest>,
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

    let rack = db_rack::get(&mut txn, &rack_id)
        .await
        .map_err(CarbideError::from)?;

    let expected_version: config_version::ConfigVersion = match request.if_version_match {
        Some(version) => version.parse().map_err(CarbideError::from)?,
        None => rack.version,
    };

    db_rack::update_metadata(&mut txn, &rack_id, expected_version, metadata).await?;

    txn.commit().await?;

    Ok(tonic::Response::new(()))
}
