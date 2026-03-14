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

use tonic::{Request, Response, Status};
use uuid::Uuid;

use crate::api::Api;
use crate::api::rpc;

fn row_to_proto(
    row: &db::operating_system::OperatingSystemRow,
) -> Result<rpc::StoredOperatingSystem, Status> {
    let os_image_id = row.os_image_id.map(|id| ::rpc::common::Uuid {
        value: id.to_string(),
    });

    let ipxe_parameters = row
        .ipxe_parameters
        .as_ref()
        .and_then(|j| j.0.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| {
                    let obj = v.as_object()?;
                    Some(rpc::IpxeOsParameter {
                        name: obj.get("name")?.as_str()?.to_string(),
                        value: obj.get("value")?.as_str().unwrap_or("").to_string(),
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let ipxe_artifacts = row
        .ipxe_artifacts
        .as_ref()
        .and_then(|j| j.0.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| {
                    let obj = v.as_object()?;
                    Some(rpc::IpxeOsArtifact {
                        name: obj.get("name")?.as_str()?.to_string(),
                        url: obj.get("url")?.as_str().unwrap_or("").to_string(),
                        sha: obj.get("sha").and_then(|v| v.as_str()).map(String::from),
                        auth_type: obj
                            .get("auth_type")
                            .and_then(|v| v.as_str())
                            .map(String::from),
                        auth_token: obj
                            .get("auth_token")
                            .and_then(|v| v.as_str())
                            .map(String::from),
                        cache_strategy: obj
                            .get("cache_strategy")
                            .and_then(|v| v.as_i64())
                            .unwrap_or(0) as i32,
                        local_url: obj
                            .get("local_url")
                            .and_then(|v| v.as_str())
                            .map(String::from),
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    Ok(rpc::StoredOperatingSystem {
        id: row.id.to_string(),
        name: row.name.clone(),
        description: row.description.clone(),
        org: row.org.clone(),
        r#type: row.type_.clone(),
        status: row.status.clone(),
        is_active: row.is_active,
        allow_override: row.allow_override,
        phone_home_enabled: row.phone_home_enabled,
        user_data: row.user_data.clone(),
        created: row.created.to_rfc3339(),
        updated: row.updated.to_rfc3339(),
        ipxe_script: row.ipxe_script.clone(),
        os_image_id,
        ipxe_template_name: row.ipxe_template_name.clone(),
        ipxe_parameters,
        ipxe_artifacts,
        ipxe_definition_hash: row.ipxe_definition_hash.clone(),
    })
}

fn parameters_to_json(params: &[rpc::IpxeOsParameter]) -> serde_json::Value {
    serde_json::Value::Array(
        params
            .iter()
            .map(|p| {
                serde_json::json!({
                    "name": p.name,
                    "value": p.value,
                })
            })
            .collect(),
    )
}

fn artifacts_to_json(artifacts: &[rpc::IpxeOsArtifact]) -> serde_json::Value {
    serde_json::Value::Array(
        artifacts
            .iter()
            .map(|a| {
                serde_json::json!({
                    "name": a.name,
                    "url": a.url,
                    "sha": a.sha,
                    "auth_type": a.auth_type,
                    "auth_token": a.auth_token,
                    "cache_strategy": a.cache_strategy,
                    "local_url": a.local_url,
                })
            })
            .collect(),
    )
}

pub async fn create_operating_system(
    api: &Api,
    request: Request<rpc::CreateOperatingSystemRequest>,
) -> Result<Response<rpc::StoredOperatingSystem>, Status> {
    let mut txn = api.txn_begin().await?;
    let req = request.into_inner();

    let (type_, ipxe_script, os_image_id, ipxe_template_name, ipxe_parameters, ipxe_artifacts) =
        if let Some(ref script) = req.ipxe_script {
            (
                "ipxe".to_string(),
                Some(script.clone()),
                None,
                None,
                None,
                None,
            )
        } else if let Some(ref img_id) = req.os_image_id {
            let id = Uuid::try_from(img_id.clone())
                .map_err(|e| Status::invalid_argument(format!("invalid os_image_id: {e}")))?;
            ("image".to_string(), None, Some(id), None, None, None)
        } else if let Some(ref tmpl) = req.ipxe_template_name {
            let params = if req.ipxe_parameters.is_empty() {
                None
            } else {
                Some(parameters_to_json(&req.ipxe_parameters))
            };
            let arts = if req.ipxe_artifacts.is_empty() {
                None
            } else {
                Some(artifacts_to_json(&req.ipxe_artifacts))
            };
            (
                "ipxe_os_definition".to_string(),
                None,
                None,
                Some(tmpl.clone()),
                params,
                arts,
            )
        } else {
            return Err(Status::invalid_argument(
                "exactly one OS variant must be specified: ipxe_script, os_image_id, or ipxe_template_name",
            ));
        };

    if req.name.is_empty() {
        return Err(Status::invalid_argument("name is required"));
    }
    if req.org.is_empty() {
        return Err(Status::invalid_argument("org is required"));
    }

    let input = db::operating_system::CreateOperatingSystem {
        name: req.name,
        description: req.description,
        org: req.org,
        type_,
        is_active: req.is_active,
        allow_override: req.allow_override,
        phone_home_enabled: req.phone_home_enabled,
        user_data: req.user_data,
        ipxe_script,
        os_image_id,
        ipxe_template_name,
        ipxe_parameters,
        ipxe_artifacts,
        ipxe_definition_hash: None,
    };

    let row = db::operating_system::create(&mut txn, &input)
        .await
        .map_err(|e| Status::internal(e.to_string()))?;
    txn.commit()
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

    Ok(Response::new(row_to_proto(&row)?))
}

pub async fn get_operating_system(
    api: &Api,
    request: Request<::rpc::Uuid>,
) -> Result<Response<rpc::StoredOperatingSystem>, Status> {
    let mut txn = api.txn_begin().await?;
    let id = Uuid::try_from(request.into_inner())
        .map_err(|e| Status::invalid_argument(e.to_string()))?;

    let row = db::operating_system::get(&mut txn, id).await.map_err(|e| {
        if e.is_not_found() {
            Status::not_found(format!("operating system {id} not found"))
        } else {
            Status::internal(e.to_string())
        }
    })?;
    txn.commit()
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

    Ok(Response::new(row_to_proto(&row)?))
}

pub async fn update_operating_system(
    api: &Api,
    request: Request<rpc::UpdateOperatingSystemRequest>,
) -> Result<Response<rpc::StoredOperatingSystem>, Status> {
    let mut txn = api.txn_begin().await?;
    let req = request.into_inner();

    let id_proto = req
        .id
        .ok_or_else(|| Status::invalid_argument("id is required"))?;
    let id = Uuid::try_from(id_proto)
        .map_err(|e| Status::invalid_argument(format!("invalid id: {e}")))?;

    let existing = db::operating_system::get(&mut txn, id).await.map_err(|e| {
        if e.is_not_found() {
            Status::not_found(format!("operating system {id} not found"))
        } else {
            Status::internal(e.to_string())
        }
    })?;

    let ipxe_parameters = if req.ipxe_parameters.is_empty() {
        None
    } else {
        Some(parameters_to_json(&req.ipxe_parameters))
    };
    let ipxe_artifacts = if req.ipxe_artifacts.is_empty() {
        None
    } else {
        Some(artifacts_to_json(&req.ipxe_artifacts))
    };

    let input = db::operating_system::UpdateOperatingSystem {
        id,
        name: req.name,
        description: req.description,
        is_active: req.is_active,
        allow_override: req.allow_override,
        phone_home_enabled: req.phone_home_enabled,
        user_data: req.user_data,
        ipxe_script: req.ipxe_script,
        ipxe_template_name: req.ipxe_template_name,
        ipxe_parameters,
        ipxe_artifacts,
    };

    let row = db::operating_system::update(&mut txn, &existing, &input)
        .await
        .map_err(|e| Status::internal(e.to_string()))?;
    txn.commit()
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

    Ok(Response::new(row_to_proto(&row)?))
}

pub async fn delete_operating_system(
    api: &Api,
    request: Request<rpc::DeleteOperatingSystemRequest>,
) -> Result<Response<rpc::DeleteOperatingSystemResponse>, Status> {
    let mut txn = api.txn_begin().await?;
    let req = request.into_inner();

    let id_proto = req
        .id
        .ok_or_else(|| Status::invalid_argument("id is required"))?;
    let id = Uuid::try_from(id_proto)
        .map_err(|e| Status::invalid_argument(format!("invalid id: {e}")))?;

    db::operating_system::delete(&mut txn, id)
        .await
        .map_err(|e| {
            if e.is_not_found() {
                Status::not_found(format!("operating system {id} not found"))
            } else {
                Status::internal(e.to_string())
            }
        })?;
    txn.commit()
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

    Ok(Response::new(rpc::DeleteOperatingSystemResponse {}))
}

pub async fn list_operating_systems(
    api: &Api,
    request: Request<rpc::ListOperatingSystemsRequest>,
) -> Result<Response<rpc::ListOperatingSystemsResponse>, Status> {
    let mut txn = api.txn_begin().await?;
    let req = request.into_inner();

    let rows = db::operating_system::list(&mut txn, req.org.as_deref())
        .await
        .map_err(|e| Status::internal(e.to_string()))?;
    txn.commit()
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

    let operating_systems = rows
        .iter()
        .map(row_to_proto)
        .collect::<Result<Vec<_>, _>>()?;

    Ok(Response::new(rpc::ListOperatingSystemsResponse {
        operating_systems,
    }))
}
