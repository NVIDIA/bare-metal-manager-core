/*
 * SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use ::rpc::forge as rpc;
use tonic::{Request, Response, Status};
use uuid::Uuid;

use crate::api::Api;
use crate::db::domain::Domain;
use crate::db::domain::NewDomain;
use crate::db::DatabaseError;
use crate::db::UuidKeyedObjectFilter;
use crate::CarbideError;

pub(crate) async fn create(
    api: &Api,
    request: Request<rpc::Domain>,
) -> Result<Response<rpc::Domain>, Status> {
    crate::api::log_request_data(&request);

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin create_domain",
            e,
        ))
    })?;

    let response = Ok(NewDomain::try_from(request.into_inner())?
        .persist(&mut txn)
        .await
        .map(rpc::Domain::from)
        .map(Response::new)?);
    txn.commit().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "commit create_domain",
            e,
        ))
    })?;

    response
}

pub(crate) async fn update(
    api: &Api,
    request: Request<rpc::Domain>,
) -> Result<Response<rpc::Domain>, Status> {
    crate::api::log_request_data(&request);

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin update_domain",
            e,
        ))
    })?;

    let rpc::Domain { id, name, .. } = request.into_inner();

    // TODO(jdg): Move this out into a function and share it with delete
    let uuid = match id {
        Some(id) => match Uuid::try_from(id) {
            Ok(uuid) => uuid,
            Err(_err) => {
                return Err(CarbideError::InvalidArgument("id".to_string()).into());
            }
        },
        None => {
            return Err(CarbideError::MissingArgument("id").into());
        }
    };

    let mut domains = Domain::find(&mut txn, UuidKeyedObjectFilter::One(uuid))
        .await
        .map_err(CarbideError::from)?;

    let mut dom = match domains.len() {
        0 => {
            return Err(CarbideError::NotFoundError {
                kind: "domain",
                id: uuid.to_string(),
            }
            .into())
        }
        1 => domains.remove(0),
        _ => {
            return Err(Status::internal(
                "Found more than one domain with the specified UUID",
            ));
        }
    };

    dom.name = name;
    let response = Ok(dom
        .update(&mut txn)
        .await
        .map_err(CarbideError::from)
        .map(rpc::Domain::from)
        .map(Response::new)?);

    txn.commit().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "commit update_domain",
            e,
        ))
    })?;

    response
}

pub(crate) async fn delete(
    api: &Api,
    request: Request<rpc::DomainDeletion>,
) -> Result<Response<rpc::DomainDeletionResult>, Status> {
    crate::api::log_request_data(&request);

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin delete_domain",
            e,
        ))
    })?;

    let rpc::DomainDeletion { id, .. } = request.into_inner();

    // load from find from domain.rs
    let uuid = match id {
        Some(id) => match Uuid::try_from(id) {
            Ok(uuid) => uuid,
            Err(_err) => {
                return Err(CarbideError::InvalidArgument("id".to_string()).into());
            }
        },
        None => {
            return Err(CarbideError::MissingArgument("id").into());
        }
    };

    let mut domains = Domain::find(&mut txn, UuidKeyedObjectFilter::One(uuid))
        .await
        .map_err(CarbideError::from)?;

    let dom = match domains.len() {
        0 => {
            return Err(CarbideError::NotFoundError {
                kind: "domain",
                id: uuid.to_string(),
            }
            .into())
        }
        1 => domains.remove(0),
        _ => {
            return Err(Status::internal(
                "Found more than one domain with the specified UUID",
            ));
        }
    };

    // TODO: This needs to validate that nothing references the domain anymore
    // (like NetworkSegments)

    let response = Ok(dom
        .delete(&mut txn)
        .await
        .map_err(CarbideError::from)
        .map(|_| rpc::DomainDeletionResult {})
        .map(Response::new)?);

    txn.commit().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "commit delete_domain",
            e,
        ))
    })?;

    response
}

pub(crate) async fn find(
    api: &Api,
    request: Request<rpc::DomainSearchQuery>,
) -> Result<Response<rpc::DomainList>, Status> {
    crate::api::log_request_data(&request);
    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(file!(), line!(), "begin find_domain", e))
    })?;

    let rpc::DomainSearchQuery { id, name, .. } = request.into_inner();
    let domains = match (id, name) {
        (Some(id), _) => {
            let uuid = match Uuid::try_from(id) {
                Ok(uuid) => UuidKeyedObjectFilter::One(uuid),
                Err(err) => {
                    return Err(Status::invalid_argument(format!(
                        "Invalid UUID supplied: {}",
                        err
                    )));
                }
            };
            Domain::find(&mut txn, uuid).await
        }
        (None, Some(name)) => Domain::find_by_name(&mut txn, &name).await,
        (None, None) => Domain::find(&mut txn, UuidKeyedObjectFilter::All).await,
    };

    let result = domains
        .map(|domain| rpc::DomainList {
            domains: domain.into_iter().map(rpc::Domain::from).collect(),
        })
        .map(Response::new)
        .map_err(CarbideError::from)?;

    Ok(result)
}
