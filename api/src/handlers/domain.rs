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

use crate::CarbideError;
use crate::api::Api;
use crate::db::domain::{self};
use crate::db::{self, DatabaseError, ObjectColumnFilter};
use crate::model::domain::NewDomain;

pub(crate) async fn create(
    api: &Api,
    request: Request<rpc::Domain>,
) -> Result<Response<rpc::Domain>, Status> {
    crate::api::log_request_data(&request);

    const DB_TXN_NAME: &str = "create_domain";
    let mut txn = api
        .database_connection
        .begin()
        .await
        .map_err(|e| DatabaseError::txn_begin(DB_TXN_NAME, e))?;

    let response = Ok(
        db::domain::persist(NewDomain::try_from(request.into_inner())?, &mut txn)
            .await
            .map(rpc::Domain::from)
            .map(Response::new)?,
    );

    txn.commit()
        .await
        .map_err(|e| DatabaseError::txn_commit(DB_TXN_NAME, e))?;

    response
}

pub(crate) async fn update(
    api: &Api,
    request: Request<rpc::Domain>,
) -> Result<Response<rpc::Domain>, Status> {
    crate::api::log_request_data(&request);

    const DB_TXN_NAME: &str = "update_domain";
    let mut txn = api
        .database_connection
        .begin()
        .await
        .map_err(|e| DatabaseError::txn_begin(DB_TXN_NAME, e))?;

    let rpc::Domain { id, name, .. } = request.into_inner();

    let uuid = id.ok_or_else(|| CarbideError::MissingArgument("id"))?;

    let mut domains =
        db::domain::find_by(&mut txn, ObjectColumnFilter::One(domain::IdColumn, &uuid)).await?;

    let mut dom = match domains.len() {
        0 => {
            return Err(CarbideError::NotFoundError {
                kind: "domain",
                id: uuid.to_string(),
            }
            .into());
        }
        1 => domains.remove(0),
        _ => {
            return Err(Status::internal(
                "Found more than one domain with the specified UUID",
            ));
        }
    };

    dom.name = name;
    let response = Ok(db::domain::update(&mut dom, &mut txn)
        .await
        .map(rpc::Domain::from)
        .map(Response::new)?);

    txn.commit()
        .await
        .map_err(|e| DatabaseError::txn_commit(DB_TXN_NAME, e))?;

    response
}

pub(crate) async fn delete(
    api: &Api,
    request: Request<rpc::DomainDeletion>,
) -> Result<Response<rpc::DomainDeletionResult>, Status> {
    crate::api::log_request_data(&request);

    const DB_TXN_NAME: &str = "delete_domain";
    let mut txn = api
        .database_connection
        .begin()
        .await
        .map_err(|e| DatabaseError::txn_begin(DB_TXN_NAME, e))?;

    let rpc::DomainDeletion { id, .. } = request.into_inner();

    // load from find from domain.rs
    let uuid = id.ok_or_else(|| CarbideError::MissingArgument("id"))?;

    let mut domains =
        db::domain::find_by(&mut txn, ObjectColumnFilter::One(domain::IdColumn, &uuid)).await?;

    let dom = match domains.len() {
        0 => {
            return Err(CarbideError::NotFoundError {
                kind: "domain",
                id: uuid.to_string(),
            }
            .into());
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

    let response = Ok(db::domain::delete(dom, &mut txn)
        .await
        .map(|_| rpc::DomainDeletionResult {})
        .map(Response::new)?);

    txn.commit()
        .await
        .map_err(|e| DatabaseError::txn_commit(DB_TXN_NAME, e))?;

    response
}

pub(crate) async fn find(
    api: &Api,
    request: Request<rpc::DomainSearchQuery>,
) -> Result<Response<rpc::DomainList>, Status> {
    crate::api::log_request_data(&request);

    let mut txn = api
        .database_connection
        .begin()
        .await
        .map_err(|e| DatabaseError::txn_begin("find_domain", e))?;

    let rpc::DomainSearchQuery { id, name, .. } = request.into_inner();
    let domains = match (id, name) {
        (Some(id), _) => {
            db::domain::find_by(&mut txn, ObjectColumnFilter::One(domain::IdColumn, &id)).await
        }
        (None, Some(name)) => db::domain::find_by_name(&mut txn, &name).await,
        (None, None) => {
            db::domain::find_by(&mut txn, ObjectColumnFilter::<domain::IdColumn>::All).await
        }
    };

    let result = domains
        .map(|domain| rpc::DomainList {
            domains: domain.into_iter().map(rpc::Domain::from).collect(),
        })
        .map(Response::new)
        .map_err(CarbideError::from)?;

    Ok(result)
}
