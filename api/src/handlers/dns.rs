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

use crate::api::{Api, log_request_data};

use crate::CarbideError;
use crate::db::{self, DatabaseError};

pub(crate) async fn lookup_record(
    api: &Api,
    request: Request<rpc::dns_message::DnsQuestion>,
) -> Result<Response<rpc::dns_message::DnsResponse>, Status> {
    log_request_data(&request);

    let mut txn = api
        .database_connection
        .begin()
        .await
        .map_err(|e| DatabaseError::txn_begin("lookup_record", e))?;

    let rpc::dns_message::DnsQuestion {
        q_name,
        q_type,
        q_class: _,
    } = request.into_inner();

    let Some(q_name) = q_name else {
        return Err(CarbideError::MissingArgument("q_name").into());
    };

    if q_name.is_empty() {
        return Err(CarbideError::InvalidArgument("q_name is empty".to_string()).into());
    }

    if q_type != Some(1) {
        return Err(CarbideError::InvalidArgument("q_type must be 1".to_string()).into());
    }

    let resource_record = db::resource_record::find(&mut txn, &q_name)
        .await?
        .ok_or_else(|| CarbideError::NotFoundError {
            kind: "dns_record",
            id: q_name,
        })?;

    Ok(Response::new(rpc::dns_message::DnsResponse {
        rrs: vec![resource_record.into()],
    }))
}
