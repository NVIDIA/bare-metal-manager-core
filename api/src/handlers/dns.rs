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

use crate::api::{log_request_data, Api};

use crate::db::resource_record::DnsQuestion;
use crate::db::DatabaseError;
use crate::CarbideError;

pub(crate) async fn lookup_record(
    api: &Api,
    request: Request<rpc::dns_message::DnsQuestion>,
) -> Result<Response<rpc::dns_message::DnsResponse>, Status> {
    log_request_data(&request);

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin lookup_record",
            e,
        ))
    })?;

    let rpc::dns_message::DnsQuestion {
        q_name,
        q_type,
        q_class,
    } = request.into_inner();

    let question = match q_name.clone() {
        Some(q_name) => DnsQuestion {
            query_name: Some(q_name),
            query_type: q_type,
            query_class: q_class,
        },
        None => {
            return Err(Status::invalid_argument(
                "A valid q_name, q_type and q_class are required",
            ));
        }
    };

    let response = DnsQuestion::find_record(&mut txn, question)
        .await
        .map(|dnsrr| rpc::dns_message::DnsResponse {
            rcode: dnsrr.response_code,
            rrs: dnsrr
                .resource_records
                .into_iter()
                .map(|r| r.into())
                .collect(),
        })
        .map_err(CarbideError::from)?;
    tracing::info!(DnsResponse = ?response, "lookup_record dns responded");

    Ok(Response::new(response))
}
