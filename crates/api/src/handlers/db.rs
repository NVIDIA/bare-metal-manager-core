/*
 * SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

pub(crate) async fn trim_table(
    api: &Api,
    request: Request<rpc::TrimTableRequest>,
) -> Result<Response<rpc::TrimTableResponse>, Status> {
    log_request_data(&request);

    let mut txn = api.txn_begin().await?;

    let total_deleted = db::trim_table::trim_table(
        &mut txn,
        request.get_ref().target(),
        request.get_ref().keep_entries,
    )
    .await?;

    txn.commit().await?;

    Ok(Response::new(rpc::TrimTableResponse {
        total_deleted: total_deleted.to_string(),
    }))
}
