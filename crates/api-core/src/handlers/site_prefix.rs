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

use ::rpc::forge as rpc;
use tonic::{Request, Response, Status};

use crate::CarbideError;
use crate::api::{Api, log_request_data};

pub(crate) async fn find_ids(
    api: &Api,
    request: Request<rpc::SitePrefixSearchFilter>,
) -> Result<Response<rpc::SitePrefixIdList>, Status> {
    log_request_data(&request);

    let filter: model::site_prefix::SitePrefixSearchFilter = request.into_inner().try_into()?;
    let site_prefix_ids = db::site_prefix::find_ids(&api.database_connection, filter).await?;

    Ok(Response::new(rpc::SitePrefixIdList { site_prefix_ids }))
}

pub(crate) async fn find_by_ids(
    api: &Api,
    request: Request<rpc::SitePrefixesByIdsRequest>,
) -> Result<Response<rpc::SitePrefixList>, Status> {
    log_request_data(&request);

    let site_prefix_ids = request.into_inner().site_prefix_ids;
    if site_prefix_ids.is_empty() {
        return Err(
            CarbideError::InvalidArgument("at least one ID must be provided".to_string()).into(),
        );
    }

    let max_find_by_ids = api.runtime_config.max_find_by_ids as usize;
    if site_prefix_ids.len() > max_find_by_ids {
        return Err(CarbideError::InvalidArgument(format!(
            "no more than {max_find_by_ids} IDs can be accepted"
        ))
        .into());
    }

    let site_prefixes =
        db::site_prefix::find_by_ids(&api.database_connection, site_prefix_ids.as_slice())
            .await?
            .into_iter()
            .map(Into::into)
            .collect();

    Ok(Response::new(rpc::SitePrefixList { site_prefixes }))
}
