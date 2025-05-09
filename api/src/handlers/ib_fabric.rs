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

pub(crate) async fn find_ids(
    api: &Api,
    request: Request<rpc::IbFabricSearchFilter>,
) -> Result<Response<rpc::IbFabricIdList>, Status> {
    log_request_data(&request);

    let _filter = request.into_inner();

    let config = api.ib_fabric_manager.get_config();
    let fabrics = config.endpoints.into_keys().collect();

    Ok(Response::new(rpc::IbFabricIdList {
        ib_fabric_ids: fabrics,
    }))
}
