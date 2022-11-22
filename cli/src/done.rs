/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use tonic::Response;

use ::rpc::forge as rpc;
use cli::CarbideClientResult;

pub struct Done {}

impl Done {
    pub async fn run(
        api: String,
        machine_interface_id: uuid::Uuid,
    ) -> CarbideClientResult<Response<rpc::Machine>> {
        let mut client = rpc::forge_client::ForgeClient::connect(api).await?;
        let request = tonic::Request::new(machine_interface_id.into());
        Ok(client.done(request).await?)
    }
}
