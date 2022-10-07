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
use ::rpc::forge as rpc;

pub mod cloud_init;
pub mod ipxe;

pub struct RpcContext;

impl RpcContext {
    async fn get_instance(machine_id: rpc::Uuid, url: String) -> Result<rpc::Instance, String> {
        match rpc::forge_client::ForgeClient::connect(url).await {
            Ok(mut client) => {
                let request = tonic::Request::new(machine_id.clone());

                client
                    .find_instance_by_machine_id(request)
                    .await
                    .map(|response| response.into_inner())
                    .map_err(|error| {
                        format!(
                            "unable to find instance for machine {} via Carbide: {:?}",
                            machine_id, error
                        )
                    })
            }
            Err(err) => Err(format!("unable to connect to Carbide API: {:?}", err)),
        }
    }
}
