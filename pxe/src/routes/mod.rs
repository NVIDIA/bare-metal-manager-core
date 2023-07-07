/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
use ::rpc::forge_tls_client::{self, ForgeTlsConfig};

pub mod cloud_init;
pub mod ipxe;

pub struct RpcContext;

impl RpcContext {
    async fn get_pxe_instructions(
        arch: rpc::MachineArchitecture,
        machine_interface_id: rocket::serde::uuid::Uuid,
        url: String,
        forge_tls_config: ForgeTlsConfig,
    ) -> Result<String, String> {
        let mut client = forge_tls_client::ForgeTlsClient::new(forge_tls_config)
            .connect(url)
            .await
            .map_err(|err| err.to_string())?;
        let interface_id = Some(rpc::Uuid {
            value: machine_interface_id.to_string(),
        });
        let request = tonic::Request::new(rpc::PxeInstructionRequest {
            arch: arch as i32,
            interface_id: interface_id.clone(),
        });
        client
            .get_pxe_instructions(request)
            .await
            .map(|response| response.into_inner().pxe_script)
            .map_err(|error| {
                format!(
                    "Error in updating build needed flag for instance for machine {:?}; Error: {}.",
                    interface_id, error
                )
            })
    }

    async fn get_instance(
        machine_id: rpc::MachineId,
        url: String,
        forge_tls_config: ForgeTlsConfig,
    ) -> Result<rpc::Instance, String> {
        match forge_tls_client::ForgeTlsClient::new(forge_tls_config)
            .connect(url)
            .await
        {
            Ok(mut client) => {
                let request = tonic::Request::new(machine_id.clone());

                let optional_instance = client
                    .find_instance_by_machine_id(request)
                    .await
                    .map(|response| response.into_inner().instances.into_iter().next())
                    .map_err(|error| {
                        format!(
                            "unable to find instance for machine {} via Carbide: {:?}",
                            machine_id, error
                        )
                    })?;

                optional_instance.ok_or_else(|| {
                    format!("No instance found for machine {} via Carbide", machine_id)
                })
            }
            Err(err) => Err(format!("unable to connect to Carbide API: {:?}", err)),
        }
    }
}
