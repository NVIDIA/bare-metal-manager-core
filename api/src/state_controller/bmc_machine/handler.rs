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

use crate::{
    db::{bmc_machine::BmcMachine, machine_interface::MachineInterface},
    model::bmc_machine::{BmcMachineError, BmcMachineState},
    redfish::RedfishCredentialType,
    state_controller::state_handler::{
        ControllerStateReader, StateHandler, StateHandlerContext, StateHandlerError,
    },
};

#[derive(Debug, Default)]
pub struct BmcMachineStateHandler {}

#[async_trait::async_trait]
impl StateHandler for BmcMachineStateHandler {
    type ObjectId = uuid::Uuid;
    type State = BmcMachine;
    type ControllerState = BmcMachineState;
    type ObjectMetrics = ();

    async fn handle_object_state(
        &self,
        machine_id: &uuid::Uuid,
        state: &mut BmcMachine,
        controller_state: &mut ControllerStateReader<Self::ControllerState>,
        txn: &mut sqlx::Transaction<sqlx::Postgres>,
        _metrics: &mut Self::ObjectMetrics,
        ctx: &mut StateHandlerContext,
    ) -> Result<(), StateHandlerError> {
        let read_state: &BmcMachineState = &*controller_state;
        match read_state {
            BmcMachineState::Init => {
                tracing::info!("Starting machine discovery with redfish.");
                let bmc_network_interface =
                    MachineInterface::find_one(txn, state.machine_interface_id)
                        .await
                        .map_err(|e| StateHandlerError::GenericError(e.into()))?;
                let standard_client = ctx
                    .services
                    .redfish_client_pool
                    .create_standard_client(bmc_network_interface.hostname(), None)
                    .await;
                // Try to instantiate standard client with a hardware default password, but ignore error
                // since it might be already changed to site-default
                match standard_client {
                    Ok(client) => {
                        let _ = ctx
                            .services
                            .redfish_client_pool
                            .change_root_password_to_site_default(*client)
                            .await
                            .map_err(|e| {
                                tracing::warn!(error = %e, "Failed to change root redfish password")
                            });
                    }
                    Err(e) => tracing::warn!(error = %e, "Failed to instantiate redfish client"),
                }

                let mut _client;

                let client_result = ctx
                    .services
                    .redfish_client_pool
                    .create_client(
                        bmc_network_interface.hostname(),
                        None,
                        RedfishCredentialType::SiteDefault,
                    )
                    .await;

                match client_result {
                    Ok(redfish_client) => _client = redfish_client,
                    Err(e) => {
                        *controller_state.modify() =
                            BmcMachineState::Error(BmcMachineError::RedfishConnection {
                                message: e.to_string(),
                            });
                        return Ok(());
                    }
                }

                if let Err(e) = ctx
                    .services
                    .redfish_client_pool
                    .create_forge_admin_user(_client, *machine_id)
                    .await
                {
                    *controller_state.modify() =
                        BmcMachineState::Error(BmcMachineError::RedfishCommand {
                            command: "create_user".to_string(),
                            message: e.to_string(),
                        });
                    return Ok(());
                }

                let client_result = ctx
                    .services
                    .redfish_client_pool
                    .create_client(
                        bmc_network_interface.hostname(),
                        None,
                        RedfishCredentialType::BmcMachine {
                            bmc_machine_id: machine_id.to_string(),
                        },
                    )
                    .await;

                match client_result {
                    Ok(redfish_client) => _client = redfish_client,
                    Err(e) => {
                        *controller_state.modify() =
                            BmcMachineState::Error(BmcMachineError::RedfishConnection {
                                message: e.to_string(),
                            });
                        return Ok(());
                    }
                }
            }
            BmcMachineState::Error(error_type) => {
                tracing::error!(error_type = format!("{error_type:#?}"), %machine_id, "BMC state machine error");
            }
        }
        Ok(())
    }
}
