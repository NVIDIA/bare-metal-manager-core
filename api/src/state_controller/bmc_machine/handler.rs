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

    async fn handle_object_state(
        &self,
        _machine_id: &uuid::Uuid,
        state: &mut BmcMachine,
        controller_state: &mut ControllerStateReader<Self::ControllerState>,
        txn: &mut sqlx::Transaction<sqlx::Postgres>,
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
                let _client = ctx
                    .services
                    .redfish_client_pool
                    .create_client(
                        bmc_network_interface.hostname(),
                        None,
                        RedfishCredentialType::HardwareDefault,
                    )
                    .await
                    .map_err(|e| {
                        *controller_state.modify() =
                            BmcMachineState::Error(BmcMachineError::RedfishConnectionError {
                                message: e.to_string(),
                            });
                        StateHandlerError::GenericError(e.into())
                    })?;
            }
            BmcMachineState::Error(error_type) => {
                tracing::error!("Bmc state machine error: {:#?}", error_type)
            }
        }
        Ok(())
    }
}
