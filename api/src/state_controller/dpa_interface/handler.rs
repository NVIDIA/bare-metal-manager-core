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

//! State Handler implementation for Dpa Interfaces

use crate::db;
use crate::db::managed_host::LoadSnapshotOptions;
use crate::db::vpc::Vpc;
use crate::{
    db::dpa_interface::DpaInterface,
    model::dpa_interface::DpaInterfaceControllerState,
    resource_pool::DbResourcePool,
    state_controller::{
        dpa_interface::context::DpaInterfaceStateHandlerContextObjects,
        state_handler::{
            StateHandler, StateHandlerContext, StateHandlerError, StateHandlerOutcome, do_nothing,
            transition,
        },
    },
};
use forge_uuid::dpa_interface::DpaInterfaceId;
use sqlx::PgConnection;
use std::sync::Arc;

use eyre::eyre;

/// The actual Dpa Interface State handler
#[derive(Debug, Clone)]
pub struct DpaInterfaceStateHandler {
    _pool_vni: Arc<DbResourcePool<i32>>,
}

impl DpaInterfaceStateHandler {
    pub fn new(pool_vni: Arc<DbResourcePool<i32>>) -> Self {
        Self {
            _pool_vni: pool_vni,
        }
    }

    fn record_metrics(
        &self,
        _state: &mut DpaInterface,
        _ctx: &mut StateHandlerContext<DpaInterfaceStateHandlerContextObjects>,
    ) {
    }
}

#[async_trait::async_trait]
impl StateHandler for DpaInterfaceStateHandler {
    type ObjectId = DpaInterfaceId;
    type State = DpaInterface;
    type ControllerState = DpaInterfaceControllerState;
    type ContextObjects = DpaInterfaceStateHandlerContextObjects;

    async fn handle_object_state(
        &self,
        _interface_id: &DpaInterfaceId,
        state: &mut DpaInterface,
        controller_state: &Self::ControllerState,
        txn: &mut PgConnection,
        ctx: &mut StateHandlerContext<Self::ContextObjects>,
    ) -> Result<StateHandlerOutcome<DpaInterfaceControllerState>, StateHandlerError> {
        // record metrics irrespective of the state of the dpa interface
        self.record_metrics(state, ctx);
        match controller_state {
            DpaInterfaceControllerState::Provisioning => {
                let new_state = DpaInterfaceControllerState::Ready;
                tracing::info!(state = ?new_state, "Dpa Interface state transition");
                Ok(transition!(new_state))
            }
            DpaInterfaceControllerState::Ready => {
                // We will stay in Ready state as long use_admin_network is true.
                // When an instance is created from this host, use_admin_network
                // will be turned off. We then need to SetVNI, and wait for the
                // SetVNI to take effect.
                if !state.use_admin_network() {
                    let new_state = DpaInterfaceControllerState::WaitingForSetVNI;
                    tracing::info!(state = ?new_state, "Dpa Interface state transition");
                    let _dpa_vni = get_dpa_vni_to_use(state, txn).await?;
                    // XXX TODO  XXX
                    // Need to send SetVNI command to MQTT broker
                    // The VNI to be used has to be  obtained from associated VPC
                    // XXX TODO  XXX
                    Ok(transition!(new_state))
                } else {
                    Ok(do_nothing!())
                }
            }
            DpaInterfaceControllerState::WaitingForSetVNI => {
                // When we are in the WaitingForSetVNI state, we are have sent a SetVNI command
                // to the DPA Interface Card. We are waiting for an ACK for that command.
                // When the ack shows up, the network_config_version and the network_status_observation
                // will match.
                if !state.managed_host_network_config_version_synced() {
                    tracing::debug!("DPA interface found in WaitingForSetVNI state");
                    let _dpa_vni = get_dpa_vni_to_use(state, txn).await?;
                    // XXX TODO XXX
                    // Send SetVNI command to DPA Card Again
                    // XXX TODO XXX
                    Ok(do_nothing!())
                } else {
                    let new_state = DpaInterfaceControllerState::Assigned;
                    tracing::info!(state = ?new_state, "Dpa Interface state transition");
                    Ok(transition!(new_state))
                }
            }
            DpaInterfaceControllerState::Assigned => {
                // We will stay in the Assigned state as long as use_admin_network is off, which
                // means we are in the tenant network. Once use_admin_network is turned on, we
                // will send a SetVNI command to the DPA Interface card to set the VNI to 0
                // and will transition to WaitingForResetVNI state.
                if state.use_admin_network() {
                    let new_state = DpaInterfaceControllerState::WaitingForResetVNI;
                    tracing::info!(state = ?new_state, "Dpa Interface state transition");
                    // XXX TODO  XXX
                    // Need to send SetVNI command with zero VNI to MQTT broker
                    // XXX TODO  XXX
                    Ok(transition!(new_state))
                } else {
                    Ok(do_nothing!())
                }
            }
            DpaInterfaceControllerState::WaitingForResetVNI => {
                // When we are in the WaitingForResetVNI state, we are have sent a SetVNI command
                // to the DPA Interface Card. We are waiting for an ACK for that command.
                // When the ack shows up, the network_config_version and the network_status_observation
                // will match.
                if !state.managed_host_network_config_version_synced() {
                    tracing::debug!("DPA interface found in WaitingForResetVNI state");
                    // XXX TODO XXX
                    // Resend SetVNI command again with VNI set to Zero
                    // XXX TODO XXX
                    Ok(do_nothing!())
                } else {
                    let new_state = DpaInterfaceControllerState::Ready;
                    tracing::info!(state = ?new_state, "Dpa Interface state transition");
                    Ok(transition!(new_state))
                }
            }
        }
    }
}

// get_dpa_vni_to_use figures out the VNI to be used for this DPA interface
// when we are transitioning to ASSIGNED state. This happens when we are
// moving from Ready to WaitingForSetVNI or when we are still in WaitingForSetVNI
// states.
//
// Given the DPA Interface, we know its associated machine ID. From that, we need
// to find the VPC the machine belongs to. From the VPC, we can find the DPA VNI
// allocated for that VPC.
async fn get_dpa_vni_to_use(
    state: &mut DpaInterface,
    txn: &mut PgConnection,
) -> Result<i32, StateHandlerError> {
    let machine_id = state.machine_id;

    let maybe_snapshot =
        db::managed_host::load_snapshot(txn, &machine_id, LoadSnapshotOptions::default())
            .await
            .map_err(StateHandlerError::DBError)?;

    let snapshot = match maybe_snapshot {
        Some(sn) => sn,
        None => return Err(StateHandlerError::GenericError(eyre!("Error"))),
    };

    let instance = match snapshot.instance {
        Some(inst) => inst,
        None => {
            return Err(StateHandlerError::GenericError(eyre!(
                "Expected an instance and found none"
            )));
        }
    };

    let interfaces = &instance.config.network.interfaces;
    let Some(network_segment_id) = interfaces[0].network_segment_id else {
        // Network segment allocation is done before persisting record in db. So if still
        // network segment is empty, return error.
        return Err(StateHandlerError::GenericError(eyre!(
            "Expected Network Segment"
        )));
    };

    let vpc = Vpc::find_by_segment(txn, network_segment_id)
        .await
        .map_err(StateHandlerError::DBError)?;

    let dpa_vni = match vpc.dpa_vni {
        Some(vni) => vni,
        None => {
            return Err(StateHandlerError::GenericError(eyre!(
                "Expected VNI. Found none"
            )));
        }
    };

    if dpa_vni == 0 {
        println!("Did not expect dpa_vni to be zero");
    }

    Ok(dpa_vni)
}
