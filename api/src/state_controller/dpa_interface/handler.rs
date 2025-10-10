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

use std::sync::Arc;

use chrono::{Duration, TimeDelta};
use eyre::eyre;
use forge_uuid::dpa_interface::DpaInterfaceId;
use model::dpa_interface::{DpaInterface, DpaInterfaceControllerState};
use model::resource_pool::ResourcePool;
use mqttea::MqtteaClient;
use sqlx::PgConnection;

use crate::db;
use crate::db::dpa_interface::get_dpa_vni;
use crate::state_controller::dpa_interface::context::DpaInterfaceStateHandlerContextObjects;
use crate::state_controller::state_handler::{
    StateHandler, StateHandlerContext, StateHandlerError, StateHandlerOutcome, do_nothing,
    transition,
};

/// The actual Dpa Interface State handler
#[derive(Debug, Clone)]
pub struct DpaInterfaceStateHandler {
    _pool_vni: Arc<ResourcePool<i32>>,
}

impl DpaInterfaceStateHandler {
    pub fn new(pool_vni: Arc<ResourcePool<i32>>) -> Self {
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

        let hb_interval = ctx
            .services
            .site_config
            .get_hb_interval()
            .unwrap_or_else(|| Duration::minutes(2));

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

                let client =
                    ctx.services.mqtt_client.clone().ok_or_else(|| {
                        StateHandlerError::GenericError(eyre!("Missing mqtt_client"))
                    })?;

                if !state.use_admin_network() {
                    let new_state = DpaInterfaceControllerState::WaitingForSetVNI;
                    tracing::info!(state = ?new_state, "Dpa Interface state transition");

                    // send the SetVni command
                    send_set_vni_command(
                        state, txn, client, true,  /* needs_vni */
                        false, /* not a heartbeat */
                        true,  /* send revision */
                    )
                    .await?;

                    Ok(transition!(new_state))
                } else {
                    do_heartbeat(state, txn, client, hb_interval, false).await?;

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

                    let client = ctx.services.mqtt_client.clone().ok_or_else(|| {
                        StateHandlerError::GenericError(eyre!("Missing mqtt_client"))
                    })?;

                    send_set_vni_command(
                        state, txn, client, true,  /* needs_vni */
                        false, /* not a heartbeat */
                        true,  /* send revision */
                    )
                    .await?;
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

                let client =
                    ctx.services.mqtt_client.clone().ok_or_else(|| {
                        StateHandlerError::GenericError(eyre!("Missing mqtt_client"))
                    })?;

                if state.use_admin_network() {
                    let new_state = DpaInterfaceControllerState::WaitingForResetVNI;
                    tracing::info!(state = ?new_state, "Dpa Interface state transition");
                    send_set_vni_command(state, txn, client, false, false, true).await?;

                    Ok(transition!(new_state))
                } else {
                    do_heartbeat(state, txn, client, hb_interval, true).await?;

                    // Send a heartbeat command, indicated by the revision string being "NIL".
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
                    let client = ctx.services.mqtt_client.clone().ok_or_else(|| {
                        StateHandlerError::GenericError(eyre!("Missing mqtt_client"))
                    })?;

                    send_set_vni_command(state, txn, client, false, false, true).await?;
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

// Determine if we need to do a heartbeat or if we need to
// send a SetVni command because the DPA and Carbide are out of sync.
// If so, call send_set_vni_command to send the heart beat or set vni
async fn do_heartbeat(
    state: &mut DpaInterface,
    txn: &mut PgConnection,
    client: Arc<MqtteaClient>,
    hb_interval: TimeDelta,
    needs_vni: bool,
) -> Result<(), StateHandlerError> {
    let mut send_hb = false;
    let mut send_revision = false;

    // We are in the Ready or Assigned state and we continue to be in the same state.
    // In this state, we will send SetVni command to the DPA if
    //    (1) if the heartbeat interval has elapsed since the heartbeat
    //    (2) The DPA sent us an ack and it looks like the DPA lost its config (due to powercycle potentially)
    // Heartbeat is identified by the revision being se to the sentinel value "NIL"
    // Both send_hb and send_revision could evaluate to true below. If send_hb is true, we will
    // update the last_hb_time for the interface entry.

    if let Some(next_hb_time) = state.last_hb_time.checked_add_signed(hb_interval)
        && chrono::Utc::now() >= next_hb_time
    {
        send_hb = true; // heartbeat interval elapsed since the last heartbeat 
    }

    if !state.managed_host_network_config_version_synced() {
        send_revision = true; // DPA config not in sync with us. So resend the config
    }

    if send_hb || send_revision {
        send_set_vni_command(state, txn, client, needs_vni, send_hb, send_revision).await?;
    }

    Ok(())
}

// Send a SetVni command to the DPA. The SetVni command could be a heart beat (identified by
// revision being "NIL"). If needs_vni is true, get the VNI to use from the DB. Otherwise, vni
// sent is 0.
async fn send_set_vni_command(
    state: &mut DpaInterface,
    txn: &mut PgConnection,
    client: Arc<MqtteaClient>,
    needs_vni: bool,
    heart_beat: bool,
    send_revision: bool,
) -> Result<(), StateHandlerError> {
    let revision_str = if send_revision {
        state.network_config.version.to_string()
    } else {
        "NIL".to_string()
    };

    let vni = if needs_vni {
        match get_dpa_vni(state, txn).await {
            Ok(dv) => dv,
            Err(e) => {
                return Err(StateHandlerError::GenericError(eyre!(
                    "get_dpa_vni error: {:#?}",
                    e
                )));
            }
        }
    } else {
        0
    };

    // Send a heartbeat command, indicated by the revision string being "NIL".
    match crate::dpa::send_dpa_command(client, state.mac_address.to_string(), revision_str, vni)
        .await
    {
        Ok(()) => {
            if heart_beat {
                let res = db::dpa_interface::update_last_hb_time(state, txn).await;
                if res.is_err() {
                    tracing::error!(
                        "Error updating last_hb_time for dpa id: {} res: {:#?}",
                        state.id,
                        res
                    );
                }
            }
        }
        Err(_e) => (),
    }

    Ok(())
}
