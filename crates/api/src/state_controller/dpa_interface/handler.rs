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

//! State Handler implementation for Dpa Interfaces

use std::sync::Arc;

use carbide_uuid::dpa_interface::DpaInterfaceId;
use chrono::{Duration, TimeDelta};
use db::WithTransaction;
use db::dpa_interface::get_dpa_vni;
use eyre::eyre;
use futures_util::FutureExt;
use model::dpa_interface::DpaLockMode::{Locked, Unlocked};
use model::dpa_interface::{DpaInterface, DpaInterfaceControllerState};
use model::resource_pool::ResourcePool;
use mqttea::MqtteaClient;
use sqlx::PgTransaction;

use crate::dpa::handler::DpaInfo;
use crate::state_controller::common_services::CommonStateHandlerServices;
use crate::state_controller::dpa_interface::context::DpaInterfaceStateHandlerContextObjects;
use crate::state_controller::state_handler::{
    StateHandler, StateHandlerContext, StateHandlerError, StateHandlerOutcome,
    StateHandlerOutcomeWithTransaction,
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
        ctx: &mut StateHandlerContext<Self::ContextObjects>,
    ) -> Result<StateHandlerOutcomeWithTransaction<DpaInterfaceControllerState>, StateHandlerError>
    {
        // record metrics irrespective of the state of the dpa interface
        self.record_metrics(state, ctx);

        let hb_interval = ctx
            .services
            .site_config
            .get_hb_interval()
            .unwrap_or_else(|| Duration::minutes(2));

        let dpa_info = ctx.services.dpa_info.clone().unwrap();

        match controller_state {
            DpaInterfaceControllerState::Provisioning => {
                // New DPA objects start off in the Provisioning state.
                // They stay in that state until the first time the machine
                // starts a transition from Ready to Assigned state.
                if state.use_admin_network() {
                    return Ok(StateHandlerOutcome::do_nothing().with_txn(None));
                }

                let new_state = DpaInterfaceControllerState::Ready;
                tracing::info!(state = ?new_state, "Dpa Interface state transition");
                return Ok(StateHandlerOutcome::transition(new_state).with_txn(None));
            }

            DpaInterfaceControllerState::Ready => {
                // We will stay in Ready state as long use_admin_network is true.
                // When an instance is created from this host, use_admin_network
                // will be turned off. We then need to SetVNI, and wait for the
                // SetVNI to take effect.

                let client = dpa_info
                    .mqtt_client
                    .clone()
                    .ok_or_else(|| StateHandlerError::GenericError(eyre!("Missing mqtt_client")))?;

                if !state.use_admin_network() {
                    let new_state = DpaInterfaceControllerState::Unlocking;
                    tracing::info!(state = ?new_state, "Dpa Interface state transition");

                    Ok(StateHandlerOutcome::transition(new_state).with_txn(None))
                } else {
                    let txn =
                        do_heartbeat(state, ctx.services, client, &dpa_info, hb_interval, false)
                            .await?;

                    Ok(StateHandlerOutcome::do_nothing().with_txn(txn))
                }
            }

            DpaInterfaceControllerState::Unlocking => {
                // Once we reach Unlocking state, we would have replied to
                // ForgeAgentControl requests from scout with a reply indicating
                // that it should unlock the card. The scout does the action, and
                // publishes an observation indicating the lock status. That causes
                // us to update the card state in the DB. If card_state is none, that
                // means this sequence has not yet taken place. So we just wait.
                if state.card_state.is_none() {
                    tracing::info!("card_state none for dpa: {:#?}", state.id);
                    return Ok(StateHandlerOutcome::wait(
                        "Waiting for card to get unlocked".to_string(),
                    )
                    .with_txn(None));
                }
                let cs = state.card_state.clone().unwrap();
                if cs.lockmode.is_some() {
                    let lm = cs.lockmode.unwrap();
                    if lm == Unlocked {
                        let new_state = DpaInterfaceControllerState::ApplyProfile;
                        tracing::info!(state = ?new_state, "Dpa Interface state transition");
                        return Ok(StateHandlerOutcome::transition(new_state).with_txn(None));
                    }
                }
                Ok(
                    StateHandlerOutcome::wait("Waiting for card to get unlocked".to_string())
                        .with_txn(None),
                )
            }

            DpaInterfaceControllerState::ApplyProfile => {
                if state.card_state.is_none() {
                    // Card should be in unlocked state when we come here. So we do
                    // expect card_state to be not NONE.
                    tracing::error!("Unexpected - card_state none for dpa: {:#?}", state.id);
                    return Ok(StateHandlerOutcome::do_nothing().with_txn(None));
                }
                let cs = state.card_state.clone().unwrap();
                if cs.profile.is_some() && cs.profile_synced.is_some() {
                    let psynced = cs.profile_synced.unwrap();
                    if psynced {
                        let new_state = DpaInterfaceControllerState::Locking;
                        tracing::info!(state = ?new_state, "Dpa Interface state transition");
                        return Ok(StateHandlerOutcome::transition(new_state).with_txn(None));
                    }
                }
                Ok(StateHandlerOutcome::wait(
                    "Waiting for profile to be applied on card".to_string(),
                )
                .with_txn(None))
            }
            DpaInterfaceControllerState::Locking => {
                if state.card_state.is_none() {
                    tracing::error!("Unexpected - card_state none for dpa: {:#?}", state.id);
                    return Ok(StateHandlerOutcome::do_nothing().with_txn(None));
                }
                let cs = state.card_state.clone().unwrap();
                if cs.lockmode.is_some() {
                    let lm = cs.lockmode.unwrap();
                    if lm == Locked {
                        let new_state = DpaInterfaceControllerState::WaitingForSetVNI;
                        tracing::info!(state = ?new_state, "Dpa Interface state transition");
                        return Ok(StateHandlerOutcome::transition(new_state).with_txn(None));
                    }
                }
                Ok(
                    StateHandlerOutcome::wait("Waiting for card to get locked".to_string())
                        .with_txn(None),
                )
            }

            DpaInterfaceControllerState::WaitingForSetVNI => {
                // When we are in the WaitingForSetVNI state, we are have sent a SetVNI command
                // to the DPA Interface Card. We are waiting for an ACK for that command.
                // When the ack shows up, the network_config_version and the network_status_observation
                // will match.

                if !state.managed_host_network_config_version_synced() {
                    tracing::debug!("DPA interface found in WaitingForSetVNI state");

                    let client = dpa_info.mqtt_client.clone().ok_or_else(|| {
                        StateHandlerError::GenericError(eyre!("Missing mqtt_client"))
                    })?;

                    let txn = send_set_vni_command(
                        state,
                        ctx.services,
                        client,
                        &dpa_info,
                        true,  /* needs_vni */
                        false, /* not a heartbeat */
                        true,  /* send revision */
                    )
                    .await?;
                    Ok(StateHandlerOutcome::do_nothing().with_txn(txn))
                } else {
                    let new_state = DpaInterfaceControllerState::Assigned;
                    tracing::info!(state = ?new_state, "Dpa Interface state transition");
                    Ok(StateHandlerOutcome::transition(new_state).with_txn(None))
                }
            }
            DpaInterfaceControllerState::Assigned => {
                // We will stay in the Assigned state as long as use_admin_network is off, which
                // means we are in the tenant network. Once use_admin_network is turned on, we
                // will send a SetVNI command to the DPA Interface card to set the VNI to 0
                // and will transition to WaitingForResetVNI state.

                let client = dpa_info
                    .mqtt_client
                    .clone()
                    .ok_or_else(|| StateHandlerError::GenericError(eyre!("Missing mqtt_client")))?;

                if state.use_admin_network() {
                    let new_state = DpaInterfaceControllerState::WaitingForResetVNI;
                    tracing::info!(state = ?new_state, "Dpa Interface state transition");
                    let txn = send_set_vni_command(
                        state,
                        ctx.services,
                        client,
                        &dpa_info,
                        false,
                        false,
                        true,
                    )
                    .await?;

                    Ok(StateHandlerOutcome::transition(new_state).with_txn(txn))
                } else {
                    let txn =
                        do_heartbeat(state, ctx.services, client, &dpa_info, hb_interval, true)
                            .await?;

                    // Send a heartbeat command, indicated by the revision string being "NIL".
                    Ok(StateHandlerOutcome::do_nothing().with_txn(txn))
                }
            }
            DpaInterfaceControllerState::WaitingForResetVNI => {
                // When we are in the WaitingForResetVNI state, we are have sent a SetVNI command
                // to the DPA Interface Card. We are waiting for an ACK for that command.
                // When the ack shows up, the network_config_version and the network_status_observation
                // will match.

                if !state.managed_host_network_config_version_synced() {
                    tracing::debug!("DPA interface found in WaitingForResetVNI state");
                    let client = dpa_info.mqtt_client.clone().ok_or_else(|| {
                        StateHandlerError::GenericError(eyre!("Missing mqtt_client"))
                    })?;

                    let txn = send_set_vni_command(
                        state,
                        ctx.services,
                        client,
                        &dpa_info,
                        false,
                        false,
                        true,
                    )
                    .await?;
                    Ok(StateHandlerOutcome::do_nothing().with_txn(txn))
                } else {
                    let new_state = DpaInterfaceControllerState::Ready;
                    tracing::info!(state = ?new_state, "Dpa Interface state transition");
                    Ok(StateHandlerOutcome::transition(new_state).with_txn(None))
                }
            }
        }
    }
}

// Determine if we need to do a heartbeat or if we need to
// send a SetVni command because the DPA and Carbide are out of sync.
// If so, call send_set_vni_command to send the heart beat or set vni
async fn do_heartbeat<'a>(
    state: &mut DpaInterface,
    services: &mut CommonStateHandlerServices,
    client: Arc<MqtteaClient>,
    dpa_info: &Arc<DpaInfo>,
    hb_interval: TimeDelta,
    needs_vni: bool,
) -> Result<Option<PgTransaction<'a>>, StateHandlerError> {
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
        let txn = send_set_vni_command(
            state,
            services,
            client,
            dpa_info,
            needs_vni,
            send_hb,
            send_revision,
        )
        .await?;
        Ok(txn)
    } else {
        Ok(None)
    }
}

// Send a SetVni command to the DPA. The SetVni command could be a heart beat (identified by
// revision being "NIL"). If needs_vni is true, get the VNI to use from the DB. Otherwise, vni
// sent is 0.
async fn send_set_vni_command<'a>(
    state: &mut DpaInterface,
    services: &mut CommonStateHandlerServices,
    client: Arc<MqtteaClient>,
    dpa_info: &Arc<DpaInfo>,
    needs_vni: bool,
    heart_beat: bool,
    send_revision: bool,
) -> Result<Option<PgTransaction<'a>>, StateHandlerError> {
    let revision_str = if send_revision {
        state.network_config.version.to_string()
    } else {
        "NIL".to_string()
    };

    let vni = if needs_vni {
        match services
            .db_pool
            .with_txn(|txn| get_dpa_vni(state, txn).boxed())
            .await?
        {
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
    match crate::dpa::handler::send_dpa_command(
        client,
        dpa_info,
        state.mac_address.to_string(),
        revision_str,
        vni,
    )
    .await
    {
        Ok(()) => {
            if heart_beat {
                let mut txn = services.db_pool.begin().await?;
                let res = db::dpa_interface::update_last_hb_time(state, &mut txn).await;
                if res.is_err() {
                    tracing::error!(
                        "Error updating last_hb_time for dpa id: {} res: {:#?}",
                        state.id,
                        res
                    );
                }
                Ok(Some(txn))
            } else {
                Ok(None)
            }
        }
        Err(_e) => Ok(None),
    }
}
