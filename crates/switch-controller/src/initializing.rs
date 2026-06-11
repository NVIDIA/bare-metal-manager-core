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

//! Handler for SwitchControllerState::Initializing.

use carbide_secrets::credentials::{CredentialKey, Credentials};
use carbide_uuid::switch::SwitchId;
use component_manager::nv_switch_manager::SwitchEndpoint;
use mac_address::MacAddress;
use model::machine_interface_address::MachineInterfaceAssociation;
use model::switch::{ConfiguringState, InitializingState, Switch, SwitchControllerState};
use state_controller::state_handler::{
    StateHandlerContext, StateHandlerError, StateHandlerOutcome,
};

use crate::context::SwitchStateHandlerContextObjects;

/// Handles the Initializing state for a switch.
pub async fn handle_initializing(
    switch_id: &SwitchId,
    state: &mut Switch,
    ctx: &mut StateHandlerContext<'_, SwitchStateHandlerContextObjects>,
) -> Result<StateHandlerOutcome<SwitchControllerState>, StateHandlerError> {
    let initializing_state = match &state.controller_state.value {
        SwitchControllerState::Initializing { initializing_state } => initializing_state,
        _ => unreachable!("handle_initializing called with non-Initializing state"),
    };

    match initializing_state {
        InitializingState::WaitForOsMachineInterface => {
            handle_wait_for_os_machine_interface(switch_id, state, ctx).await
        }
    }
}

async fn handle_wait_for_os_machine_interface(
    switch_id: &SwitchId,
    state: &mut Switch,
    ctx: &mut StateHandlerContext<'_, SwitchStateHandlerContextObjects>,
) -> Result<StateHandlerOutcome<SwitchControllerState>, StateHandlerError> {
    let Some(bmc_mac_address) = state.bmc_mac_address else {
        return Ok(StateHandlerOutcome::transition(
            SwitchControllerState::Error {
                cause: "No BMC MAC address on switch".to_string(),
            },
        ));
    };

    let nvos_credentials = {
        let key = CredentialKey::SwitchNvosAdmin { bmc_mac_address };
        match ctx.services.credential_manager.get_credentials(&key).await {
            Ok(Some(Credentials::UsernamePassword { username, password })) => {
                Some((username, password))
            }
            _ => None,
        }
    };

    let mut txn = ctx.services.db_pool.begin().await?;

    let expected_switch =
        db::expected_switch::find_by_bmc_mac_address(&mut txn, bmc_mac_address).await?;

    let expected_switch = match expected_switch {
        Some(es) => es,
        None => {
            tracing::info!(
                "Switch {:?}: no expected switch found for BMC MAC {}, waiting",
                switch_id,
                bmc_mac_address
            );
            return Ok(StateHandlerOutcome::transition(
                SwitchControllerState::Error {
                    cause: format!("No expected switch found for BMC MAC {}", bmc_mac_address),
                },
            ));
        }
    };

    let nvos_mac_addresses = &expected_switch.nvos_mac_addresses;
    if nvos_mac_addresses.is_empty() {
        tracing::warn!(
            "Switch {:?}: no NVOS MAC addresses on expected switch for serial {}, BMC MAC {}",
            switch_id,
            bmc_mac_address,
            expected_switch.bmc_mac_address
        );
        return Ok(StateHandlerOutcome::transition(
            SwitchControllerState::Error {
                cause: format!(
                    "No NVOS MAC addresses on expected switch for serial {}, BMC MAC {}",
                    bmc_mac_address, expected_switch.bmc_mac_address
                ),
            },
        ));
    }

    let mut associated_count = 0usize;
    let total = nvos_mac_addresses.len();
    let mut nvos_interfaces: Vec<(mac_address::MacAddress, Option<std::net::IpAddr>)> = Vec::new();

    for mac_address in nvos_mac_addresses {
        let mi = db::machine_interface::find_by_mac_address(&mut *txn, *mac_address).await?;
        let interface = match mi.first() {
            Some(iface) => iface,
            None => continue,
        };

        if let Some(existing_switch_id) = interface.switch_id {
            if existing_switch_id != *switch_id {
                tracing::warn!(
                    "Switch {:?}: NVOS MAC {} already associated with switch {}",
                    switch_id,
                    mac_address,
                    existing_switch_id
                );
                return Ok(StateHandlerOutcome::transition(
                    SwitchControllerState::Error {
                        cause: format!(
                            "NVOS MAC {} already associated with switch {}",
                            mac_address, existing_switch_id
                        ),
                    },
                ));
            }
            nvos_interfaces.push((*mac_address, interface.addresses.first().copied()));
            associated_count += 1;
            continue;
        }

        db::machine_interface::associate_interface_with_machine(
            &interface.id,
            MachineInterfaceAssociation::Switch(*switch_id),
            &mut txn,
        )
        .await?;
        tracing::info!(
            "Switch {:?}: associated NVOS interface {} (MAC {})",
            switch_id,
            interface.id,
            mac_address
        );
        nvos_interfaces.push((*mac_address, interface.addresses.first().copied()));
        associated_count += 1;
    }

    let rack_id = expected_switch.rack_id.clone();
    txn.commit().await?;

    tracing::info!(
        "Switch {:?}: associated {} NVOS interfaces for BMC MAC {}",
        switch_id,
        associated_count,
        bmc_mac_address
    );
    if associated_count >= 1 {
        if let (Some(_rack_id), Some(component_manager)) =
            (&rack_id, &ctx.services.component_manager)
        {
            // RMS has always used one host interface for this lookup even though
            // the previous proto exposed a list, so pick a single interface here.
            if let Some((nvos_mac, nvos_ip)) = nvos_interfaces
                .iter()
                .find(|(_, ip)| ip.is_some())
                .or_else(|| nvos_interfaces.first())
            {
                let endpoint = build_switch_endpoint_for_slot_tray(
                    bmc_mac_address,
                    *nvos_mac,
                    *nvos_ip,
                    nvos_credentials,
                );
                match component_manager
                    .nv_switch
                    .get_slot_and_tray(std::slice::from_ref(&endpoint))
                    .await
                {
                    Ok(results) => {
                        if let Some(result) = results.into_iter().next() {
                            if let Some(error) = result.error.as_ref() {
                                tracing::warn!(
                                    %error,
                                    %switch_id,
                                    backend = component_manager.nv_switch.name(),
                                    "Failed to get slot and tray from component manager backend"
                                );
                            }
                            let mut update_txn = ctx.services.db_pool.begin().await?;
                            if let Err(e) = db::switch::update_slot_and_tray(
                                &mut update_txn,
                                switch_id,
                                result.slot_number,
                                result.tray_index,
                            )
                            .await
                            {
                                tracing::warn!(
                                    %e,
                                    %switch_id,
                                    "Failed to update slot_number and tray_index for switch"
                                );
                            }
                            update_txn.commit().await?;
                        }
                    }
                    Err(error) => {
                        tracing::warn!(
                            %error,
                            %switch_id,
                            backend = component_manager.nv_switch.name(),
                            "Failed to get slot and tray from component manager backend"
                        );
                    }
                }
            }
        }

        tracing::info!(
            "Switch {:?}: at least one NVOS interface associated ({}/{}), transitioning to Configuring",
            switch_id,
            associated_count,
            total
        );
        Ok(StateHandlerOutcome::transition(
            SwitchControllerState::Configuring {
                config_state: ConfiguringState::RotateOsPassword,
            },
        ))
    } else {
        tracing::info!(
            "Switch {:?}: {}/{} NVOS interfaces associated, waiting",
            switch_id,
            associated_count,
            total
        );
        Ok(StateHandlerOutcome::wait(format!(
            "{}/{} NVOS interfaces associated, waiting",
            associated_count, total
        )))
    }
}

fn build_switch_endpoint_for_slot_tray(
    bmc_mac: MacAddress,
    nvos_mac: MacAddress,
    nvos_ip: Option<std::net::IpAddr>,
    nvos_credentials: Option<(String, String)>,
) -> SwitchEndpoint {
    let placeholder_ip = "0.0.0.0".parse().expect("valid placeholder IP");
    let nvos_ip = nvos_ip.unwrap_or(placeholder_ip);
    let credentials = nvos_credentials
        .map(|(username, password)| Credentials::UsernamePassword { username, password })
        .unwrap_or(Credentials::UsernamePassword {
            username: String::new(),
            password: String::new(),
        });

    SwitchEndpoint {
        bmc_ip: placeholder_ip,
        bmc_mac,
        nvos_ip,
        nvos_mac,
        bmc_credentials: credentials.clone(),
        nvos_credentials: credentials,
    }
}
