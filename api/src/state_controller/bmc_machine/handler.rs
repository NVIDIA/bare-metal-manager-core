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

use libredfish::{Boot, SystemPowerControl};

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
            BmcMachineState::Initializing => {
                tracing::info!("Starting machine discovery with redfish.");
                let bmc_network_interface =
                    MachineInterface::find_one(txn, state.machine_interface_id)
                        .await
                        .map_err(|e| StateHandlerError::GenericError(e.into()))?;

                let redfish_ip = match bmc_network_interface.addresses().first() {
                    Some(machine_address) => machine_address.address.to_string(),
                    None => {
                        let msg = format!(
                            "No IP address for BMC network interface interface: {:#?}",
                            bmc_network_interface
                        );
                        tracing::error!(msg);
                        *controller_state.modify() =
                            BmcMachineState::Error(BmcMachineError::RedfishConnection {
                                message: msg,
                            });
                        return Ok(());
                    }
                };

                let standard_client = ctx
                    .services
                    .redfish_client_pool
                    .create_standard_client(redfish_ip.as_str(), None)
                    .await;
                // Try to instantiate standard client with a hardware default password, but ignore error
                // since it might be already changed to site-default
                match standard_client {
                    Ok(client) => {
                        let _ = ctx
                            .services
                            .redfish_client_pool
                            .change_root_password_to_site_default(*client.clone())
                            .await
                            .map_err(|e| {
                                tracing::warn!(error = %e, "Failed to change root redfish password")
                            });
                    }
                    Err(e) => tracing::warn!(error = %e, "Failed to instantiate redfish client"),
                }

                let client;

                let client_result = ctx
                    .services
                    .redfish_client_pool
                    .create_client(
                        redfish_ip.as_str(),
                        None,
                        RedfishCredentialType::SiteDefault,
                    )
                    .await;

                match client_result {
                    Ok(redfish_client) => client = redfish_client,
                    Err(e) => {
                        tracing::error!(error = %e, "Failed to instantiate redfish client");
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
                    .create_forge_admin_user(client, *machine_id)
                    .await
                {
                    tracing::error!(error = %e, "Failed to create user");
                    *controller_state.modify() =
                        BmcMachineState::Error(BmcMachineError::RedfishCommand {
                            command: "create_user".to_string(),
                            message: e.to_string(),
                        });
                    return Ok(());
                }
                *controller_state.modify() = BmcMachineState::Configuring;
            }
            BmcMachineState::Configuring => {
                let bmc_network_interface =
                    MachineInterface::find_one(txn, state.machine_interface_id)
                        .await
                        .map_err(|e| StateHandlerError::GenericError(e.into()))?;

                let redfish_ip = bmc_network_interface
                    .addresses()
                    .first()
                    .unwrap()
                    .address
                    .to_string();

                let client_result = ctx
                    .services
                    .redfish_client_pool
                    .create_client(
                        redfish_ip.as_str(),
                        None,
                        RedfishCredentialType::BmcMachine {
                            bmc_machine_id: machine_id.to_string(),
                        },
                    )
                    .await;

                let client = match client_result {
                    Ok(redfish_client) => redfish_client,
                    Err(e) => {
                        tracing::error!(error = %e, "Failed to instantiate redfish client (forge-admin user)");
                        *controller_state.modify() =
                            BmcMachineState::Error(BmcMachineError::RedfishConnection {
                                message: e.to_string(),
                            });
                        return Ok(());
                    }
                };

                let bmc_inventory = match client.get_firmware("BMC_Firmware").await {
                    Ok(inventory) => inventory,
                    Err(e) => {
                        tracing::error!(error = %e, "Failed to get BMC version");
                        *controller_state.modify() =
                            BmcMachineState::Error(BmcMachineError::RedfishCommand {
                                command: "get_firmware".to_string(),
                                message: e.to_string(),
                            });
                        return Ok(());
                    }
                };

                match bmc_inventory.version {
                    Some(version_str) => {
                        // example of returned result: "BF-23.07-3"
                        let version = version_str.replace("BF-", "");
                        let minimal_supported_version = "23.07";
                        if let Ok(version_compare::Cmp::Lt) =
                            version_compare::compare(version.as_str(), minimal_supported_version)
                        {
                            tracing::error!(
                                "Current BMC FW version: {}, minimal supported version: {}",
                                version.as_str(),
                                minimal_supported_version
                            );
                            *controller_state.modify() =
                                BmcMachineState::Error(BmcMachineError::UnsupportedBmcFirmware);
                            return Ok(());
                        }

                        state.update_firmware_version(txn, version).await?;
                    }
                    None => {
                        tracing::error!("Unknown BMC FW version");
                        *controller_state.modify() =
                            BmcMachineState::Error(BmcMachineError::UnsupportedBmcFirmware);
                        return Ok(());
                    }
                }

                if let Err(e) = client.disable_secure_boot().await {
                    tracing::error!(error = %e, "Failed to disable secure boot");
                    *controller_state.modify() =
                        BmcMachineState::Error(BmcMachineError::RedfishCommand {
                            command: "disable_secure_boot".to_string(),
                            message: e.to_string(),
                        });
                    return Ok(());
                }

                if let Err(e) = client.boot_once(Boot::UefiHttp).await {
                    *controller_state.modify() =
                        BmcMachineState::Error(BmcMachineError::RedfishCommand {
                            command: "boot_once(UEFI http)".to_string(),
                            message: e.to_string(),
                        });
                    return Ok(());
                }

                if let Err(e) = client.power(SystemPowerControl::GracefulRestart).await {
                    *controller_state.modify() =
                        BmcMachineState::Error(BmcMachineError::RedfishCommand {
                            command: "reboot".to_string(),
                            message: e.to_string(),
                        });
                    return Ok(());
                } else {
                    *controller_state.modify() = BmcMachineState::DpuReboot;
                    return Ok(());
                }
            }
            BmcMachineState::DpuReboot => {
                // TODO: check Machine discovery and link current BmcMachine, change state.
                *controller_state.modify() = BmcMachineState::Initialized;
            }
            BmcMachineState::Initialized => {
                // Leaf state
            }
            BmcMachineState::Error(error_type) => {
                tracing::debug!(error_type = format!("{error_type:#?}"), %machine_id, "BMC state machine error");
            }
        }
        Ok(())
    }
}
