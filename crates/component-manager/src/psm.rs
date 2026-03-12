// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::str::FromStr;

use carbide_uuid::power_shelf::PowerShelfId;
use tonic::transport::Channel;
use tracing::instrument;

use crate::config::BackendTlsConfig;
use crate::error::ComponentManagerError;
use crate::power_shelf_manager::{
    FirmwareState, PowerShelfComponentResult, PowerShelfFirmwareUpdateStatus, PowerShelfManager,
};
use crate::proto::psm;
use crate::types::PowerAction;

#[derive(Debug)]
pub struct PsmPowerShelfBackend {
    client: psm::powershelf_manager_client::PowershelfManagerClient<Channel>,
}

impl PsmPowerShelfBackend {
    pub async fn connect(
        url: &str,
        tls: Option<&BackendTlsConfig>,
    ) -> Result<Self, ComponentManagerError> {
        let channel = crate::tls::build_channel(url, tls, "PSM").await?;
        Ok(Self {
            client: psm::powershelf_manager_client::PowershelfManagerClient::new(channel),
        })
    }
}

fn map_psm_fw_state(state: i32) -> FirmwareState {
    match psm::FirmwareUpdateState::try_from(state) {
        Ok(psm::FirmwareUpdateState::Queued) => FirmwareState::Queued,
        Ok(psm::FirmwareUpdateState::Verifying) => FirmwareState::Verifying,
        Ok(psm::FirmwareUpdateState::Completed) => FirmwareState::Completed,
        Ok(psm::FirmwareUpdateState::Failed) => FirmwareState::Failed,
        _ => FirmwareState::Unknown,
    }
}

fn ids_to_strings(ids: &[PowerShelfId]) -> Vec<String> {
    ids.iter().map(|id| id.to_string()).collect()
}

fn parse_power_shelf_id(s: &str) -> Result<PowerShelfId, ComponentManagerError> {
    PowerShelfId::from_str(s).map_err(|e| {
        ComponentManagerError::Internal(format!("invalid power shelf id from backend: {e}"))
    })
}

#[async_trait::async_trait]
impl PowerShelfManager for PsmPowerShelfBackend {
    fn name(&self) -> &str {
        "psm"
    }

    #[instrument(skip(self), fields(backend = "psm"))]
    async fn power_control(
        &self,
        ids: &[PowerShelfId],
        action: PowerAction,
    ) -> Result<Vec<PowerShelfComponentResult>, ComponentManagerError> {
        let id_strings = ids_to_strings(ids);
        let request = psm::PowershelfRequest {
            pmc_macs: id_strings.clone(),
        };

        let response = match action {
            PowerAction::On => self.client.clone().power_on(request).await?.into_inner(),
            PowerAction::ForceOff | PowerAction::GracefulShutdown => {
                self.client.clone().power_off(request).await?.into_inner()
            }
            PowerAction::GracefulRestart
            | PowerAction::ForceRestart
            | PowerAction::AcPowercycle => {
                let off = self
                    .client
                    .clone()
                    .power_off(psm::PowershelfRequest {
                        pmc_macs: id_strings.clone(),
                    })
                    .await?
                    .into_inner();

                let any_off_failure = off
                    .responses
                    .iter()
                    .any(|r| r.status != psm::StatusCode::Success as i32);
                if any_off_failure {
                    return off
                        .responses
                        .into_iter()
                        .map(|r| {
                            Ok(PowerShelfComponentResult {
                                power_shelf_id: parse_power_shelf_id(&r.pmc_mac_address)?,
                                success: r.status == psm::StatusCode::Success as i32,
                                error: if r.error.is_empty() {
                                    None
                                } else {
                                    Some(r.error)
                                },
                            })
                        })
                        .collect();
                }

                self.client
                    .clone()
                    .power_on(psm::PowershelfRequest {
                        pmc_macs: id_strings,
                    })
                    .await?
                    .into_inner()
            }
        };

        response
            .responses
            .into_iter()
            .map(|r| {
                Ok(PowerShelfComponentResult {
                    power_shelf_id: parse_power_shelf_id(&r.pmc_mac_address)?,
                    success: r.status == psm::StatusCode::Success as i32,
                    error: if r.error.is_empty() {
                        None
                    } else {
                        Some(r.error)
                    },
                })
            })
            .collect()
    }

    #[instrument(skip(self), fields(backend = "psm"))]
    async fn update_firmware(
        &self,
        ids: &[PowerShelfId],
        target_version: &str,
        components: &[String],
    ) -> Result<Vec<PowerShelfComponentResult>, ComponentManagerError> {
        let upgrades = ids
            .iter()
            .map(|id| {
                let mac = id.to_string();
                let component_reqs: Vec<psm::UpdateComponentFirmwareRequest> =
                    if components.is_empty() {
                        vec![
                            psm::UpdateComponentFirmwareRequest {
                                component: psm::PowershelfComponent::Pmc as i32,
                                upgrade_to: Some(psm::FirmwareVersion {
                                    version: target_version.to_owned(),
                                }),
                            },
                            psm::UpdateComponentFirmwareRequest {
                                component: psm::PowershelfComponent::Psu as i32,
                                upgrade_to: Some(psm::FirmwareVersion {
                                    version: target_version.to_owned(),
                                }),
                            },
                        ]
                    } else {
                        components
                            .iter()
                            .filter_map(|c| {
                                let comp = match c.to_lowercase().as_str() {
                                    "pmc" => psm::PowershelfComponent::Pmc as i32,
                                    "psu" => psm::PowershelfComponent::Psu as i32,
                                    _ => return None,
                                };
                                Some(psm::UpdateComponentFirmwareRequest {
                                    component: comp,
                                    upgrade_to: Some(psm::FirmwareVersion {
                                        version: target_version.to_owned(),
                                    }),
                                })
                            })
                            .collect()
                    };
                psm::UpdatePowershelfFirmwareRequest {
                    pmc_mac_address: mac,
                    components: component_reqs,
                }
            })
            .collect();

        let request = psm::UpdateFirmwareRequest { upgrades };

        let response = self
            .client
            .clone()
            .update_firmware(request)
            .await?
            .into_inner();

        response
            .responses
            .into_iter()
            .map(|r| {
                let any_error = r
                    .components
                    .iter()
                    .any(|c| c.status != psm::StatusCode::Success as i32);
                let error_msg = r
                    .components
                    .iter()
                    .filter(|c| !c.error.is_empty())
                    .map(|c| c.error.clone())
                    .collect::<Vec<_>>()
                    .join("; ");
                Ok(PowerShelfComponentResult {
                    power_shelf_id: parse_power_shelf_id(&r.pmc_mac_address)?,
                    success: !any_error,
                    error: if error_msg.is_empty() {
                        None
                    } else {
                        Some(error_msg)
                    },
                })
            })
            .collect()
    }

    #[instrument(skip(self), fields(backend = "psm"))]
    async fn get_firmware_status(
        &self,
        ids: &[PowerShelfId],
    ) -> Result<Vec<PowerShelfFirmwareUpdateStatus>, ComponentManagerError> {
        let queries = ids
            .iter()
            .flat_map(|id| {
                let mac = id.to_string();
                vec![
                    psm::FirmwareUpdateQuery {
                        pmc_mac_address: mac.clone(),
                        component: psm::PowershelfComponent::Pmc as i32,
                    },
                    psm::FirmwareUpdateQuery {
                        pmc_mac_address: mac,
                        component: psm::PowershelfComponent::Psu as i32,
                    },
                ]
            })
            .collect();

        let request = psm::GetFirmwareUpdateStatusRequest { queries };

        let response = self
            .client
            .clone()
            .get_firmware_update_status(request)
            .await?
            .into_inner();

        response
            .statuses
            .into_iter()
            .map(|s| {
                Ok(PowerShelfFirmwareUpdateStatus {
                    power_shelf_id: parse_power_shelf_id(&s.pmc_mac_address)?,
                    state: map_psm_fw_state(s.state),
                    target_version: String::new(),
                    error: if s.error.is_empty() {
                        None
                    } else {
                        Some(s.error)
                    },
                })
            })
            .collect()
    }

    #[instrument(skip(self), fields(backend = "psm"))]
    async fn list_firmware(
        &self,
        ids: &[PowerShelfId],
    ) -> Result<Vec<String>, ComponentManagerError> {
        let request = psm::PowershelfRequest {
            pmc_macs: ids_to_strings(ids),
        };

        let response = self
            .client
            .clone()
            .list_available_firmware(request)
            .await?
            .into_inner();

        let versions: Vec<String> = response
            .upgrades
            .into_iter()
            .flat_map(|af| {
                af.upgrades
                    .into_iter()
                    .flat_map(|cu| cu.upgrades.into_iter().map(|fv| fv.version))
            })
            .collect();

        Ok(versions)
    }
}
