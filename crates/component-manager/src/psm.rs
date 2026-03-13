// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use mac_address::MacAddress;
use tonic::transport::Channel;
use tracing::instrument;

use crate::config::BackendTlsConfig;
use crate::error::ComponentManagerError;
use crate::power_shelf_manager::{
    FirmwareState, PowerShelfComponentResult, PowerShelfEndpoint, PowerShelfFirmwareUpdateStatus,
    PowerShelfManager, PowerShelfVendor,
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

fn parse_mac(s: &str) -> Result<MacAddress, ComponentManagerError> {
    s.parse::<MacAddress>()
        .map_err(|e| ComponentManagerError::Internal(format!("invalid MAC from backend: {e}")))
}

fn map_vendor(v: &PowerShelfVendor) -> i32 {
    match v {
        PowerShelfVendor::Unknown => psm::PmcVendor::PmcTypeUnknown as i32,
        PowerShelfVendor::Liteon => psm::PmcVendor::PmcTypeLiteon as i32,
    }
}

fn mac_strings(endpoints: &[PowerShelfEndpoint]) -> Vec<String> {
    endpoints.iter().map(|ep| ep.pmc_mac.to_string()).collect()
}

/// Registers endpoints with PSM. PSM uses PMC MAC as its identifier, so
/// registration is primarily about ensuring PSM knows about the device and
/// has credentials.
async fn register_with_psm(
    client: &mut psm::powershelf_manager_client::PowershelfManagerClient<Channel>,
    endpoints: &[PowerShelfEndpoint],
) -> Result<(), ComponentManagerError> {
    let reqs: Vec<psm::RegisterPowershelfRequest> = endpoints
        .iter()
        .map(|ep| psm::RegisterPowershelfRequest {
            pmc_mac_address: ep.pmc_mac.to_string(),
            pmc_ip_address: ep.pmc_ip.to_string(),
            pmc_vendor: map_vendor(&ep.pmc_vendor),
            pmc_credentials: None,
        })
        .collect();

    let response = client
        .register_powershelves(psm::RegisterPowershelvesRequest {
            registration_requests: reqs,
        })
        .await?
        .into_inner();

    let failures: Vec<_> = response
        .responses
        .iter()
        .filter(|r| r.status != psm::StatusCode::Success as i32)
        .collect();

    if failures.len() == endpoints.len() && !endpoints.is_empty() {
        let errors: Vec<String> = failures.iter().map(|f| f.error.clone()).collect();
        return Err(ComponentManagerError::Internal(format!(
            "PSM registration failed for all power shelves: {}",
            errors.join("; ")
        )));
    }

    for f in &failures {
        tracing::warn!(
            pmc_mac = %f.pmc_mac_address,
            error = %f.error,
            "PSM registration failed for power shelf"
        );
    }

    Ok(())
}

#[async_trait::async_trait]
impl PowerShelfManager for PsmPowerShelfBackend {
    fn name(&self) -> &str {
        "psm"
    }

    #[instrument(skip(self), fields(backend = "psm"))]
    async fn power_control(
        &self,
        endpoints: &[PowerShelfEndpoint],
        action: PowerAction,
    ) -> Result<Vec<PowerShelfComponentResult>, ComponentManagerError> {
        register_with_psm(&mut self.client.clone(), endpoints).await?;

        let pmc_macs = mac_strings(endpoints);
        let request = psm::PowershelfRequest {
            pmc_macs: pmc_macs.clone(),
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
                        pmc_macs: pmc_macs.clone(),
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
                                pmc_mac: parse_mac(&r.pmc_mac_address)?,
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
                    .power_on(psm::PowershelfRequest { pmc_macs })
                    .await?
                    .into_inner()
            }
        };

        response
            .responses
            .into_iter()
            .map(|r| {
                Ok(PowerShelfComponentResult {
                    pmc_mac: parse_mac(&r.pmc_mac_address)?,
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
        endpoints: &[PowerShelfEndpoint],
        target_version: &str,
        components: &[String],
    ) -> Result<Vec<PowerShelfComponentResult>, ComponentManagerError> {
        register_with_psm(&mut self.client.clone(), endpoints).await?;

        let upgrades = endpoints
            .iter()
            .map(|ep| {
                let mac = ep.pmc_mac.to_string();
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
                    pmc_mac: parse_mac(&r.pmc_mac_address)?,
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
        endpoints: &[PowerShelfEndpoint],
    ) -> Result<Vec<PowerShelfFirmwareUpdateStatus>, ComponentManagerError> {
        register_with_psm(&mut self.client.clone(), endpoints).await?;

        let queries = endpoints
            .iter()
            .flat_map(|ep| {
                let mac = ep.pmc_mac.to_string();
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
                    pmc_mac: parse_mac(&s.pmc_mac_address)?,
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
        endpoints: &[PowerShelfEndpoint],
    ) -> Result<Vec<String>, ComponentManagerError> {
        register_with_psm(&mut self.client.clone(), endpoints).await?;

        let request = psm::PowershelfRequest {
            pmc_macs: mac_strings(endpoints),
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
