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

use arc_swap::ArcSwap;
use async_trait::async_trait;
use forge_secrets::credentials::{
    BmcCredentialType, CredentialKey, CredentialProvider, CredentialType, Credentials,
};
use libredfish::{
    EnabledDisabled, Endpoint, PowerState, Redfish, RedfishError, SystemPowerControl,
    model::BootProgress,
};
use sqlx::PgConnection;
use std::net::IpAddr;
use std::{collections::HashMap, str::FromStr, sync::Arc};
use utils::HostPortPair;

use crate::api::log_request_data;
use crate::{
    CarbideError, CarbideResult,
    db::{self},
    ipmitool::IPMITool,
    model::machine::Machine,
};

#[derive(thiserror::Error, Debug)]
pub enum RedfishClientCreationError {
    #[error("Missing credential {key}: {cause}")]
    MissingCredentials { key: String, cause: eyre::Report },
    #[error("Failed redfish request {0}")]
    RedfishError(RedfishError),
    #[error("Invalid Header {0}")]
    InvalidHeader(String),
    #[error("Missing Arguments: {0}")]
    MissingArgument(String),
    #[error("Missing BMC Information: {0}")]
    MissingBmcEndpoint(String),
    #[error("Database Error Loading Machine Interface")]
    MachineInterfaceLoadError(#[from] crate::db::DatabaseError),
}

pub enum RedfishAuth {
    Anonymous,
    Key(CredentialKey),
    Direct(String, String), // username, password
}

/// Create Redfish clients for a certain Redfish BMC endpoint
#[async_trait]
pub trait RedfishClientPool: Send + Sync + 'static {
    // MARK: - Required methods

    /// Creates a new Redfish client for a Machines BMC
    /// `host` is the IP address or hostname of the BMC
    async fn create_client(
        &self,
        host: &str,
        port: Option<u16>,
        auth: RedfishAuth,
        initialize: bool, // fetch some initial values like system id and manager id
    ) -> Result<Box<dyn Redfish>, RedfishClientCreationError>;

    /// Returns a CredentialProvider for use in setting credentials in the UEFI/BMC.
    fn credential_provider(&self) -> Arc<dyn CredentialProvider>;

    // MARK: - Default (helper) methods

    fn allow_proxy_to_unknown_host(&self) -> bool {
        false
    }

    async fn create_client_from_machine(
        &self,
        target: &Machine,
        txn: &mut PgConnection,
    ) -> Result<Box<dyn Redfish>, RedfishClientCreationError> {
        let Some(addr) = target.bmc_addr() else {
            return if self.allow_proxy_to_unknown_host() {
                // test_integration relies on this because it doesn't use site_explorer and thus
                // can't inform carbide of what the BMC address is for a host. It only runs one
                // instance of bmc_mock so it can accept requests for any host.
                tracing::info!(
                    "BMC Endpoint Information (bmc_info.ip) is missing for {}, but allow_proxy_to_unknown_host is set. Will send requests to proxy without knowing the host IP",
                    target.id
                );
                self.create_client("", None, RedfishAuth::Anonymous, true)
                    .await
            } else {
                Err(RedfishClientCreationError::MissingBmcEndpoint(format!(
                    "BMC Endpoint Information (bmc_info.ip) is missing for {}",
                    target.id,
                )))
            };
        };

        self.create_client_for_ingested_host(addr.ip(), Some(addr.port()), txn)
            .await
    }

    /// Create a redfish client using auth credentials we already have in machine_interfaces for a
    /// given IP.
    ///
    /// For testing purposes, if no credentials are found for the IP, and if self.proxy_address is
    /// set, will use anonymous auth.
    async fn create_client_for_ingested_host(
        &self,
        ip: IpAddr,
        port: Option<u16>,
        txn: &mut PgConnection,
    ) -> Result<Box<dyn Redfish>, RedfishClientCreationError> {
        let auth_key = db::machine_interface::find_by_ip(txn, ip)
            .await?
            .ok_or_else(|| {
                RedfishClientCreationError::MissingArgument(format!(
                    "Machine Interface for IP address: {}",
                    ip
                ))
            })
            .map(|machine_interface| {
                RedfishAuth::Key(CredentialKey::BmcCredentials {
                    // TODO(ajf): Change this to Forge Admin user once site explorer
                    // ensures it exist, credentials are done by mac address
                    credential_type: BmcCredentialType::BmcRoot {
                        bmc_mac_address: machine_interface.mac_address,
                    },
                })
            })?;

        self.create_client(&ip.to_string(), port, auth_key, true)
            .await
    }

    // clear_host_uefi_password updates the UEFI password from Forge's sitewide password to an empty string
    // The assumption is that this function will only be called on a machine that already updated the UEFI password to match the Forge sitewide password.
    async fn clear_host_uefi_password(
        &self,
        client: &dyn Redfish,
    ) -> Result<Option<String>, RedfishClientCreationError> {
        let credential_key = CredentialKey::HostUefi {
            credential_type: CredentialType::SiteDefault,
        };

        let credentials = self
            .credential_provider()
            .get_credentials(credential_key.clone())
            .await
            .map_err(|cause| RedfishClientCreationError::MissingCredentials {
                key: credential_key.to_key_str(),
                cause,
            })?;

        let (_, current_password) = match credentials {
            Credentials::UsernamePassword { username, password } => (username, password),
        };

        client
            .clear_uefi_password(current_password.as_str())
            .await
            .map_err(RedfishClientCreationError::RedfishError)
    }

    async fn uefi_setup(
        &self,
        client: &dyn Redfish,
        dpu: bool,
    ) -> Result<Option<String>, RedfishClientCreationError> {
        let mut current_password = String::new();
        let new_password: String;
        if dpu {
            let bios_attrs = client
                .bios()
                .await
                .map_err(RedfishClientCreationError::RedfishError)?;

            //
            // This should be changed to be an actual failure once we make it this far since we don't
            // want to leave machines lying around in the datacenter without UEFI credentials.
            //
            // But adding logs here so that we know when it happens
            //
            match bios_attrs.get("Attributes") {
                None => {
                    tracing::warn!(
                        "BIOS Attributes are missing in the Redfish System BIOS endpoint, skipping UEFI password setting"
                    );
                    return Ok(None);
                }
                Some(attrs) => match attrs.as_object() {
                    None => {
                        tracing::warn!(
                            "BIOS attributes are not an object in the Redfish System BIOS endpoint, skipping UEFI password setting"
                        );
                        return Ok(None);
                    }
                    Some(attrs) if !attrs.contains_key("CurrentUefiPassword") => {
                        tracing::warn!(
                            "BIOS Attributes exist, but is missing CurrentUefiPassword key, skipping UEFI password setting"
                        );
                        return Ok(None);
                    }
                    _ => {
                        tracing::info!(
                            "BIOS Attributes found, and contains CurrentUefiPassword, continuing with UEFI password setting"
                        );
                    }
                },
            }

            // Replace DPU UEFI default password with site default
            // default password is taken from DpuUefi:factory_default key
            // site password is taken from DpuUefi:site_default key
            //
            let credentials = self
                .credential_provider()
                .get_credentials(CredentialKey::DpuUefi {
                    credential_type: CredentialType::DpuHardwareDefault,
                })
                .await
                .unwrap_or(Credentials::UsernamePassword {
                    username: "".to_string(),
                    password: "bluefield".to_string(),
                });

            (_, current_password) = match credentials {
                Credentials::UsernamePassword { username, password } => (username, password),
            };

            let credential_key = CredentialKey::DpuUefi {
                credential_type: CredentialType::SiteDefault,
            };
            let credentials = self
                .credential_provider()
                .get_credentials(credential_key.clone())
                .await
                .map_err(|cause| RedfishClientCreationError::MissingCredentials {
                    key: credential_key.to_key_str(),
                    cause,
                })?;

            (_, new_password) = match credentials {
                Credentials::UsernamePassword { username, password } => (username, password),
            };
        } else {
            // the current password is always an empty string for the host uefi
            let credential_key = CredentialKey::HostUefi {
                credential_type: CredentialType::SiteDefault,
            };
            let credentials = self
                .credential_provider()
                .get_credentials(credential_key.clone())
                .await
                .map_err(|cause| RedfishClientCreationError::MissingCredentials {
                    key: credential_key.to_key_str(),
                    cause,
                })?;

            (_, new_password) = match credentials {
                Credentials::UsernamePassword { username, password } => (username, password),
            };
        }

        client
            .change_uefi_password(current_password.as_str(), new_password.as_str())
            .await
            .map_err(RedfishClientCreationError::RedfishError)
    }
}

pub struct RedfishClientPoolImpl {
    pool: libredfish::RedfishClientPool,
    credential_provider: Arc<dyn CredentialProvider>,
    proxy_address: Arc<ArcSwap<Option<HostPortPair>>>,
    allow_proxy_to_unknown_host: bool,
}

impl RedfishClientPoolImpl {
    pub fn new(
        credential_provider: Arc<dyn CredentialProvider>,
        pool: libredfish::RedfishClientPool,
        proxy_address: Arc<ArcSwap<Option<HostPortPair>>>,
        allow_proxy_to_unknown_host: bool,
    ) -> Self {
        RedfishClientPoolImpl {
            credential_provider,
            pool,
            proxy_address,
            allow_proxy_to_unknown_host,
        }
    }
}

#[async_trait]
impl RedfishClientPool for RedfishClientPoolImpl {
    async fn create_client(
        &self,
        host: &str,
        port: Option<u16>,
        auth: RedfishAuth,
        initialize: bool,
    ) -> Result<Box<dyn Redfish>, RedfishClientCreationError> {
        let original_host = host;

        // Allow globally overriding the bmc port via site-config. We read this on every call to
        // create_client, because self.proxy_address is a dynamic setting.
        let proxy_address = self.proxy_address.load();
        let (host, port, add_custom_header) = match proxy_address.as_ref() {
            // No override
            None => (host, port, false),
            // Override the host and port
            Some(HostPortPair::HostAndPort(h, p)) => (h.as_str(), Some(*p), true),
            // Only override the host
            Some(HostPortPair::HostOnly(h)) => (h.as_str(), port, true),
            // Only override the port
            Some(HostPortPair::PortOnly(p)) => (host, Some(*p), false),
        };

        let (username, password) = match auth {
            RedfishAuth::Anonymous => (None, None), // anonymous login, usually to get service root Vendor info
            RedfishAuth::Direct(username, password) => (Some(username), Some(password)),
            RedfishAuth::Key(credential_key) => {
                let credentials = self
                    .credential_provider
                    .get_credentials(credential_key.clone())
                    .await
                    .map_err(|cause| RedfishClientCreationError::MissingCredentials {
                        key: credential_key.to_key_str(),
                        cause,
                    })?;

                let (username, password) = match credentials {
                    Credentials::UsernamePassword { username, password } => {
                        (Some(username), Some(password))
                    }
                };

                (username, password)
            }
        };

        let endpoint = Endpoint {
            host: host.to_string(),
            port,
            user: username,
            password,
        };

        let custom_headers = if add_custom_header {
            // If we're overriding the host, inject a header indicating the IP address we were
            // originally going to use, using the HTTP "Forwarded" header:
            // https://datatracker.ietf.org/doc/html/rfc7239

            // Override host only if host value is provided in config.
            vec![(
                http::HeaderName::from_str("forwarded")
                    .map_err(|err| RedfishClientCreationError::InvalidHeader(err.to_string()))?,
                format!("host={original_host}"),
            )]
        } else {
            Vec::default()
        };

        if initialize {
            // Creating the client performs a HTTP request to determine the BMC vendor
            self.pool
                .create_client_with_custom_headers(endpoint, custom_headers)
                .await
                .map_err(RedfishClientCreationError::RedfishError)
        } else {
            // This client does not make any HTTP requests
            let client: Box<dyn Redfish> = self
                .pool
                .create_standard_client_with_custom_headers(endpoint.clone(), custom_headers)
                .map_err(RedfishClientCreationError::RedfishError)?;
            Ok(client)
        }
    }

    fn credential_provider(&self) -> Arc<dyn CredentialProvider> {
        self.credential_provider.clone()
    }

    fn allow_proxy_to_unknown_host(&self) -> bool {
        self.allow_proxy_to_unknown_host
    }
}

/// redfish utility functions
///
/// host_power_control allows control over the power of the host
pub async fn host_power_control(
    redfish_client: &dyn Redfish,
    machine: &Machine,
    action: SystemPowerControl,
    ipmi_tool: Arc<dyn IPMITool>,
    txn: &mut PgConnection,
) -> CarbideResult<()> {
    // Always log to ensure we can see that forge is doing the power controlling
    tracing::info!(
        machine_id = machine.id.to_string(),
        action = action.to_string(),
        "Host Power Control"
    );
    db::machine::update_reboot_requested_time(&machine.id, txn, action.into()).await?;
    match machine.bmc_vendor() {
        bmc_vendor::BMCVendor::Lenovo => {
            // Lenovos prepend the users OS to the boot order once it is installed and this cleans up the mess
            redfish_client
                .boot_once(libredfish::Boot::Pxe)
                .await
                .map_err(CarbideError::RedfishError)?;

            redfish_client
                .power(action)
                .await
                .map_err(CarbideError::RedfishError)?;
        }
        bmc_vendor::BMCVendor::Supermicro => {
            match machine.current_state() {
                /*
                    These two states will add pending BIOS settings prior to calling host_power_control
                    On Supermicros, this will result in the following error from calling boot_once:
                        Failed to advance state: handler_host_power_control failed:
                        Error in libredfish: HTTP 400 Bad Request at https://10.217.155.10:443/redfish/v1/Systems/1:
                        {"error":{"code":"Base.v1_10_3.GeneralError","message":"A general error has occurred. See ExtendedInfo for more information.",
                        "@Message.ExtendedInfo": [{"MessageId":"SMC.v1_0_0.OemBiosSettingFileAlreadyExists","Severity":"Warning","Resolution":"No resolution is required.",
                        "Message":"Bios setting file already exists.","MessageArgs":[""],"RelatedProperties":[""]}]}}
                */
                crate::model::machine::ManagedHostState::HostInit {
                    machine_state:
                        crate::model::machine::MachineState::WaitingForPlatformConfiguration,
                }
                | crate::model::machine::ManagedHostState::HostInit {
                    machine_state:
                        crate::model::machine::MachineState::SetBootOrder {
                            set_boot_order_info: _,
                        },
                } => {}
                _ => {
                    // We need to unlock BMC to perform boot modification, and relock it later
                    let lstatus = redfish_client.lockdown_status().await?;
                    if lstatus.is_fully_enabled() {
                        redfish_client.lockdown(EnabledDisabled::Disabled).await?;
                    }
                    // Supermicro will boot the users OS if we don't do this
                    let boot_result = redfish_client
                        .boot_once(libredfish::Boot::Pxe)
                        .await
                        .map_err(CarbideError::RedfishError);
                    if lstatus.is_fully_enabled() {
                        redfish_client.lockdown(EnabledDisabled::Enabled).await?;
                    }

                    // We error only after lockdown is reinstaited
                    boot_result?;
                }
            }

            redfish_client
                .power(action)
                .await
                .map_err(CarbideError::RedfishError)?;
        }

        bmc_vendor::BMCVendor::Nvidia
            if (action == SystemPowerControl::GracefulRestart)
                || (action == SystemPowerControl::ForceRestart) =>
        {
            // vikings reboot their DPU's if redfish reset is used. \
            // ipmitool is verified to not cause it to reset, so we use it, hackily, here.
            //
            // TODO(ajf) none of this IPMI code should be in the redfish module, we've already constructed
            // a redfish client and aren't going to use it, and constructing an IPMI requires duplicate
            // work that we did in the calling function.
            //
            let machine_id = &machine.id;

            let maybe_ip = machine.bmc_info.ip.as_ref().ok_or_else(|| {
                CarbideError::internal(format!("IP address is missing for {}", machine_id))
            })?;

            let ip = maybe_ip.parse().map_err(|_| {
                CarbideError::internal(format!("Invalid IP address for {}", machine_id))
            })?;

            let machine_interface_target = db::machine_interface::find_by_ip(txn, ip)
                .await?
                .ok_or_else(|| CarbideError::NotFoundError {
                    kind: "MachineInterface by IP",
                    id: ip.to_string(),
                })?;

            let credential_key = CredentialKey::BmcCredentials {
                credential_type: BmcCredentialType::BmcRoot {
                    bmc_mac_address: machine_interface_target.mac_address,
                },
            };

            ipmi_tool
                .restart(&machine.id, ip, false, credential_key)
                .await
                .map_err(|e: eyre::ErrReport| {
                    CarbideError::internal(format!("Failed to restart machine: {}", e))
                })?;
        }

        _ => {
            if (action == SystemPowerControl::GracefulRestart)
                || (action == SystemPowerControl::ForceRestart)
            {
                let power_result: Result<PowerState, RedfishError> =
                    redfish_client.get_power_state().await;
                if let Ok(power_state) = power_result {
                    tracing::info!(
                        machine_id = machine.id.to_string(),
                        action = power_state.to_string(),
                        "Host Power State"
                    );
                    if power_state == PowerState::Off {
                        tracing::info!(
                            machine_id = machine.id.to_string(),
                            action =
                                "Manual intervention required to initiate power-on".to_string(),
                            "Host Power Action"
                        );
                        /* // reserve for future proactive power on action
                        redfish_client
                        .power(SystemPowerControl::On)
                        .await
                        .map_err(CarbideError::RedfishError)?
                        */
                    } else {
                        redfish_client
                            .power(action)
                            .await
                            .map_err(CarbideError::RedfishError)?
                    }
                }
            } else {
                redfish_client
                    .power(action)
                    .await
                    .map_err(CarbideError::RedfishError)?
            }
        }
    }

    Ok(())
}

/// set_host_uefi_password sets the UEFI password on the host and then power-cycles it.
/// It returns the job ID for the UEFI password change for vendors that require
/// generating a job to set the UEFI password.
pub async fn set_host_uefi_password(
    redfish_client: &dyn Redfish,
    redfish_client_pool: Arc<dyn RedfishClientPool>,
) -> CarbideResult<Option<String>> {
    redfish_client_pool
        .uefi_setup(redfish_client, false)
        .await
        .map_err(|e| {
            tracing::error!(%e, "Failed to run uefi_setup call");
            CarbideError::internal(format!("Failed redfish uefi_setup subtask: {}", e))
        })
}

pub async fn clear_host_uefi_password(
    redfish_client: &dyn Redfish,
    redfish_client_pool: Arc<dyn RedfishClientPool>,
) -> CarbideResult<Option<String>> {
    redfish_client_pool
        .clear_host_uefi_password(redfish_client)
        .await
        .map_err(|e| {
            tracing::error!(%e, "Failed to run clear_host_uefi_password call");
            CarbideError::internal(format!(
                "Failed redfish clear_host_uefi_password subtask: {}",
                e
            ))
        })
}

const LAST_OEM_STATE_OS_IS_RUNNING: &str = "OsIsRunning";

// did_dpu_finish_booting returns true if the DPU has come up from the last reboot and the OS is running. It will return false if the DPU has not come up from the last reboot or is stuck booting.
// the function will return the BootProgress structure to the caller if it returns true.
pub async fn did_dpu_finish_booting(
    dpu_redfish_client: &dyn Redfish,
) -> Result<(bool, Option<BootProgress>), RedfishError> {
    let system = dpu_redfish_client.get_system().await?;
    match system.boot_progress.clone() {
        Some(boot_progress) => {
            let is_dpu_up = match boot_progress
                .last_state
                .unwrap_or(libredfish::model::BootProgressTypes::None)
            {
                libredfish::model::BootProgressTypes::OSRunning => true,
                _ => {
                    boot_progress.oem_last_state.unwrap_or_default() == LAST_OEM_STATE_OS_IS_RUNNING
                }
            };

            Ok((is_dpu_up, system.boot_progress))
        }
        None => Ok((false, None)),
    }
}

pub async fn redfish_browse(
    api: &crate::api::Api,
    request: tonic::Request<::rpc::forge::RedfishBrowseRequest>,
) -> Result<tonic::Response<::rpc::forge::RedfishBrowseResponse>, tonic::Status> {
    log_request_data(&request);

    let request = request.into_inner();
    let uri: http::Uri = match request.uri.clone().parse() {
        Ok(uri) => uri,
        Err(err) => {
            return Err(CarbideError::internal(format!("Parsing uri failed: {}", err)).into());
        }
    };

    let bmc_metadata_request = tonic::Request::new(rpc::forge::BmcMetaDataGetRequest {
        machine_id: None,
        bmc_endpoint_request: Some(rpc::forge::BmcEndpointRequest {
            ip_address: uri.host().map(|x| x.to_string()).unwrap_or_default(),
            mac_address: None,
        }),
        role: rpc::forge::UserRoles::Administrator.into(),
        request_type: rpc::forge::BmcRequestType::Ipmi.into(),
    });

    let metadata = crate::handlers::bmc_metadata::get(api, bmc_metadata_request)
        .await?
        .into_inner();

    let http_client = {
        let builder = reqwest::Client::builder();
        let builder = builder
            .danger_accept_invalid_certs(true)
            .redirect(reqwest::redirect::Policy::limited(5))
            .connect_timeout(std::time::Duration::from_secs(5)) // Limit connections to 5 seconds
            .timeout(std::time::Duration::from_secs(60)); // Limit the overall request to 60 seconds

        match builder.build() {
            Ok(client) => client,
            Err(err) => {
                tracing::error!(%err, "build_http_client");
                return Err(
                    CarbideError::internal(format!("Http building failed: {}", err)).into(),
                );
            }
        }
    };

    let response = match http_client
        .request(http::Method::GET, request.uri.to_string())
        .basic_auth(metadata.user.clone(), Some(metadata.password.clone()))
        .send()
        .await
    {
        Ok(response) => response,
        Err(e) => {
            return Err(CarbideError::internal(format!("Http request failed: {:?}", e)).into());
        }
    };

    let headers = response
        .headers()
        .iter()
        .map(|(x, y)| {
            (
                x.to_string(),
                String::from_utf8_lossy(y.as_bytes()).to_string(),
            )
        })
        .collect::<HashMap<String, String>>();

    let status = response.status();
    let text = response.text().await.map_err(|e| {
        CarbideError::internal(format!(
            "Error reading response body: {}, Status: {}",
            e, status
        ))
    })?;

    Ok(tonic::Response::new(::rpc::forge::RedfishBrowseResponse {
        text,
        headers,
    }))
}

#[cfg(test)]
pub mod test_support {
    use super::*;
    use libredfish::{
        Chassis, Collection, EnabledDisabled, JobState, NetworkAdapter, PowerState, Redfish,
        RedfishError, Resource, SystemPowerControl,
        model::{
            ODataId, ODataLinks,
            oem::nvidia_dpu::NicMode,
            secure_boot::SecureBootMode,
            sensor::GPUSensors,
            service_root::ServiceRoot,
            storage::Drives,
            task::Task,
            update_service::{ComponentType, TransferProtocolType, UpdateService},
        },
    };
    use mac_address::MacAddress;
    use std::path::Path;
    use std::sync::Mutex;
    use std::time::Duration;
    use {chrono::Utc, forge_secrets::credentials::TestCredentialProvider};

    #[derive(Default)]
    struct RedfishSimState {
        _hosts: HashMap<String, RedfishSimHostState>,
        users: HashMap<String, String>,
        fw_version: Arc<String>,
    }

    #[derive(Debug, Default)]
    struct RedfishSimHostState {
        power: PowerState,
    }

    #[derive(Default)]
    pub struct RedfishSim {
        state: Arc<Mutex<RedfishSimState>>,
    }

    struct RedfishSimClient {
        state: Arc<Mutex<RedfishSimState>>,
        _host: String,
        _port: Option<u16>,
    }

    #[async_trait]
    impl Redfish for RedfishSimClient {
        async fn get_power_state(&self) -> Result<libredfish::PowerState, RedfishError> {
            Ok(self.state.clone().lock().unwrap()._hosts[&self._host].power)
        }

        async fn get_power_metrics(&self) -> Result<libredfish::model::power::Power, RedfishError> {
            todo!()
        }

        async fn power(&self, action: libredfish::SystemPowerControl) -> Result<(), RedfishError> {
            let power_state = match action {
                libredfish::SystemPowerControl::ForceOff
                | libredfish::SystemPowerControl::GracefulShutdown => PowerState::Off,
                _ => PowerState::On,
            };
            self.state
                .clone()
                .lock()
                .unwrap()
                ._hosts
                .get_mut(&self._host)
                .unwrap()
                .power = power_state;
            Ok(())
        }

        async fn bmc_reset(&self) -> Result<(), RedfishError> {
            Ok(())
        }

        async fn get_thermal_metrics(
            &self,
        ) -> Result<libredfish::model::thermal::Thermal, RedfishError> {
            todo!()
        }

        async fn machine_setup(
            &self,
            _boot_interface_mac: Option<&str>,
            _bios_profiles: &HashMap<
                libredfish::model::service_root::RedfishVendor,
                HashMap<
                    String,
                    HashMap<libredfish::BiosProfileType, HashMap<String, serde_json::Value>>,
                >,
            >,
            _profile_type: libredfish::BiosProfileType,
        ) -> Result<(), RedfishError> {
            Ok(())
        }

        async fn machine_setup_status(
            &self,
            _boot_interface_mac: Option<&str>,
        ) -> Result<libredfish::MachineSetupStatus, RedfishError> {
            Ok(libredfish::MachineSetupStatus {
                is_done: true,
                diffs: vec![],
            })
        }

        async fn lockdown(&self, _target: libredfish::EnabledDisabled) -> Result<(), RedfishError> {
            Ok(())
        }

        async fn lockdown_status(&self) -> Result<libredfish::Status, RedfishError> {
            Ok(libredfish::Status::build_fake(
                libredfish::EnabledDisabled::Disabled,
            ))
        }

        async fn setup_serial_console(&self) -> Result<(), RedfishError> {
            todo!()
        }

        async fn serial_console_status(&self) -> Result<libredfish::Status, RedfishError> {
            todo!()
        }

        async fn get_boot_options(&self) -> Result<libredfish::BootOptions, RedfishError> {
            todo!()
        }

        async fn get_boot_option(
            &self,
            _option_id: &str,
        ) -> Result<libredfish::model::BootOption, RedfishError> {
            todo!()
        }

        async fn boot_once(&self, _target: libredfish::Boot) -> Result<(), RedfishError> {
            Ok(())
        }

        async fn boot_first(&self, _target: libredfish::Boot) -> Result<(), RedfishError> {
            todo!()
        }

        async fn clear_tpm(&self) -> Result<(), RedfishError> {
            todo!()
        }

        async fn bios(&self) -> Result<HashMap<String, serde_json::Value>, RedfishError> {
            todo!()
        }

        async fn set_bios(
            &self,
            _values: HashMap<String, serde_json::Value>,
        ) -> Result<(), RedfishError> {
            todo!()
        }

        async fn pending(&self) -> Result<HashMap<String, serde_json::Value>, RedfishError> {
            todo!()
        }

        async fn clear_pending(&self) -> Result<(), RedfishError> {
            todo!()
        }

        async fn pcie_devices(&self) -> Result<Vec<libredfish::PCIeDevice>, RedfishError> {
            todo!()
        }

        async fn change_password(&self, user: &str, new: &str) -> Result<(), RedfishError> {
            let s_user = user.to_string();
            let mut state = self.state.lock().unwrap();
            if !state.users.contains_key(&s_user) {
                return Err(RedfishError::UserNotFound(s_user));
            }
            state.users.insert(s_user, new.to_string());
            Ok(())
        }

        async fn change_password_by_id(
            &self,
            account_id: &str,
            new_pass: &str,
        ) -> Result<(), RedfishError> {
            let s_acct = account_id.to_string();
            let mut state = self.state.lock().unwrap();
            if !state.users.contains_key(&s_acct) {
                return Err(RedfishError::UserNotFound(s_acct));
            }
            state.users.insert(s_acct, new_pass.to_string());
            Ok(())
        }

        async fn get_firmware(
            &self,
            id: &str,
        ) -> Result<libredfish::model::software_inventory::SoftwareInventory, RedfishError>
        {
            if id == "Bluefield_FW_ERoT" {
                Ok(serde_json::from_str(
                    "{
            \"@odata.id\": \"/redfish/v1/UpdateService/FirmwareInventory/Bluefield_FW_ERoT\",
            \"@odata.type\": \"#SoftwareInventory.v1_4_0.SoftwareInventory\",
            \"Description\": \"Other image\",
            \"Id\": \"Bluefield_FW_ERoT\",
            \"Manufacturer\": \"NVIDIA\",
            \"Name\": \"Software Inventory\",
            \"Version\": \"00.02.0180.0000\"
            }",
                )
                .unwrap())
            } else if id == "DPU_NIC" {
                Ok(serde_json::from_str(
                    "{
            \"@odata.id\": \"/redfish/v1/UpdateService/FirmwareInventory/DPU_NIC\",
            \"@odata.type\": \"#SoftwareInventory.v1_4_0.SoftwareInventory\",
            \"Description\": \"Other image\",
            \"Id\": \"DPU_NIC\",
            \"Manufacturer\": \"NVIDIA\",
            \"Name\": \"Software Inventory\",
            \"Version\": \"32.39.2048\"
            }",
                )
                .unwrap())
            } else {
                let state = self.state.lock().unwrap();
                Ok(serde_json::from_str(
                    "{
            \"@odata.id\": \"/redfish/v1/UpdateService/FirmwareInventory/BMC_Firmware\",
            \"@odata.type\": \"#SoftwareInventory.v1_4_0.SoftwareInventory\",
            \"Description\": \"BMC image\",
            \"Id\": \"BMC_Firmware\",
            \"Name\": \"Software Inventory\",
            \"Updateable\": true,
            \"Version\": \"BF-FW-VERSION\",
            \"WriteProtected\": false
          }"
                    .replace("FW-VERSION", state.fw_version.as_str())
                    .as_str(),
                )
                .unwrap())
            }
        }

        async fn update_firmware(
            &self,
            _firmware: tokio::fs::File,
        ) -> Result<libredfish::model::task::Task, RedfishError> {
            let mut state = self.state.lock().unwrap();
            state.fw_version = Arc::new("23.10".to_string());
            Ok(serde_json::from_str(
                "{
            \"@odata.id\": \"/redfish/v1/TaskService/Tasks/0\",
            \"@odata.type\": \"#Task.v1_4_3.Task\",
            \"Id\": \"0\"
            }",
            )
            .unwrap())
        }

        async fn update_firmware_simple_update(
            &self,
            _image_uri: &str,
            _targets: Vec<String>,
            _transfer_protocol: TransferProtocolType,
        ) -> Result<libredfish::model::task::Task, RedfishError> {
            Ok(serde_json::from_str(
                "{
            \"@odata.id\": \"/redfish/v1/TaskService/Tasks/0\",
            \"@odata.type\": \"#Task.v1_4_3.Task\",
            \"Id\": \"0\"
            }",
            )
            .unwrap())
        }

        async fn get_task(&self, _id: &str) -> Result<libredfish::model::task::Task, RedfishError> {
            Ok(serde_json::from_str(
                "{
            \"@odata.id\": \"/redfish/v1/TaskService/Tasks/0\",
            \"@odata.type\": \"#Task.v1_4_3.Task\",
            \"Id\": \"0\",
            \"PercentComplete\": 100,
            \"StartTime\": \"2024-01-30T09:00:52+00:00\",
            \"TaskMonitor\": \"/redfish/v1/TaskService/Tasks/0/Monitor\",
            \"TaskState\": \"Completed\",
            \"TaskStatus\": \"OK\"
            }",
            )
            .unwrap())
        }

        async fn get_chassis_all(&self) -> Result<Vec<String>, RedfishError> {
            Ok(vec![
                "Bluefield_BMC".to_string(),
                "Bluefield_EROT".to_string(),
                "Card1".to_string(),
            ])
        }

        async fn get_chassis(&self, _id: &str) -> Result<Chassis, RedfishError> {
            Ok(Chassis {
                manufacturer: Some("Nvidia".to_string()),
                model: Some("Bluefield 3 SmartNIC Main Card".to_string()),
                name: Some("Card1".to_string()),
                ..Default::default()
            })
        }

        async fn get_chassis_network_adapters(
            &self,
            _chassis_id: &str,
        ) -> Result<Vec<String>, RedfishError> {
            Ok(vec!["NvidiaNetworkAdapter".to_string()])
        }

        async fn get_chassis_network_adapter(
            &self,
            _chassis_id: &str,
            _id: &str,
        ) -> Result<libredfish::model::chassis::NetworkAdapter, RedfishError> {
            Ok(serde_json::from_str(
                r##"
            {
                "@odata.id": "/redfish/v1/Chassis/Card1/NetworkAdapters/NvidiaNetworkAdapter",
                "@odata.type": "#NetworkAdapter.v1_9_0.NetworkAdapter",
                "Id": "NetworkAdapter",
                "Manufacturer": "Nvidia",
                "Name": "NvidiaNetworkAdapter",
                "NetworkDeviceFunctions": {
                  "@odata.id": "/redfish/v1/Chassis/Card1/NetworkAdapters/NvidiaNetworkAdapter/NetworkDeviceFunctions"
                },
                "Ports": {
                  "@odata.id": "/redfish/v1/Chassis/Card1/NetworkAdapters/NvidiaNetworkAdapter/Ports"
                }
              }
            "##)
                .unwrap())
        }

        async fn get_manager_ethernet_interfaces(
            &self,
        ) -> Result<Vec<std::string::String>, RedfishError> {
            Ok(vec!["eth0".to_string(), "vlan4040".to_string()])
        }

        async fn get_manager_ethernet_interface(
            &self,
            _id: &str,
        ) -> Result<libredfish::model::ethernet_interface::EthernetInterface, RedfishError>
        {
            Ok(libredfish::model::ethernet_interface::EthernetInterface::default())
        }

        async fn get_system_ethernet_interfaces(
            &self,
        ) -> Result<Vec<std::string::String>, RedfishError> {
            Ok(vec!["oob_net0".to_string()])
        }

        async fn get_system_ethernet_interface(
            &self,
            _id: &str,
        ) -> Result<libredfish::model::ethernet_interface::EthernetInterface, RedfishError>
        {
            Ok(libredfish::model::ethernet_interface::EthernetInterface::default())
        }

        async fn get_software_inventories(&self) -> Result<Vec<std::string::String>, RedfishError> {
            Ok(vec![
                "BMC_Firmware".to_string(),
                "Bluefield_FW_ERoT".to_string(),
                "DPU_NIC".to_string(),
            ])
        }

        async fn get_system(&self) -> Result<libredfish::model::ComputerSystem, RedfishError> {
            Ok(libredfish::model::ComputerSystem {
                id: "Bluefield".to_string(),
                boot_progress: Some(libredfish::model::BootProgress {
                    last_state: Some(libredfish::model::BootProgressTypes::OSRunning),
                    last_state_time: Some(Utc::now().to_string()),
                    oem_last_state: Some("OSRunning".to_string()),
                }),
                ..Default::default()
            })
        }

        async fn get_secure_boot(
            &self,
        ) -> Result<libredfish::model::secure_boot::SecureBoot, RedfishError> {
            Ok(libredfish::model::secure_boot::SecureBoot {
                odata: ODataLinks {
                    odata_context: None,
                    odata_id: "/redfish/v1/Systems/Bluefield/SecureBoot".to_string(),
                    odata_type: "#SecureBoot.v1_1_0.SecureBoot".to_string(),
                    odata_etag: None,
                    links: None,
                },
                id: "SecureBoot".to_string(),
                name: "UEFI Secure Boot".to_string(),
                secure_boot_current_boot: Some(EnabledDisabled::Disabled),
                secure_boot_enable: Some(false),
                secure_boot_mode: Some(SecureBootMode::UserMode),
            })
        }

        async fn disable_secure_boot(&self) -> Result<(), RedfishError> {
            Ok(())
        }

        async fn get_network_device_functions(
            &self,
            _chassis_id: &str,
        ) -> Result<Vec<std::string::String>, RedfishError> {
            Ok(Vec::new())
        }

        async fn get_network_device_function(
            &self,
            _chassis_id: &str,
            _id: &str,
            _port: Option<&str>,
        ) -> Result<libredfish::model::network_device_function::NetworkDeviceFunction, RedfishError>
        {
            Ok(
                libredfish::model::network_device_function::NetworkDeviceFunction {
                    odata: None,
                    description: None,
                    id: None,
                    ethernet: None,
                    name: None,
                    net_dev_func_capabilities: Some(Vec::new()),
                    net_dev_func_type: None,
                    links: None,
                    oem: None,
                },
            )
        }

        async fn get_ports(
            &self,
            _chassis_id: &str,
            _network_adapter: &str,
        ) -> Result<Vec<std::string::String>, RedfishError> {
            Ok(Vec::new())
        }

        async fn get_port(
            &self,
            _chassis_id: &str,
            _network_adapter: &str,
            _id: &str,
        ) -> Result<libredfish::model::port::NetworkPort, RedfishError> {
            Ok(libredfish::model::port::NetworkPort {
                odata: None,
                description: None,
                id: None,
                name: None,
                link_status: None,
                link_network_technology: None,
                current_speed_gbps: None,
            })
        }

        async fn change_uefi_password(
            &self,
            _current_uefi_password: &str,
            _new_uefi_password: &str,
        ) -> Result<Option<String>, RedfishError> {
            Ok(None)
        }

        async fn change_boot_order(&self, _boot_array: Vec<String>) -> Result<(), RedfishError> {
            Ok(())
        }

        async fn create_user(
            &self,
            username: &str,
            password: &str,
            _role_id: libredfish::RoleId,
        ) -> Result<(), RedfishError> {
            let mut state = self.state.lock().unwrap();
            if state.users.contains_key(username) {
                return Err(RedfishError::HTTPErrorCode {
                    url: "AccountService/Accounts".to_string(),
                    status_code: http::StatusCode::BAD_REQUEST,
                    response_body: format!(
                        r##"{{
                "UserName@Message.ExtendedInfo": [
                  {{
                    "@odata.type": "#Message.v1_1_1.Message",
                    "Message": "The requested resource of type ManagerAccount with the property UserName with the value {username} already exists.",
                    "MessageArgs": [
                      "ManagerAccount",
                      "UserName",
                      "{username}"
                    ],
                    "MessageId": "Base.1.15.0.ResourceAlreadyExists",
                    "MessageSeverity": "Critical",
                    "Resolution": "Do not repeat the create operation as the resource has already been created."
                  }}
                ]
              }}"##
                    ),
                });
            }

            state
                .users
                .insert(username.to_string(), password.to_string());
            Ok(())
        }

        async fn get_service_root(
            &self,
        ) -> Result<libredfish::model::service_root::ServiceRoot, RedfishError> {
            Ok(ServiceRoot {
                vendor: Some("Nvidia".to_string()),
                ..Default::default()
            })
        }

        async fn get_systems(&self) -> Result<Vec<String>, RedfishError> {
            Ok(Vec::new())
        }

        async fn get_managers(&self) -> Result<Vec<String>, RedfishError> {
            Ok(Vec::new())
        }

        async fn get_manager(&self) -> Result<libredfish::model::Manager, RedfishError> {
            Ok(serde_json::from_str(
                r##"{
            "@odata.id": "/redfish/v1/Managers/Bluefield_BMC",
            "@odata.type": "#Manager.v1_14_0.Manager",
            "Actions": {
              "#Manager.Reset": {
                "@Redfish.ActionInfo": "/redfish/v1/Managers/Bluefield_BMC/ResetActionInfo",
                "target": "/redfish/v1/Managers/Bluefield_BMC/Actions/Manager.Reset"
              },
              "#Manager.ResetToDefaults": {
                "ResetType@Redfish.AllowableValues": [
                  "ResetAll"
                ],
                "target": "/redfish/v1/Managers/Bluefield_BMC/Actions/Manager.ResetToDefaults"
              }
            },
            "CommandShell": {
              "ConnectTypesSupported": [
                "SSH"
              ],
              "MaxConcurrentSessions": 1,
              "ServiceEnabled": true
            },
            "DateTime": "2024-04-09T11:13:49+00:00",
            "DateTimeLocalOffset": "+00:00",
            "Description": "Baseboard Management Controller",
            "EthernetInterfaces": {
              "@odata.id": "/redfish/v1/Managers/Bluefield_BMC/EthernetInterfaces"
            },
            "FirmwareVersion": "bf-23.10-5-0-g87a8acd1708.1701259870.8631477",
            "GraphicalConsole": {
              "ConnectTypesSupported": [
                "KVMIP"
              ],
              "MaxConcurrentSessions": 4,
              "ServiceEnabled": true
            },
            "Id": "Bluefield_BMC",
            "LastResetTime": "2024-04-01T13:04:04+00:00",
            "LogServices": {
                "@odata.id": "/redfish/v1/Managers/Bluefield_BMC/LogServices"
              },
              "ManagerType": "BMC",
              "Model": "OpenBmc",
              "Name": "OpenBmc Manager",
              "NetworkProtocol": {
                "@odata.id": "/redfish/v1/Managers/Bluefield_BMC/NetworkProtocol"
              },
              "Oem": {
                "@odata.id": "/redfish/v1/Managers/Bluefield_BMC/Oem",
                "@odata.type": "#OemManager.Oem",
                "Nvidia": {
                  "@odata.id": "/redfish/v1/Managers/Bluefield_BMC/Oem/Nvidia"
                },
                "OpenBmc": {
                  "@odata.id": "/redfish/v1/Managers/Bluefield_BMC/Oem/OpenBmc",
                  "@odata.type": "#OemManager.OpenBmc",
                  "Certificates": {
                    "@odata.id": "/redfish/v1/Managers/Bluefield_BMC/Truststore/Certificates"
                  }
                }
              },
              "PowerState": "On",
              "SerialConsole": {
                "ConnectTypesSupported": [
                  "IPMI",
                  "SSH"
                ],
                "MaxConcurrentSessions": 15,
                "ServiceEnabled": true
              },
              "ServiceEntryPointUUID": "a614e837-6b4a-4560-8c22-c6ed1b96c7c9",
              "Status": {
                "Conditions": [],
                "Health": "OK",
                "HealthRollup": "OK",
                "State": "Starting"
              },
              "UUID": "0b623306-fa7f-42d2-809d-a63a13d49c8d"
        }"##,
            )
            .unwrap())
        }

        async fn bmc_reset_to_defaults(&self) -> Result<(), RedfishError> {
            Ok(())
        }

        async fn get_system_event_log(
            &self,
        ) -> Result<Vec<libredfish::model::sel::LogEntry>, RedfishError> {
            Ok(Vec::new())
        }

        async fn get_bmc_event_log(
            &self,
            _from: Option<chrono::DateTime<chrono::Utc>>,
        ) -> Result<Vec<libredfish::model::sel::LogEntry>, RedfishError> {
            Err(RedfishError::NotSupported(
                "BMC Event Log not supported for tests".to_string(),
            ))
        }

        async fn get_tasks(&self) -> Result<Vec<String>, RedfishError> {
            Ok(Vec::new())
        }

        async fn add_secure_boot_certificate(&self, _: &str) -> Result<Task, RedfishError> {
            Ok(Task {
                odata: ODataLinks {
                    odata_context: None,
                    odata_id: "odata_id".to_string(),
                    odata_type: "odata_type".to_string(),
                    odata_etag: None,
                    links: None,
                },
                id: "".to_string(),
                messages: Vec::new(),
                name: None,
                task_state: None,
                task_status: None,
                task_monitor: None,
                percent_complete: None,
            })
        }

        async fn enable_secure_boot(&self) -> Result<(), RedfishError> {
            Ok(())
        }

        async fn change_username(
            &self,
            _old_name: &str,
            _new_name: &str,
        ) -> Result<(), RedfishError> {
            Ok(())
        }
        async fn get_accounts(
            &self,
        ) -> Result<Vec<libredfish::model::account_service::ManagerAccount>, RedfishError> {
            todo!()
        }
        async fn set_machine_password_policy(&self) -> Result<(), RedfishError> {
            Ok(())
        }
        async fn update_firmware_multipart(
            &self,
            _filename: &Path,
            _reboot: bool,
            _timeout: Duration,
            _component_type: ComponentType,
        ) -> Result<String, RedfishError> {
            // Simulate it taking a bit of time to upload
            tokio::time::sleep(Duration::from_secs(4)).await;
            Ok("0".to_string())
        }

        async fn get_job_state(&self, _job_id: &str) -> Result<JobState, RedfishError> {
            Ok(JobState::Unknown)
        }

        async fn get_collection(&self, _id: ODataId) -> Result<Collection, RedfishError> {
            Ok(Collection {
                url: String::new(),
                body: HashMap::new(),
            })
        }

        async fn get_resource(&self, _id: ODataId) -> Result<Resource, RedfishError> {
            Ok(Resource {
                url: String::new(),
                raw: Default::default(),
            })
        }

        async fn set_boot_order_dpu_first(
            &self,
            _mac_address: &str,
        ) -> Result<Option<String>, RedfishError> {
            Ok(None)
        }

        async fn clear_uefi_password(
            &self,
            _current_uefi_password: &str,
        ) -> Result<Option<String>, RedfishError> {
            Ok(None)
        }

        async fn get_base_network_adapters(
            &self,
            _system_id: &str,
        ) -> Result<Vec<String>, RedfishError> {
            Ok(vec![])
        }

        async fn get_base_network_adapter(
            &self,
            _system_id: &str,
            _id: &str,
        ) -> Result<NetworkAdapter, RedfishError> {
            todo!();
        }

        async fn chassis_reset(
            &self,
            _chassis_id: &str,
            _reset_type: SystemPowerControl,
        ) -> Result<(), RedfishError> {
            Ok(())
        }

        async fn get_update_service(&self) -> Result<UpdateService, RedfishError> {
            todo!();
        }

        async fn get_base_mac_address(&self) -> Result<Option<String>, RedfishError> {
            Ok(Some("a088c208804c".to_string()))
        }

        async fn lockdown_bmc(&self, _target: EnabledDisabled) -> Result<(), RedfishError> {
            Ok(())
        }

        async fn get_gpu_sensors(&self) -> Result<Vec<GPUSensors>, RedfishError> {
            todo!();
        }

        async fn get_drives_metrics(&self) -> Result<Vec<Drives>, RedfishError> {
            todo!();
        }

        async fn is_ipmi_over_lan_enabled(&self) -> Result<bool, RedfishError> {
            Ok(false)
        }

        async fn enable_ipmi_over_lan(&self, _target: EnabledDisabled) -> Result<(), RedfishError> {
            Ok(())
        }

        async fn enable_rshim_bmc(&self) -> Result<(), RedfishError> {
            Ok(())
        }

        async fn clear_nvram(&self) -> Result<(), RedfishError> {
            Ok(())
        }

        async fn get_nic_mode(&self) -> Result<Option<NicMode>, RedfishError> {
            Ok(None)
        }

        async fn set_nic_mode(&self, _mode: NicMode) -> Result<(), RedfishError> {
            Ok(())
        }

        async fn is_infinite_boot_enabled(&self) -> Result<Option<bool>, RedfishError> {
            Ok(None)
        }

        async fn reset_bios(&self) -> Result<(), RedfishError> {
            Ok(())
        }

        async fn set_host_rshim(&self, _enabled: EnabledDisabled) -> Result<(), RedfishError> {
            Err(RedfishError::NotSupported("set_nic_mode".to_string()))
        }

        async fn get_host_rshim(&self) -> Result<Option<EnabledDisabled>, RedfishError> {
            Ok(None)
        }

        async fn set_idrac_lockdown(&self, _enabled: EnabledDisabled) -> Result<(), RedfishError> {
            Ok(())
        }

        async fn get_boss_controller(&self) -> Result<Option<String>, RedfishError> {
            Ok(None)
        }

        async fn decommission_storage_controller(
            &self,
            _controller_id: &str,
        ) -> Result<Option<String>, RedfishError> {
            Ok(None)
        }

        async fn create_storage_volume(
            &self,
            _controller_id: &str,
            _volume_name: &str,
            _raid_type: &str,
        ) -> Result<Option<String>, RedfishError> {
            Ok(None)
        }
    }

    #[async_trait]
    impl RedfishClientPool for RedfishSim {
        async fn create_client(
            &self,
            host: &str,
            port: Option<u16>,
            _auth: RedfishAuth,
            _initialize: bool,
        ) -> Result<Box<dyn Redfish>, RedfishClientCreationError> {
            {
                self.state
                    .clone()
                    .lock()
                    .unwrap()
                    ._hosts
                    .entry(host.to_string())
                    .or_insert(RedfishSimHostState {
                        power: PowerState::On,
                    });
                if self.state.clone().lock().unwrap().fw_version.is_empty() {
                    self.state.clone().lock().unwrap().fw_version = Arc::new("23.10".to_string());
                }
            }
            Ok(Box::new(RedfishSimClient {
                state: self.state.clone(),
                _host: host.to_string(),
                _port: port,
            }))
        }

        fn credential_provider(&self) -> Arc<dyn CredentialProvider> {
            Arc::new(TestCredentialProvider::default())
        }

        async fn create_client_for_ingested_host(
            &self,
            _ip: IpAddr,
            _port: Option<u16>,
            _txn: &mut PgConnection,
        ) -> Result<Box<dyn Redfish>, RedfishClientCreationError> {
            self.create_client(
                "fake",
                Some(443),
                RedfishAuth::Key(CredentialKey::BmcCredentials {
                    credential_type: BmcCredentialType::BmcRoot {
                        bmc_mac_address: MacAddress::default(),
                    },
                }),
                true,
            )
            .await
        }

        async fn uefi_setup(
            &self,
            _client: &dyn Redfish,
            _dpu: bool,
        ) -> Result<Option<String>, RedfishClientCreationError> {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;
    use libredfish::PowerState;

    #[tokio::test]
    async fn test_power_state() {
        let sim = RedfishSim::default();
        let client = sim
            .create_client(
                "localhost",
                None,
                RedfishAuth::Key(CredentialKey::HostRedfish {
                    credential_type: CredentialType::SiteDefault,
                }),
                true,
            )
            .await
            .unwrap();

        assert_eq!(PowerState::On, client.get_power_state().await.unwrap());
        client
            .power(libredfish::SystemPowerControl::ForceOff)
            .await
            .unwrap();

        assert_eq!(PowerState::Off, client.get_power_state().await.unwrap());
        let client = sim
            .create_client(
                "localhost",
                None,
                RedfishAuth::Key(CredentialKey::HostRedfish {
                    credential_type: CredentialType::SiteDefault,
                }),
                true,
            )
            .await
            .unwrap();
        assert_eq!(PowerState::Off, client.get_power_state().await.unwrap());
    }
}
