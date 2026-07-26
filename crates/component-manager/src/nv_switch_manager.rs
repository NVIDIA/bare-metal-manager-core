// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fmt::Debug;
use std::net::IpAddr;

use carbide_secrets::credentials::Credentials;
use mac_address::MacAddress;
use model::component_manager::{
    ConfigureSwitchCertificateState, FirmwareState, NvSwitchComponent, PowerAction,
};

use crate::error::ComponentManagerError;
use crate::types::FirmwareUpdateOptions;

/// Selects which `NvSwitchManager` backend is used
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Backend {
    Nsm,
    #[default]
    Rms,
    Mock,
}

impl std::fmt::Display for Backend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Nsm => f.write_str("nsm"),
            Self::Rms => f.write_str("rms"),
            Self::Mock => f.write_str("mock"),
        }
    }
}

/// Backend observation of a switch OS password-rotation job.
///
/// This describes the backend job, not the credential state observed on the
/// switch. In particular, `NotFound` does not prove that the password mutation
/// was never accepted or did not complete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwitchPasswordRotationState {
    /// The backend cannot currently resolve the job. This does not establish
    /// the mutation outcome; callers must retain or fail the staged target
    /// according to their recovery policy.
    NotFound,

    /// The backend returned a job state that cannot be classified.
    Unknown,

    /// The backend accepted the job and it has not reached a terminal state.
    Pending,

    /// The backend reports that the password mutation completed successfully.
    /// Callers may still need to promote and verify the staged credential.
    Completed,

    /// The backend reports that the job terminated unsuccessfully.
    Failed,
}

/// Physical network identifiers for an NV-Switch, used to register with and
/// operate against the backend service (NSM).
#[derive(Debug, Clone)]
pub struct SwitchEndpoint {
    pub bmc_ip: IpAddr,
    pub bmc_mac: MacAddress,
    pub nvos_ip: IpAddr,
    pub nvos_mac: MacAddress,
    pub bmc_credentials: Credentials,
    pub nvos_credentials: Credentials,
    /// Fully qualified NVOS hostname from `machine_interfaces` (TLS SNI).
    pub nvos_host_name: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SwitchComponentResult {
    pub bmc_mac: MacAddress,
    pub success: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SwitchFirmwareUpdateStatus {
    pub bmc_mac: MacAddress,
    pub state: FirmwareState,
    pub target_version: String,
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SwitchSlotAndTrayResult {
    pub bmc_mac: MacAddress,
    pub slot_number: Option<i32>,
    pub tray_index: Option<i32>,
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SwitchPowerStateResult {
    pub bmc_mac: MacAddress,
    pub power_state: Option<String>,
    pub error: Option<String>,
}

impl crate::component_common::ComponentPowerStateResult for SwitchPowerStateResult {
    fn power_state(&self) -> Option<&str> {
        self.power_state.as_deref()
    }

    fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigureSwitchCertificateJobStatus {
    pub state: ConfigureSwitchCertificateState,
    pub error: Option<String>,
}

/// Backend trait for NV-Switch management operations.
///
/// Implementations receive physical endpoint information (BMC + NVOS IPs/MACs)
/// and handle registration with the backend service internally. The
/// service-generated UUID is used for the actual operation and never exposed
/// to the caller; results are keyed by `bmc_mac`.
///
/// Password rotation is split into capability discovery, submission, and
/// observation. This keeps backend-specific job handling here while leaving
/// convergence persistence to the orchestration layer.
#[async_trait::async_trait]
pub trait NvSwitchManager: Send + Sync + Debug + 'static {
    fn name(&self) -> &str;

    /// Reports whether this backend supports OS password rotation.
    ///
    /// `false` means callers must not submit rotation work. `true` means an
    /// unchanged request from the current password to the target password is
    /// safe to repeat: a backend must either apply the target or recognize that
    /// the target is already active. The default keeps existing backends
    /// disabled until they implement this contract.
    fn supports_password_rotation(&self) -> bool {
        false
    }

    fn supports_firmware_object_json(&self) -> bool {
        false
    }

    async fn power_control(
        &self,
        endpoints: &[SwitchEndpoint],
        action: PowerAction,
    ) -> Result<Vec<SwitchComponentResult>, ComponentManagerError>;

    async fn queue_firmware_updates(
        &self,
        endpoints: &[SwitchEndpoint],
        bundle_version: &str,
        components: &[NvSwitchComponent],
        options: &FirmwareUpdateOptions,
    ) -> Result<Vec<SwitchComponentResult>, ComponentManagerError>;

    async fn get_firmware_status(
        &self,
        endpoints: &[SwitchEndpoint],
    ) -> Result<Vec<SwitchFirmwareUpdateStatus>, ComponentManagerError>;

    async fn list_firmware_bundles(&self) -> Result<Vec<String>, ComponentManagerError>;

    async fn get_slot_and_tray(
        &self,
        endpoints: &[SwitchEndpoint],
    ) -> Result<Vec<SwitchSlotAndTrayResult>, ComponentManagerError>;

    async fn get_power_state(
        &self,
        endpoints: &[SwitchEndpoint],
    ) -> Result<Vec<SwitchPowerStateResult>, ComponentManagerError>;
    async fn configure_switch_certificate(
        &self,
        endpoint: &SwitchEndpoint,
        domain_name: Option<&str>,
        services: Option<&[i32]>,
    ) -> Result<String, ComponentManagerError>;

    async fn get_configure_switch_certificate_job_status(
        &self,
        job_id: &str,
    ) -> Result<ConfigureSwitchCertificateJobStatus, ComponentManagerError>;

    /// Converges the endpoint from its current NVOS credential to
    /// `next_password`.
    ///
    /// Implementations must make repeated identical requests safe after a
    /// controller or backend restart, including overlapping requests through
    /// different backend replicas. If the endpoint authenticates with the current
    /// password, apply the target. If it authenticates with the target, recognize
    /// convergence without applying another password change.
    ///
    /// The returned job ID can be passed to
    /// [`Self::get_password_rotation_job_status`] for an early completion
    /// observation. It is opaque and transient: callers must not derive
    /// credential state from it. Implementations must not log `next_password`
    /// or otherwise expose it outside the backend request.
    ///
    /// If dispatch may have reached the backend but no job ID is available, the
    /// implementation returns [`ComponentManagerError::OperationOutcomeUnknown`].
    /// Callers retain the exact staged current-to-target transition and retry it
    /// later. [`ComponentManagerError::RejectedBeforeDispatch`] is reserved for
    /// rejection that proves no mutation or job was accepted. The default
    /// implementation returns
    /// [`ComponentManagerError::Unsupported`].
    async fn ensure_password_rotation(
        &self,
        _endpoint: &SwitchEndpoint,
        _next_password: &str,
    ) -> Result<String, ComponentManagerError> {
        Err(ComponentManagerError::Unsupported(format!(
            "switch password rotation is not supported by the {} backend",
            self.name()
        )))
    }

    /// Returns the latest backend observation for a submitted rotation job.
    ///
    /// A job that cannot be resolved is returned as
    /// [`SwitchPasswordRotationState::NotFound`], not as an error. An error means
    /// no job observation was obtained and does not imply a terminal job state.
    /// The default implementation returns [`ComponentManagerError::Unsupported`].
    async fn get_password_rotation_job_status(
        &self,
        _job_id: &str,
    ) -> Result<SwitchPasswordRotationState, ComponentManagerError> {
        Err(ComponentManagerError::Unsupported(format!(
            "switch password rotation is not supported by the {} backend",
            self.name()
        )))
    }
}
