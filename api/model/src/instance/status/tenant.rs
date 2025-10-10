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

use ::rpc::errors::RpcDataConversionError;
use serde::{Deserialize, Serialize};

/// The most recent tenant related status
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstanceTenantStatus {
    /// The current state of the instance from the point of view of the assigned tenant
    pub state: TenantState,
    /// An optional message which can contain details about the state
    pub state_details: String,
}

impl TryFrom<InstanceTenantStatus> for rpc::InstanceTenantStatus {
    type Error = RpcDataConversionError;

    fn try_from(state: InstanceTenantStatus) -> Result<Self, Self::Error> {
        Ok(rpc::InstanceTenantStatus {
            state: rpc::TenantState::try_from(state.state)? as i32,
            state_details: state.state_details,
        })
    }
}

/// Enumerates possible instance states from the view of a tenant
/// This is only a subset of total states that the instance might be in, and
/// excludes states that are used while the instance is not being allocated to
/// a tenant.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TenantState {
    /// The instance is currently getting provisioned for a tenant
    Provisioning,
    /// DPU is being reprovisioned.
    DpuReprovisioning,
    /// Host is being reprovisioned.
    HostReprovisioning,
    /// Firmware or other updates are being peformed, of which
    /// the tenant should not have to be concerned with the
    /// specific details.
    Updating,
    /// The instance is ready and can be used by the tenant
    Ready,
    /// The instance has been ready, but the newest configuration that the tenant
    /// desired has not been applied yet
    Configuring,
    /// The instance is shutting down. Shutdown has not completed yet
    Terminating,
    /// The instance has fully shut down, and is no longer available for the user
    Terminated,
    /// The instance is in a terminal failed state. This state is equivalent to
    /// DEACTIVATED - no user software is running anymore during the state. However
    /// an instance might enter a FAILED state before even fully activating, in case
    /// activation failed.
    Failed,
    /// Not sure what happened. Check log for more info
    Invalid,
}

impl TryFrom<TenantState> for rpc::TenantState {
    type Error = RpcDataConversionError;

    fn try_from(state: TenantState) -> Result<Self, Self::Error> {
        Ok(match state {
            TenantState::Provisioning => rpc::TenantState::Provisioning,
            TenantState::DpuReprovisioning => rpc::TenantState::DpuReprovisioning,
            TenantState::Ready => rpc::TenantState::Ready,
            TenantState::Configuring => rpc::TenantState::Configuring,
            TenantState::Terminating => rpc::TenantState::Terminating,
            TenantState::Terminated => rpc::TenantState::Terminated,
            TenantState::Failed => rpc::TenantState::Failed,
            TenantState::HostReprovisioning => rpc::TenantState::HostReprovisioning,
            TenantState::Updating => rpc::TenantState::Updating,
            TenantState::Invalid => rpc::TenantState::Invalid,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_tenant_status() {
        let status = InstanceTenantStatus {
            state: TenantState::Configuring,
            state_details: "Details".to_string(),
        };
        let serialized = serde_json::to_string(&status).unwrap();
        assert_eq!(
            serialized,
            "{\"state\":\"configuring\",\"state_details\":\"Details\"}"
        );
        assert_eq!(
            serde_json::from_str::<InstanceTenantStatus>(&serialized).unwrap(),
            status
        );
    }
}
