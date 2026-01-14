use std::net::IpAddr;

/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use carbide_uuid::machine::MachineId;
use db::DatabaseError;
use model::site_explorer::ExploredManagedHost;
use sqlx::PgConnection;

/// ManagedHost wraps an ExploredManagedHost along with a machine id.
/// This helper structure is used by the create_managed_host to create a managed host
/// using the explored managed host structure that the site explorer retrieves from the
/// explored_managed_host table.
/// The create_managed_host function creates a ManagedHost with the machine ID set to None initially.
/// It sets the machine_id when attaching the first DPU to a given host.
/// It will use the machine_id from this structure when attaching all other DPUs to a host.
#[derive(Debug, Clone)]
pub struct ManagedHost<'a> {
    /// Retrieved from the explored_managed_host table
    pub explored_host: &'a ExploredManagedHost,
    /// The site explorer uses the machine_id as the host's machine ID when attaching a DPU to a host.
    /// The site explorer sets this field as part of attaching the first DPU to a host in the create_managed_host function.
    pub machine_id: Option<MachineId>,
}

impl<'a> ManagedHost<'a> {
    pub fn init(explored_host: &'a ExploredManagedHost) -> Self {
        Self {
            explored_host,
            machine_id: None,
        }
    }
}

/// Checks if an ingested machine (host or DPU) exists with the given BMC IP address.
///
/// This queries the `machine_topologies` table which stores actual ingested machines,
/// rather than the `explored_managed_hosts` staging table which gets wiped and rebuilt
/// on every site explorer update.
///
/// This prevents site explorer from triggering unintended actions (like power cycles
/// or re-ingestion) on machines that have already been ingested, even if the host's
/// BMC temporarily stops reporting DPUs in its PCIe device list.
pub async fn is_endpoint_in_managed_host(
    bmc_ip_address: IpAddr,
    txn: &mut PgConnection,
) -> Result<bool, DatabaseError> {
    let machine_id =
        db::machine_topology::find_machine_id_by_bmc_ip(txn, &bmc_ip_address.to_string()).await?;
    Ok(machine_id.is_some())
}
