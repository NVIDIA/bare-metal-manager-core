/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::collections::HashMap;
use std::sync::Arc;

use carbide_uuid::machine::MachineId;
use db::{ObjectColumnFilter, Transaction};
use model::bmc_info::BmcInfo;
use model::expected_machine::ExpectedMachine;
use model::hardware_info::HardwareInfo;
use model::machine::machine_id::host_id_from_dpu_hardware_info;
use model::machine::machine_search_config::MachineSearchConfig;
use model::machine::{
    DpuDiscoveringState, DpuDiscoveringStates, Machine, MachineInterfaceSnapshot, ManagedHostState,
};
use model::machine_interface_address::MachineInterfaceAssociation;
use model::metadata::Metadata;
use model::network_segment::NetworkSegmentType;
use model::predicted_machine_interface::NewPredictedMachineInterface;
use model::resource_pool::common::CommonPools;
use model::site_explorer::{EndpointExplorationReport, ExploredDpu, ExploredManagedHost};
use sqlx::{PgConnection, PgPool};

use crate::site_explorer::SiteExplorerConfig;
use crate::site_explorer::explored_endpoint_index::ExploredEndpointIndex;
use crate::site_explorer::managed_host::ManagedHost;
use crate::site_explorer::metrics::SiteExplorationMetrics;
use crate::state_controller::machine::io::CURRENT_STATE_MODEL_VERSION;
use crate::{CarbideError, CarbideResult};

pub struct MachineCreator {
    database_connection: PgPool,
    config: SiteExplorerConfig,
    common_pools: Arc<CommonPools>,
}

impl MachineCreator {
    pub fn new(
        database_connection: PgPool,
        config: SiteExplorerConfig,
        common_pools: Arc<CommonPools>,
    ) -> Self {
        Self {
            database_connection,
            config,
            common_pools,
        }
    }

    /// Creates a new ManagedHost (Host `Machine` and DPU `Machine` pair)
    /// for each ManagedHost that was identified and that doesn't have a corresponding `Machine` yet
    pub(crate) async fn create_machines(
        &self,
        metrics: &mut SiteExplorationMetrics,
        explored_managed_hosts: &mut [(ExploredManagedHost, EndpointExplorationReport)],
        expected_explored_endpoint_index: &ExploredEndpointIndex,
    ) -> CarbideResult<()> {
        // TODO: Improve the efficiency of this method. Right now we perform 3 database transactions
        // for every identified ManagedHost even if we don't create any objects.
        // We can perform a single query upfront to identify which ManagedHosts don't yet have Machines
        for (host, report) in explored_managed_hosts {
            let expected_machine =
                expected_explored_endpoint_index.matched_expected_machine(&host.host_bmc_ip);

            match self
                .create_managed_host(host, report, expected_machine, &self.database_connection)
                .await
            {
                Ok(true) => {
                    metrics.created_machines += 1;
                    if metrics.created_machines as u64 == self.config.machines_created_per_run {
                        break;
                    }
                }
                Ok(false) => {}
                Err(error) => tracing::error!(%error, "Failed to create managed host {:#?}", host),
            }
        }

        Ok(())
    }

    /// Creates a `Machine` objects for an identified `ManagedHost` with initial states
    ///
    /// Returns `true` if new `Machine` objects have been created or `false` otherwise
    pub async fn create_managed_host(
        &self,
        explored_host: &ExploredManagedHost,
        report: &mut EndpointExplorationReport,
        expected_machine: Option<&ExpectedMachine>,
        pool: &PgPool,
    ) -> CarbideResult<bool> {
        let mut managed_host = ManagedHost::init(explored_host);

        let mut txn = Transaction::begin(pool).await?;

        let (metadata, sku_id, dpf_enabled) = match expected_machine {
            Some(m) => (
                Some(&m.data.metadata),
                m.data.sku_id.as_ref(),
                m.data.dpf_enabled,
            ),
            None => (None, None, true),
        };

        // Zero-dpu case: If the explored host had no DPUs, we can create the machine now
        if managed_host.explored_host.dpus.is_empty() {
            if !self.config.allow_zero_dpu_hosts {
                let error = CarbideError::NoDpusInMachine(managed_host.explored_host.host_bmc_ip);
                tracing::error!(%error, "Cannot create managed host for explored endpoint with no DPUs: Zero-dpu hosts are disallowed by config");
                return Err(error);
            }
            if let Some(machine_id) = self
                .create_zero_dpu_machine(
                    &mut txn,
                    &managed_host,
                    report,
                    metadata.unwrap_or(&Metadata::default()),
                )
                .await?
            {
                managed_host.machine_id = Some(machine_id);
            } else {
                // Site explorer has already created a machine for this endpoint previously, skip.
                return Ok(false);
            }
            tracing::info!("Created managed_host with zero DPUs");
        }

        let mut dpu_ids = vec![];
        for dpu_report in managed_host.explored_host.dpus.iter() {
            // machine_id_if_valid_report makes sure that all optional fields on dpu_report are
            // actually set (like the machine-id etc) and returns the machine_id if everything
            // is valid.
            let dpu_machine_id = *dpu_report.machine_id_if_valid_report()?;
            dpu_ids.push(dpu_machine_id);

            if !self.create_dpu(&mut txn, dpu_report, dpf_enabled).await? {
                // Site explorer has already created a machine for this DPU previously.
                //
                // If the DPU's machine is not attached to its machine interface, do so here.
                // TODO (sp): is this defensive check really neccessary?
                if self.configure_dpu_interface(&mut txn, dpu_report).await? {
                    txn.commit().await?;
                }
                return Ok(false);
            }

            let host_machine_id = self
                .attach_dpu_to_host(
                    &mut txn,
                    &managed_host,
                    dpu_report,
                    metadata.unwrap_or(&Metadata::default()),
                    sku_id,
                    dpf_enabled,
                )
                .await?;
            managed_host.machine_id = Some(host_machine_id)
        }

        // Now since all DPUs are created, update host and DPUs state correctly.
        let host_machine_id = managed_host
            .machine_id
            .ok_or(CarbideError::internal(format!(
                "Failed to get machine ID for host: {managed_host:#?}"
            )))?;

        db::machine::update_state(
            &mut txn,
            &host_machine_id,
            &ManagedHostState::DpuDiscoveringState {
                dpu_states: DpuDiscoveringStates {
                    states: dpu_ids
                        .into_iter()
                        .map(|x| (x, DpuDiscoveringState::Initializing))
                        .collect::<HashMap<MachineId, DpuDiscoveringState>>(),
                },
            },
        )
        .await?;

        txn.commit().await?;

        Ok(true)
    }

    // Returns MachineId if machene was created.
    async fn create_zero_dpu_machine(
        &self,
        txn: &mut PgConnection,
        managed_host: &ManagedHost<'_>,
        report: &mut EndpointExplorationReport,
        metadata: &Metadata,
    ) -> CarbideResult<Option<MachineId>> {
        // If there's already a machine with the same MAC address as this endpoint, return false. We
        // can't rely on matching the machine_id, as it may have migrated to a stable MachineID
        // already.
        let mac_addresses = report.all_mac_addresses();
        for mac_address in &mac_addresses {
            if db::machine::find_by_mac_address(txn, mac_address)
                .await?
                .is_some()
            {
                return Ok(None);
            }

            // If we already minted this machine and it hasn't DHCP'd yet, there will be an
            // predicted_machine_interface with this MAC address. If so, also skip.
            if !db::predicted_machine_interface::find_by(
                txn,
                ObjectColumnFilter::One(
                    db::predicted_machine_interface::MacAddressColumn,
                    mac_address,
                ),
            )
            .await?
            .is_empty()
            {
                return Ok(None);
            }
        }

        let machine_id = match managed_host.machine_id.as_ref() {
            Some(machine_id) => machine_id,
            None => {
                // Mint a predicted-host machine_id from the exploration report
                report.generate_machine_id(true)?.unwrap()
            }
        };

        tracing::info!(%machine_id, "Minted predicted host ID for zero-DPU machine");

        let existing_machine = db::machine::find_one(
            txn,
            machine_id,
            MachineSearchConfig {
                include_predicted_host: true,
                ..Default::default()
            },
        )
        .await?;

        if let Some(existing_machine) = existing_machine {
            // There's already a machine with this ID, but we already looked above for machines with
            // the same MAC address as this one, so something's weird here. Log this host's mac
            // addresses and the ones from the colliding hosts to help in diagnosis.
            let existing_macs = existing_machine
                .hardware_info
                .as_ref()
                .map(|hw| hw.all_mac_addresses())
                .unwrap_or_default();
            tracing::warn!(
                %machine_id,
                ?existing_macs,
                predicted_host_macs=?mac_addresses,
                "Predicted host already exists, with different mac addresses from this one. Potentially multiple machines with same serial number?"
            );
            return Ok(None);
        }

        self.create_machine_from_explored_managed_host(
            txn,
            managed_host,
            machine_id,
            metadata,
            None,
            true,
        )
        .await?;

        // Create and attach a non-DPU machine_interface to the host for every MAC address we see in
        // the exploration report
        for mac_address in mac_addresses {
            if let Some(machine_interface) =
                db::machine_interface::find_by_mac_address(txn, mac_address)
                    .await?
                    .into_iter()
                    .next()
            {
                // There's already a machine_interface with this MAC...
                if let Some(existing_machine_id) = machine_interface.machine_id {
                    // ...If it has a MachineId, something's gone wrong. We already checked db::machine::find_by_mac()
                    // above for all mac addresses, and returned Ok(false) if any were found. Finding an interface
                    // with this MAC with a non-nil machine_id is a contradiction.
                    tracing::error!(
                        %mac_address,
                        %machine_id,
                        %existing_machine_id,
                        "BUG! Found existing machine_interface with this MAC address, we should not have gotten here!"
                    );
                    return Err(CarbideError::AlreadyFoundError {
                        kind: "MachineInterface",
                        id: mac_address.to_string(),
                    });
                } else {
                    // ...If it has no MachineId, the host must have DHCP'd before site-explorer ran. Set it to the new machine ID.
                    tracing::info!(%mac_address, %machine_id, "Migrating unowned machine_interface to new managed host");
                    db::machine_interface::associate_interface_with_machine(
                        &machine_interface.id,
                        MachineInterfaceAssociation::Machine(*machine_id),
                        txn,
                    )
                    .await?;
                }
            } else {
                db::predicted_machine_interface::create(
                    NewPredictedMachineInterface {
                        machine_id,
                        mac_address,
                        expected_network_segment_type: NetworkSegmentType::HostInband,
                    },
                    txn,
                )
                .await?;
            }
        }

        Ok(Some(*machine_id))
    }

    // create_dpu does everything needed to create a DPU as part of a newly discovered managed host.
    // If the DPU does not exist in the machines table, the function creates a new DPU machine and configures it appropriately. create_dpu returns true.
    // If the DPU already exists in the machines table, this is a no-op. create_dpu returns false.
    async fn create_dpu(
        &self,
        txn: &mut PgConnection,
        explored_dpu: &ExploredDpu,
        dpf_enabled: bool,
    ) -> CarbideResult<bool> {
        if let Some(dpu_machine) = self
            .create_dpu_machine(txn, explored_dpu, dpf_enabled)
            .await?
        {
            self.configure_dpu_interface(txn, explored_dpu).await?;
            self.update_dpu_network_config(txn, &dpu_machine).await?;
            let dpu_machine_id: &MachineId = explored_dpu.report.machine_id.as_ref().unwrap();
            let dpu_bmc_info = explored_dpu.bmc_info();
            let dpu_hw_info = explored_dpu.hardware_info()?;
            self.update_machine_topology(txn, dpu_machine_id, dpu_bmc_info, dpu_hw_info)
                .await?;
            return Ok(true);
        }
        Ok(false)
    }

    // 1) Create a machine for this host using the passed machine_id
    // 2) Update the "machine_topologies" table with the bmc info for this host
    async fn create_machine_from_explored_managed_host(
        &self,
        txn: &mut PgConnection,
        managed_host: &ManagedHost<'_>,
        predicted_machine_id: &MachineId,
        metadata: &Metadata,
        sku_id: Option<&String>,
        dpf_enabled: bool,
    ) -> CarbideResult<()> {
        _ = db::machine::create(
            txn,
            Some(&self.common_pools),
            predicted_machine_id,
            ManagedHostState::Created,
            metadata,
            sku_id,
            dpf_enabled,
            CURRENT_STATE_MODEL_VERSION,
        )
        .await?;
        let hardware_info = HardwareInfo::default();
        self.update_machine_topology(
            txn,
            predicted_machine_id,
            managed_host.explored_host.bmc_info(),
            hardware_info,
        )
        .await
    }

    // configure_dpu_interface checks the machine_interfaces table to see if the DPU's machine interface has its machine id set.
    // If the machine ID is already configured appropriately for the DPU's machine interface, configure_dpu_interface will return false
    // If the DPU's machine interface was missing the machine ID in the table, configure_dpu_interface will set the machine ID and return true.
    async fn configure_dpu_interface(
        &self,
        txn: &mut PgConnection,
        explored_dpu: &ExploredDpu,
    ) -> CarbideResult<bool> {
        let dpu_machine_id: &MachineId = explored_dpu.report.machine_id.as_ref().unwrap();
        let oob_net0_mac = explored_dpu.report.systems.iter().find_map(|x| {
            x.ethernet_interfaces.iter().find_map(|x| {
                if x.id
                    .as_ref()
                    .is_some_and(|id| id.to_lowercase().contains("oob"))
                {
                    x.mac_address
                } else {
                    None
                }
            })
        });

        // If machine_interface exists for the DPU and machine_id is not updated, do it now.
        if let Some(oob_net0_mac) = oob_net0_mac {
            let mi = db::machine_interface::find_by_mac_address(txn, oob_net0_mac).await?;

            if let Some(interface) = mi.first()
                && interface.machine_id.is_none()
            {
                tracing::info!(
                    "Updating machine interface {} with machine id {dpu_machine_id}.",
                    interface.id
                );
                db::machine_interface::associate_interface_with_machine(
                    &interface.id,
                    MachineInterfaceAssociation::Machine(*dpu_machine_id),
                    txn,
                )
                .await?;
                db::machine_interface::associate_interface_with_dpu_machine(
                    &interface.id,
                    dpu_machine_id,
                    txn,
                )
                .await?;
                return Ok(true);
            }
        }

        Ok(false)
    }

    // create_dpu_machine creates a machine for the DPU as specified by dpu_machine_id. Returns an Optional Machine indicating whether the function created a new machine (returns None if a machine already existed for this DPU).
    // if an entry exists in the machines table with a machine ID which matches dpu_machine_id, a machine has already been created for this DPU. Returns None.
    // if an entry doesnt exist in the machine table, the site explorer will add an entry in the machines table for the DPU and update its network config appropriately (allocating a loop ip address etc). Return the newly created machine.
    async fn create_dpu_machine(
        &self,
        txn: &mut PgConnection,
        explored_dpu: &ExploredDpu,
        dpf_enabled: bool,
    ) -> CarbideResult<Option<Machine>> {
        let dpu_machine_id = explored_dpu.report.machine_id.as_ref().unwrap();
        match db::machine::find_one(txn, dpu_machine_id, MachineSearchConfig::default()).await? {
            // Do nothing if machine exists. It'll be reprovisioned via redfish
            Some(_existing_machine) => Ok(None),
            None => match db::machine::create(
                txn,
                Some(&self.common_pools),
                dpu_machine_id,
                ManagedHostState::Created,
                &Metadata::default(),
                None,
                // Although this field is not used in case of DPU, but let's keep them
                // in sync.
                dpf_enabled,
                CURRENT_STATE_MODEL_VERSION,
            )
            .await
            {
                Ok(machine) => {
                    tracing::info!("Created DPU machine with id: {}", dpu_machine_id);
                    Ok(Some(machine))
                }
                Err(e) => {
                    tracing::error!(error = %e, "Can't create DPU machine");
                    Err(e.into())
                }
            },
        }
    }

    async fn attach_dpu_to_host(
        &self,
        txn: &mut PgConnection,
        explored_host: &ManagedHost<'_>,
        explored_dpu: &ExploredDpu,
        metadata: &Metadata,
        sku_id: Option<&String>,
        dpf_enabled: bool,
    ) -> CarbideResult<MachineId> {
        let dpu_hw_info = explored_dpu.hardware_info()?;
        // Create Host proactively.
        // In case host interface is created, this method will return existing one, instead
        // creating new everytime.
        let host_machine_interface =
            db::machine_interface::create_host_machine_dpu_interface_proactively(
                txn,
                Some(&dpu_hw_info),
                explored_dpu.report.machine_id.as_ref().unwrap(),
            )
            .await?;

        if host_machine_interface.machine_id.is_some() {
            return Err(CarbideError::internal(format!(
                "The host's machine interface for DPU {} already has the machine ID set--something is wrong: {:#?}",
                explored_dpu.report.machine_id.as_ref().unwrap(),
                host_machine_interface
            )));
        }

        let host_machine_id = self
            .configure_host_machine(
                txn,
                explored_host,
                &host_machine_interface,
                explored_dpu,
                metadata,
                sku_id,
                dpf_enabled,
            )
            .await?;

        db::machine_interface::associate_interface_with_machine(
            &host_machine_interface.id,
            MachineInterfaceAssociation::Machine(host_machine_id),
            txn,
        )
        .await?;

        Ok(host_machine_id)
    }

    async fn update_machine_topology(
        &self,
        txn: &mut PgConnection,
        machine_id: &MachineId,
        mut bmc_info: BmcInfo,
        hardware_info: HardwareInfo,
    ) -> CarbideResult<()> {
        let _topology =
            db::machine_topology::create_or_update(txn, machine_id, &hardware_info).await?;

        // Forge scout will update this topology with a full information.
        db::machine_topology::set_topology_update_needed(txn, machine_id, true).await?;

        // call enrich_mac_address to fill the MAC address info from the machine_interfaces table
        db::bmc_metadata::enrich_mac_address(
            &mut bmc_info,
            "SiteExplorer::update_machine_topology".to_string(),
            txn,
            machine_id,
            true,
        )
        .await?;

        db::bmc_metadata::update_bmc_network_into_topologies(txn, machine_id, &bmc_info).await?;

        Ok(())
    }

    async fn update_dpu_network_config(
        &self,
        txn: &mut PgConnection,
        dpu_machine: &Machine,
    ) -> CarbideResult<()> {
        let (mut network_config, version) = dpu_machine.network_config.clone().take();
        if network_config.loopback_ip.is_none() {
            let loopback_ip = db::machine::allocate_loopback_ip(
                &self.common_pools,
                txn,
                &dpu_machine.id.to_string(),
            )
            .await?;
            network_config.loopback_ip = Some(loopback_ip);
        }

        if self.config.allocate_secondary_vtep_ip
            && network_config.secondary_overlay_vtep_ip.is_none()
        {
            let secondary_vtep_ip = db::machine::allocate_secondary_vtep_ip(
                &self.common_pools,
                txn,
                &dpu_machine.id.to_string(),
            )
            .await?;
            network_config.secondary_overlay_vtep_ip = Some(secondary_vtep_ip);
        }

        network_config.use_admin_network = Some(true);
        db::machine::try_update_network_config(txn, &dpu_machine.id, version, &network_config)
            .await?;

        Ok(())
    }

    // configure_host_machine configures the host's machine with the specific interface. It returns the host's machine ID.
    //
    // Normally, a host will have a single machine interface because the majority of hosts (for now) have a single DPU.
    // If a host has multiple DPUs, the host machine will have a machine interface for each DPU.
    // However, all of the host machine interfaces must be attached to the same host machine (and host machine-id).
    // Until this point, all of these interfaces will be marked as the "primary" interface by default.
    //
    // configure_host_machine handles two cases:
    // 1) host_machine_interface is the primary interface for this host: generate the machine ID for this host and use it to actually create the machine for the host.
    // 2) host_machine_interface is *not* the primary interface for this host: set "primary_interface" to false for this machine interface. Return the host ID generated from (1)
    //
    // The first DPU that we attach to the host is designated as the primary DPU; the associate host machine interface is designated is the primary interface.
    // Therefore, the primary interface is guaranteed to be configured prior to any secondary interface.
    #[allow(clippy::too_many_arguments)]
    async fn configure_host_machine(
        &self,
        txn: &mut PgConnection,
        explored_host: &ManagedHost<'_>,
        host_machine_interface: &MachineInterfaceSnapshot,
        explored_dpu: &ExploredDpu,
        metadata: &Metadata,
        sku_id: Option<&String>,
        dpf_enabled: bool,
    ) -> CarbideResult<MachineId> {
        match &explored_host.machine_id {
            Some(host_machine_id) => {
                // This is not the primary interface for this host
                // The primary interface *must* have already been created for this host (otherwise something very bad has happened)
                db::machine_interface::set_primary_interface(
                    &host_machine_interface.id,
                    false,
                    txn,
                )
                .await?;
                Ok(*host_machine_id)
            }
            None => {
                // This is the primary interface for the host.
                // 1. Generate the ID for the host from *this* DPU's hw info
                // 2. Add an entry for this host in the machines table (with a machine-id from (1)).
                let host_machine_id = self
                    .create_host_from_dpu_hw_info(
                        txn,
                        explored_host.explored_host,
                        explored_dpu,
                        metadata,
                        sku_id,
                        dpf_enabled,
                    )
                    .await?;

                tracing::info!(
                    ?host_machine_interface.id,
                    machine_id = %host_machine_id,
                    "Created host machine proactively in site-explorer",
                );

                db::machine_interface::set_primary_interface(&host_machine_interface.id, true, txn)
                    .await?;
                Ok(host_machine_id)
            }
        }
    }

    // 1) Generate the host's machine ID from the DPU's hardware info
    // 2) Create a machine for this host using the machine ID from (1)
    // 3) Update the "machine_topologies" table with the bmc info for this host
    async fn create_host_from_dpu_hw_info(
        &self,
        txn: &mut PgConnection,
        explored_host: &ExploredManagedHost,
        explored_dpu: &ExploredDpu,
        metadata: &Metadata,
        sku_id: Option<&String>,
        dpf_enabled: bool,
    ) -> CarbideResult<MachineId> {
        let dpu_hw_info = explored_dpu.hardware_info()?;
        let predicted_machine_id = host_id_from_dpu_hardware_info(&dpu_hw_info)
            .map_err(|e| CarbideError::InvalidArgument(format!("hardware info missing: {e}")))?;

        let _host_machine = db::machine::create(
            txn,
            Some(&self.common_pools),
            &predicted_machine_id,
            ManagedHostState::Created,
            metadata,
            sku_id,
            dpf_enabled,
            CURRENT_STATE_MODEL_VERSION,
        )
        .await?;

        let host_bmc_info = explored_host.bmc_info();
        let host_hardware_info = HardwareInfo::default();
        self.update_machine_topology(
            txn,
            &predicted_machine_id,
            host_bmc_info,
            host_hardware_info,
        )
        .await?;

        Ok(predicted_machine_id)
    }
}
