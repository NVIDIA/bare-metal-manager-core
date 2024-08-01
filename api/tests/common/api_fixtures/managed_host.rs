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

use carbide::{
    db::{self, machine::Machine, machine_interface::MachineInterfaceId},
    model::{
        hardware_info::TpmEkCertificate,
        machine::machine_id::{try_parse_machine_id, MachineId},
    },
};
use mac_address::MacAddress;

use super::{dpu::create_dpu_machine, host::create_host_machine, TestEnv};

/// Describes the a Managed Host
#[derive(Debug, Clone)]
pub struct ManagedHostConfig {
    pub dpu_oob_mac_address: MacAddress,
    pub dpu_bmc_mac_address: MacAddress,
    pub host_mac_address: MacAddress,
    pub host_bmc_mac_address: MacAddress,
    pub host_tpm_ek_cert: TpmEkCertificate,
}

#[derive(Debug)]
pub struct ManagedHostSim {
    pub config: ManagedHostConfig,
}

/// Create a managed_host set of machines with `dpu_count` DPUs. This currently uses a hacky
/// approach by creating `dpu_count` managed_hosts and then moving the DPUs of all of the managed
/// hosts to the first host.
///
/// This will be cleaned up to be made less hacky as we implement more of the logic for ingesting
/// "real" multi-dpu hosts.
pub async fn create_managed_host_multi_dpu(env: &TestEnv, dpu_count: usize) -> MachineId {
    assert!(dpu_count >= 1, "need to specify at least 1 dpu");
    let mut txn = env.pool.begin().await.unwrap();

    let host_sim = env.start_managed_host_sim();
    let dpu_machine_id =
        try_parse_machine_id(&create_dpu_machine(env, &host_sim.config).await).unwrap();
    let host_machine_id =
        try_parse_machine_id(&create_host_machine(env, &host_sim.config, &dpu_machine_id).await)
            .unwrap();

    for _ in 1..dpu_count {
        let extra_host_sim = env.start_managed_host_sim();
        let extra_dpu_machine_id =
            try_parse_machine_id(&create_dpu_machine(env, &extra_host_sim.config).await).unwrap();
        let extra_host_machine_id = try_parse_machine_id(
            &create_host_machine(env, &extra_host_sim.config, &extra_dpu_machine_id).await,
        )
        .unwrap();

        tracing::info!(
            "Created extra mh: host: {extra_host_machine_id} dpu: {extra_dpu_machine_id}"
        );

        let interface =
            db::machine_interface::find_by_machine_ids(&mut txn, &[extra_host_machine_id.clone()])
                .await
                .unwrap()
                .get(&extra_host_machine_id)
                .unwrap()
                .first()
                .unwrap()
                .clone();

        associate_interface_with_machine_as_non_primary(&interface.id, &mut txn, &host_machine_id)
            .await;

        tracing::info!("Deleting extra host: {extra_host_machine_id}");
        if let Err(e) = Machine::force_cleanup(&mut txn, &extra_host_machine_id).await {
            tracing::warn!("Failed to clean up extra host: {e}");
        }
    }

    // Make sure any calls to the API will see the changes we just wrote.
    txn.commit().await.unwrap();
    host_machine_id
}

pub async fn associate_interface_with_machine_as_non_primary(
    interface_id: &MachineInterfaceId,
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    machine_id: &MachineId,
) {
    db::machine_interface::set_primary_interface(interface_id, false, txn)
        .await
        .unwrap();
    db::machine_interface::associate_interface_with_machine(interface_id, machine_id, txn)
        .await
        .unwrap();
}
