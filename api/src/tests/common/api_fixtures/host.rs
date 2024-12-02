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

//! Contains host related fixtures

use super::dpu::create_dpu_machine;
use super::managed_host::ManagedHostSim;
use super::tpm_attestation::{AK_NAME_SERIALIZED, AK_PUB_SERIALIZED, EK_PUB_SERIALIZED};
use super::{get_machine_validation_runs, FIXTURE_DHCP_RELAY_ADDRESS};
use crate::db::machine::Machine;
use crate::db::network_prefix::NetworkPrefix;
use crate::db::{network_prefix, ObjectColumnFilter};
use crate::model::hardware_info::TpmEkCertificate;
use crate::model::machine::{FailureCause, FailureDetails, FailureSource};
use crate::model::machine::{MachineState::UefiSetup, UefiSetupInfo, UefiSetupState};
use crate::tests::common::api_fixtures::{
    discovery_completed, forge_agent_control, managed_host::ManagedHostConfig, update_bmc_metadata,
    TestEnv,
};
use crate::tests::common::api_fixtures::{
    inject_machine_measurements, machine_validation_completed, persist_machine_validation_result,
    update_machine_validation_run,
};
use crate::{
    db,
    model::{
        hardware_info::HardwareInfo,
        machine::{machine_id::try_parse_machine_id, ManagedHostState},
    },
};
use forge_uuid::machine::MachineId;
use health_report::HealthReport;
use rpc::forge::HardwareHealthReport;
use rpc::machine_discovery::AttestKeyInfo;
use rpc::{
    forge::{forge_agent_control_response::Action, forge_server::Forge, DhcpDiscovery},
    DiscoveryData, DiscoveryInfo, MachineDiscoveryInfo,
};
use strum::IntoEnumIterator;
use tonic::Request;

pub const FIXTURE_HOST_BMC_VERSION: &str = "4.3";
pub const FIXTURE_HOST_BMC_FIRMWARE_VERSION: &str = "5.4";

pub const FIXTURE_HOST_BMC_ADMIN_USER_NAME: &str = "forge_admin_host";

/// Uses the `discover_dhcp` API to discover a Host BMC with a certain MAC address
///
/// Returns the created `machine_interface_id`
pub async fn host_bmc_discover_dhcp(env: &TestEnv, mac_address: &str) -> rpc::Uuid {
    let response = env
        .api
        .discover_dhcp(Request::new(DhcpDiscovery {
            mac_address: mac_address.to_string(),
            relay_address: FIXTURE_DHCP_RELAY_ADDRESS.to_string(),
            vendor_string: None,
            link_address: None,
            circuit_id: None,
            remote_id: None,
        }))
        .await
        .unwrap()
        .into_inner();
    response
        .machine_interface_id
        .expect("machine_interface_id must be set")
}

/// Uses the `discover_dhcp` API to discover a Host with a certain MAC address
///
/// Returns the created `machine_interface_id`
pub async fn host_discover_dhcp(
    env: &TestEnv,
    host_config: &ManagedHostConfig,
    dpu_machine_id: &MachineId,
) -> rpc::Uuid {
    let mut txn = env.pool.begin().await.unwrap();
    let loopback_ip = super::dpu::loopback_ip(&mut txn, dpu_machine_id).await;
    let predicted_host = Machine::find_host_by_dpu_machine_id(&mut txn, dpu_machine_id)
        .await
        .unwrap()
        .unwrap();

    let prefix = NetworkPrefix::find_by(
        &mut txn,
        ObjectColumnFilter::One(
            network_prefix::SegmentIdColumn,
            &predicted_host.interfaces()[0].segment_id,
        ),
    )
    .await
    .unwrap()
    .remove(0);

    let response = env
        .api
        .discover_dhcp(Request::new(DhcpDiscovery {
            mac_address: host_config.dhcp_mac_address().to_string(),
            relay_address: loopback_ip.to_string(),
            vendor_string: None,
            link_address: Some(prefix.gateway.unwrap().to_string()),
            circuit_id: None,
            remote_id: None,
        }))
        .await
        .unwrap()
        .into_inner();
    response
        .machine_interface_id
        .expect("machine_interface_id must be set")
}

/// Emulates Host Machine Discovery (submitting hardware information) for the
/// Host that uses a certain `machine_interface_id`
pub async fn host_discover_machine(
    env: &TestEnv,
    host_config: &ManagedHostConfig,
    machine_interface_id: rpc::Uuid,
) -> ::rpc::common::MachineId {
    let mut discovery_info = DiscoveryInfo::try_from(HardwareInfo::from(host_config)).unwrap();

    discovery_info.attest_key_info = Some(AttestKeyInfo {
        ek_pub: EK_PUB_SERIALIZED.to_vec(),
        ak_pub: AK_PUB_SERIALIZED.to_vec(),
        ak_name: AK_NAME_SERIALIZED.to_vec(),
    });

    let response = env
        .api
        .discover_machine(Request::new(MachineDiscoveryInfo {
            machine_interface_id: Some(machine_interface_id),
            discovery_data: Some(DiscoveryData::Info(discovery_info)),
            create_machine: true,
        }))
        .await
        .unwrap()
        .into_inner();

    response.machine_id.expect("machine_id must be set")
}

/// Creates a Machine Interface and Machine for a Host
///
/// Returns the ID of the created machine
pub async fn create_host_machine(
    env: &TestEnv,
    host_config: &ManagedHostConfig,
    dpu_machine_id: &MachineId,
) -> rpc::MachineId {
    use crate::model::machine::{
        LockdownInfo, LockdownMode, LockdownState, MachineState, MeasuringState,
    };
    let bmc_machine_interface_id =
        host_bmc_discover_dhcp(env, &host_config.bmc_mac_address.to_string()).await;
    // Let's find the IP that we assign to the BMC
    let mut txn = env.pool.begin().await.unwrap();
    let bmc_interface =
        db::machine_interface::find_one(&mut txn, bmc_machine_interface_id.try_into().unwrap())
            .await
            .unwrap();
    let host_bmc_ip = bmc_interface.addresses[0];
    txn.rollback().await.unwrap();

    let machine_interface_id = host_discover_dhcp(env, host_config, dpu_machine_id).await;

    let host_machine_id = host_discover_machine(env, host_config, machine_interface_id).await;
    let host_machine_id = try_parse_machine_id(&host_machine_id).unwrap();
    let host_rpc_machine_id: rpc::MachineId = host_machine_id.to_string().into();

    update_bmc_metadata(
        env,
        host_rpc_machine_id.clone(),
        &host_bmc_ip.to_string(),
        FIXTURE_HOST_BMC_ADMIN_USER_NAME.to_string(),
        host_config.bmc_mac_address,
        FIXTURE_HOST_BMC_VERSION.to_owned(),
        FIXTURE_HOST_BMC_FIRMWARE_VERSION.to_owned(),
    )
    .await;

    if env.attestation_enabled {
        let mut txn = env.pool.begin().await.unwrap();
        env.run_machine_state_controller_iteration_until_state_matches(
            &host_machine_id,
            3,
            &mut txn,
            ManagedHostState::HostInit {
                machine_state: MachineState::Measuring {
                    measuring_state: MeasuringState::WaitingForMeasurements,
                },
            },
        )
        .await;
        txn.commit().await.unwrap();

        inject_machine_measurements(env, host_rpc_machine_id.clone()).await;
    }

    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration_until_state_matches(
        &host_machine_id,
        4,
        &mut txn,
        ManagedHostState::HostInit {
            machine_state: MachineState::WaitingForDiscovery,
        },
    )
    .await;

    env.api
        .record_hardware_health_report(Request::new(HardwareHealthReport {
            machine_id: Some(host_machine_id.to_string().into()),
            report: Some(HealthReport::empty("hardware-health".to_string()).into()),
        }))
        .await
        .expect("Failed to add hardware health report to newly created machine");

    txn.commit().await.unwrap();

    let response = forge_agent_control(env, host_rpc_machine_id.clone()).await;
    assert_eq!(response.action, Action::Discovery as i32);

    discovery_completed(env, host_rpc_machine_id.clone()).await;

    host_uefi_setup(env, &host_machine_id, host_rpc_machine_id.clone()).await;

    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration_until_state_matches(
        &host_machine_id,
        2,
        &mut txn,
        ManagedHostState::HostInit {
            machine_state: MachineState::WaitingForLockdown {
                lockdown_info: LockdownInfo {
                    state: LockdownState::WaitForDPUUp,
                    mode: LockdownMode::Enable,
                },
            },
        },
    )
    .await;
    txn.commit().await.unwrap();

    // We use forge_dpu_agent's health reporting as a signal that
    // DPU has rebooted.
    super::network_configured(env, dpu_machine_id).await;

    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration_until_state_matches(
        &host_machine_id,
        3,
        &mut txn,
        ManagedHostState::HostInit {
            machine_state: MachineState::MachineValidating {
                context: "Discovery".to_string(),
                id: uuid::Uuid::default(),
                completed: 1,
                total: 1,
                is_enabled: env.config.machine_validation_config.enabled,
            },
        },
    )
    .await;
    txn.commit().await.unwrap();

    machine_validation_completed(env, host_rpc_machine_id.clone(), None).await;

    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration_until_state_matches(
        &host_machine_id,
        3,
        &mut txn,
        ManagedHostState::HostInit {
            machine_state: MachineState::Discovered {
                skip_reboot_wait: false,
            },
        },
    )
    .await;
    txn.commit().await.unwrap();

    // This is what simulates a reboot being completed.
    let response = forge_agent_control(env, host_rpc_machine_id.clone()).await;
    assert_eq!(response.action, Action::Noop as i32);

    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration_until_state_matches(
        &host_machine_id,
        1,
        &mut txn,
        ManagedHostState::Ready,
    )
    .await;
    txn.commit().await.unwrap();

    host_rpc_machine_id
}

pub async fn host_uefi_setup(
    env: &TestEnv,
    host_machine_id: &MachineId,
    host_rpc_machine_id: ::rpc::common::MachineId,
) {
    for state in UefiSetupState::iter() {
        if state == UefiSetupState::UnlockHost {
            // This state is reserved for legacy hosts--newly ingested hosts will never get here
            continue;
        }

        let mut txn = env.pool.begin().await.unwrap();
        env.run_machine_state_controller_iteration_until_state_matches(
            host_machine_id,
            1,
            &mut txn,
            ManagedHostState::HostInit {
                machine_state: UefiSetup {
                    uefi_setup_info: UefiSetupInfo {
                        uefi_password_jid: None,
                        uefi_setup_state: state,
                    },
                },
            },
        )
        .await;
        txn.commit().await.unwrap();

        let response = forge_agent_control(env, host_rpc_machine_id.clone()).await;
        assert_eq!(response.action, Action::Noop as i32);
    }
}

pub async fn create_host_with_machine_validation(
    env: &TestEnv,
    host_config: &ManagedHostConfig,
    dpu_machine_id: &MachineId,
    machine_validation_result_data: Option<rpc::forge::MachineValidationResult>,
    error: Option<String>,
) -> rpc::MachineId {
    let mut machine_validation_result = machine_validation_result_data.unwrap_or_default();
    use crate::model::machine::{LockdownInfo, LockdownMode, LockdownState, MachineState};
    let bmc_machine_interface_id =
        host_bmc_discover_dhcp(env, &host_config.bmc_mac_address.to_string()).await;
    // Let's find the IP that we assign to the BMC
    let mut txn = env.pool.begin().await.unwrap();
    let bmc_interface =
        db::machine_interface::find_one(&mut txn, bmc_machine_interface_id.try_into().unwrap())
            .await
            .unwrap();
    let host_bmc_ip = bmc_interface.addresses[0];
    txn.rollback().await.unwrap();

    let machine_interface_id = host_discover_dhcp(env, host_config, dpu_machine_id).await;

    let host_machine_id = host_discover_machine(env, host_config, machine_interface_id).await;
    let host_machine_id = try_parse_machine_id(&host_machine_id).unwrap();
    let host_rpc_machine_id: rpc::MachineId = host_machine_id.to_string().into();

    update_bmc_metadata(
        env,
        host_rpc_machine_id.clone(),
        &host_bmc_ip.to_string(),
        FIXTURE_HOST_BMC_ADMIN_USER_NAME.to_string(),
        host_config.bmc_mac_address,
        FIXTURE_HOST_BMC_VERSION.to_owned(),
        FIXTURE_HOST_BMC_FIRMWARE_VERSION.to_owned(),
    )
    .await;

    let mut txn = env.pool.begin().await.unwrap();

    env.run_machine_state_controller_iteration_until_state_matches(
        &host_machine_id,
        4,
        &mut txn,
        ManagedHostState::HostInit {
            machine_state: MachineState::WaitingForDiscovery,
        },
    )
    .await;
    txn.commit().await.unwrap();

    let response = forge_agent_control(env, host_rpc_machine_id.clone()).await;
    assert_eq!(response.action, Action::Discovery as i32);

    discovery_completed(env, host_rpc_machine_id.clone()).await;

    host_uefi_setup(env, &host_machine_id, host_rpc_machine_id.clone()).await;

    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration_until_state_matches(
        &host_machine_id,
        2,
        &mut txn,
        ManagedHostState::HostInit {
            machine_state: MachineState::WaitingForLockdown {
                lockdown_info: LockdownInfo {
                    state: LockdownState::WaitForDPUUp,
                    mode: LockdownMode::Enable,
                },
            },
        },
    )
    .await;
    txn.commit().await.unwrap();

    // We use forge_dpu_agent's health reporting as a signal that
    // DPU has rebooted.
    super::network_configured(env, dpu_machine_id).await;

    let mut txn = env.pool.begin().await.unwrap();
    env.run_machine_state_controller_iteration_until_state_matches(
        &host_machine_id,
        3,
        &mut txn,
        ManagedHostState::HostInit {
            machine_state: MachineState::MachineValidating {
                context: "Discovery".to_string(),
                id: uuid::Uuid::default(),
                completed: 1,
                total: 1,
                is_enabled: env.config.machine_validation_config.enabled,
            },
        },
    )
    .await;
    txn.commit().await.unwrap();

    let response = forge_agent_control(env, host_rpc_machine_id.clone()).await;
    if env.config.machine_validation_config.enabled {
        let uuid = &response.data.unwrap().pair[1].value;
        let validation_id = Some(rpc::Uuid {
            value: uuid.to_owned(),
        });
        let success = update_machine_validation_run(
            env,
            validation_id.clone(),
            Some(rpc::Duration::from(std::time::Duration::from_secs(1200))),
            1,
        )
        .await;
        assert_eq!(success.message, "Success".to_string());
        let runs = get_machine_validation_runs(env, host_rpc_machine_id.clone(), false).await;
        for run in runs.runs {
            if run.validation_id == validation_id {
                assert_eq!(run.status.unwrap_or_default().total, 1);
                assert_eq!(run.status.unwrap_or_default().completed_tests, 0);
                assert_eq!(run.duration_to_complete.unwrap_or_default().seconds, 1200);
            }
        }
        machine_validation_result.validation_id = validation_id.clone();
        persist_machine_validation_result(env, machine_validation_result.clone()).await;
        assert_eq!(
            get_machine_validation_runs(env, host_rpc_machine_id.clone(), false)
                .await
                .runs[0]
                .end_time,
            None
        );

        machine_validation_completed(env, host_rpc_machine_id.clone(), error.clone()).await;

        let runs = get_machine_validation_runs(env, host_rpc_machine_id.clone(), false).await;
        for run in runs.runs {
            if run.validation_id == validation_id {
                assert_eq!(run.status.unwrap_or_default().total, 1);
                assert_eq!(run.status.unwrap_or_default().completed_tests, 1);
                assert_eq!(run.duration_to_complete.unwrap_or_default().seconds, 1200);
            }
        }

        if error.is_some() {
            env.run_machine_state_controller_iteration().await;

            let mut txn = env.pool.begin().await.unwrap();
            let machine = Machine::find_one(
                &mut txn,
                dpu_machine_id,
                crate::db::machine::MachineSearchConfig::default(),
            )
            .await
            .unwrap()
            .unwrap();

            match machine.current_state() {
                ManagedHostState::Failed { .. } => {}
                s => {
                    panic!("Incorrect state: {}", s);
                }
            }

            txn.commit().await.unwrap();
        } else if machine_validation_result.exit_code == 0 {
            let _ = forge_agent_control(env, host_rpc_machine_id.clone()).await;

            let mut txn = env.pool.begin().await.unwrap();
            env.run_machine_state_controller_iteration_until_state_matches(
                &host_machine_id,
                3,
                &mut txn,
                ManagedHostState::HostInit {
                    machine_state: MachineState::Discovered {
                        skip_reboot_wait: false,
                    },
                },
            )
            .await;
            txn.commit().await.unwrap();

            let response = forge_agent_control(env, host_rpc_machine_id.clone()).await;
            assert_eq!(response.action, Action::Noop as i32);
            let mut txn = env.pool.begin().await.unwrap();
            env.run_machine_state_controller_iteration_until_state_matches(
                &host_machine_id,
                1,
                &mut txn,
                ManagedHostState::Ready,
            )
            .await;
            txn.commit().await.unwrap();
        } else {
            let mut txn = env.pool.begin().await.unwrap();
            env.run_machine_state_controller_iteration_until_state_matches(
                &host_machine_id,
                1,
                &mut txn,
                ManagedHostState::Failed {
                    details: FailureDetails {
                        cause: FailureCause::MachineValidation {
                            err: format!("{} is failed", machine_validation_result.name),
                        },
                        failed_at: chrono::Utc::now(),
                        source: FailureSource::Scout,
                    },
                    machine_id: host_machine_id.clone(),
                    retry_count: 0,
                },
            )
            .await;
            txn.commit().await.unwrap();
        }
    } else {
        let mut txn = env.pool.begin().await.unwrap();

        env.run_machine_state_controller_iteration_until_state_matches(
            &host_machine_id,
            3,
            &mut txn,
            ManagedHostState::HostInit {
                machine_state: MachineState::Discovered {
                    skip_reboot_wait: true,
                },
            },
        )
        .await;

        txn.commit().await.unwrap();

        // Note: no forge_agent_control/reboot_completed call happens here, since we're skipping
        // machine validation and thus not doing an extra reboot.

        let mut txn = env.pool.begin().await.unwrap();
        env.run_machine_state_controller_iteration_until_state_matches(
            &host_machine_id,
            1,
            &mut txn,
            ManagedHostState::Ready,
        )
        .await;
        txn.commit().await.unwrap();
    }
    host_rpc_machine_id
}

pub async fn create_managed_host_with_ek(env: &TestEnv, ek_cert: &[u8]) -> (MachineId, MachineId) {
    let host_sim = ManagedHostSim {
        config: ManagedHostConfig {
            tpm_ek_cert: TpmEkCertificate::from(ek_cert.to_vec()),
            ..Default::default()
        },
    };

    let dpu_machine_id = create_dpu_machine(env, &host_sim.config).await;
    let dpu_machine_id = try_parse_machine_id(&dpu_machine_id).unwrap();
    let host_machine_id = create_host_machine(env, &host_sim.config, &dpu_machine_id).await;

    (
        try_parse_machine_id(&host_machine_id).unwrap(),
        dpu_machine_id,
    )
}
