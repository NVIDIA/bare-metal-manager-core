/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use carbide_uuid::instance::InstanceId;
use carbide_uuid::network::NetworkSegmentId;
use common::api_fixtures::{TestEnv, TestManagedHost, create_test_env};
use rpc::forge::forge_server::Forge;

use crate::tests::common;
use crate::tests::common::api_fixtures::create_managed_host;
use crate::tests::common::api_fixtures::instance::{
    TestInstance, default_os_config, default_tenant_config, single_interface_network_config,
};

/// The tenant's script is served for as long as the host keeps asking for it,
/// and only stops being served once provisioning is confirmed.
///
/// Consuming the one-shot request on the first serve was NVBug 6601291: a script
/// that failed to fetch its kernel spent the request, so every later boot got
/// exit instructions and the host network booted against an empty disk forever.
#[crate::sqlx_test]
async fn custom_ipxe_is_reserved_until_provisioning_completes(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let segment_id = env.create_vpc_and_tenant_segment().await;
    let mh = create_managed_host(&env).await;

    let mut txn = env.pool.begin().await.unwrap();
    let host_interface = mh.host().first_interface(&mut txn).await;
    txn.rollback().await.unwrap();
    let host_arch = rpc::forge::MachineArchitecture::X86;

    let tinstance = create_instance_awaiting_provisioning(&env, &mh, segment_id).await;
    assert!(
        !tinstance
            .rpc_instance()
            .await
            .config()
            .os()
            .run_provisioning_instructions_on_every_boot
    );

    // The install fails and the host comes back for instructions. Both boots get
    // the tenant's script, and both are recorded.
    for expected_serves in 1..=2 {
        let pxe = host_interface.get_pxe_instructions(host_arch).await;
        assert_eq!(pxe.pxe_script, "SomeRandomiPxe");
        assert_eq!(serve_count(&env, &tinstance).await, expected_serves);
    }

    // The host stops coming back, which is what a successful install looks like
    // from outside: the instance becomes Ready and the request is released.
    advance_to_instance_ready(&env, &mh).await;
    let mut txn = env.pool.begin().await.unwrap();
    let instance = tinstance.db_instance(&mut txn).await;
    txn.rollback().await.unwrap();
    assert!(!instance.use_custom_pxe_on_boot);
    assert_eq!(instance.custom_pxe_serve_count, 0);
    assert_eq!(instance.custom_pxe_last_served_at, None);

    assert_exits_into_os(&host_interface.get_pxe_instructions(host_arch).await.pxe_script);

    // A regular reboot attempt should still lead to returning "exit"
    invoke_instance_power(&env, tinstance.id, false).await;
    assert_exits_into_os(&host_interface.get_pxe_instructions(host_arch).await.pxe_script);

    // A reboot with flag `boot_with_custom_ipxe` should provide the custom iPXE
    // The reboot is handled by the state machine, which makes sure the boot order is configured properly.
    invoke_instance_power(&env, tinstance.id, true).await;
    advance_to_awaiting_provisioning(&env, &mh).await;
    let pxe = host_interface.get_pxe_instructions(host_arch).await;
    assert_eq!(pxe.pxe_script, "SomeRandomiPxe");
    advance_to_instance_ready(&env, &mh).await;

    // The next reboot should again lead to returning "exit"
    invoke_instance_power(&env, tinstance.id, false).await;
    assert_exits_into_os(&host_interface.get_pxe_instructions(host_arch).await.pxe_script);
}

/// A host that never installs anything is failed rather than left looping, and a
/// tenant can restart provisioning from that failure.
#[crate::sqlx_test]
async fn repeated_pxe_boots_fail_provisioning_and_can_be_retried(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let segment_id = env.create_vpc_and_tenant_segment().await;
    let mh = create_managed_host(&env).await;

    let mut txn = env.pool.begin().await.unwrap();
    let host_interface = mh.host().first_interface(&mut txn).await;
    txn.rollback().await.unwrap();
    let host_arch = rpc::forge::MachineArchitecture::X86;

    let tinstance = create_instance_awaiting_provisioning(&env, &mh, segment_id).await;

    // Every attempt fails, so the host asks for one more than its budget allows.
    let budget = env
        .config
        .machine_state_controller
        .max_provisioning_serves;
    for _ in 0..=budget {
        let pxe = host_interface.get_pxe_instructions(host_arch).await;
        assert_eq!(pxe.pxe_script, "SomeRandomiPxe");
    }
    assert_eq!(serve_count(&env, &tinstance).await, budget + 1);

    env.run_machine_state_controller_iteration_until_state_condition(&mh.id, 2, |machine| {
        matches!(
            machine.current_state(),
            model::machine::ManagedHostState::Assigned {
                instance_state: model::machine::InstanceState::Failed {
                    details: model::machine::FailureDetails {
                        cause: model::machine::FailureCause::ProvisioningFailed { .. },
                        ..
                    },
                    ..
                }
            }
        )
    })
    .await;

    // Launch Layer sees a terminal failure instead of an endless PENDING.
    assert_eq!(
        env.one_instance(tinstance.id).await.status().tenant(),
        rpc::TenantState::Failed
    );

    // Re-serving the script here would resume the loop the failure exists to
    // stop, and exit instructions would send the host into an unbootable disk.
    let pxe = host_interface.get_pxe_instructions(host_arch).await;
    assert!(
        pxe.pxe_script
            .contains("Could not continue boot due to invalid state"),
        "Actual script: {}",
        pxe.pxe_script
    );

    // The tenant fixes the script's artifacts and asks for another attempt.
    invoke_instance_power(&env, tinstance.id, true).await;
    advance_to_awaiting_provisioning(&env, &mh).await;
    assert_eq!(serve_count(&env, &tinstance).await, 0);
    let pxe = host_interface.get_pxe_instructions(host_arch).await;
    assert_eq!(pxe.pxe_script, "SomeRandomiPxe");
}

#[crate::sqlx_test]
async fn invoke_instance_power_requires_instance_id(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;

    let err = env
        .api
        .invoke_instance_power(tonic::Request::new(
            rpc::forge::InstancePowerRequest::default(),
        ))
        .await
        .unwrap_err();

    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert!(err.message().contains("instance_id"));
}

#[crate::sqlx_test]
async fn test_instance_always_boot_with_custom_ipxe(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let segment_id = env.create_vpc_and_tenant_segment().await;
    let mh = create_managed_host(&env).await;

    let mut txn = env.pool.begin().await.unwrap();
    let host_interface = mh.host().first_interface(&mut txn).await;
    txn.rollback().await.unwrap();
    let host_arch = rpc::forge::MachineArchitecture::X86;

    let tinstance = create_instance(&env, &mh, true, segment_id).await;
    assert!(
        tinstance
            .rpc_instance()
            .await
            .config()
            .os()
            .run_provisioning_instructions_on_every_boot
    );

    // First boot should return custom iPXE instructions
    let pxe = host_interface.get_pxe_instructions(host_arch).await;
    assert_eq!(pxe.pxe_script, "SomeRandomiPxe");

    // Second boot should also return custom iPXE instructions
    let pxe = host_interface.get_pxe_instructions(host_arch).await;
    assert_eq!(pxe.pxe_script, "SomeRandomiPxe");

    // A regular reboot attempt should also return custom iPXE instructions
    invoke_instance_power(&env, tinstance.id, false).await;
    let pxe = host_interface.get_pxe_instructions(host_arch).await;
    assert_eq!(pxe.pxe_script, "SomeRandomiPxe");

    // A reboot with flag `boot_with_custom_ipxe` should also return custom iPXE instructions
    invoke_instance_power(&env, tinstance.id, true).await;
    let pxe = host_interface.get_pxe_instructions(host_arch).await;
    assert_eq!(pxe.pxe_script, "SomeRandomiPxe");
}

fn assert_exits_into_os(pxe_script: &str) {
    assert!(
        pxe_script.contains("Current state: Assigned/Ready"),
        "Actual script: {pxe_script}"
    );
    assert!(
        pxe_script.contains(
            "This state assumes an OS is provisioned and will exit into the OS in 5 seconds."
        ),
        "Actual script: {pxe_script}"
    );
}

async fn serve_count(env: &TestEnv, tinstance: &TestInstance<'_, '_>) -> u32 {
    let mut txn = env.pool.begin().await.unwrap();
    let serve_count = tinstance.db_instance(&mut txn).await.custom_pxe_serve_count;
    txn.rollback().await.unwrap();
    serve_count
}

/// Drives a host that has just been asked for a custom-iPXE reboot through boot
/// configuration to the provisioning wait, where its script is served.
async fn advance_to_awaiting_provisioning(env: &TestEnv, mh: &TestManagedHost) {
    env.run_machine_state_controller_iteration_until_state_condition(&mh.id, 5, |machine| {
        matches!(
            machine.current_state(),
            model::machine::ManagedHostState::Assigned {
                instance_state: model::machine::InstanceState::HostPlatformConfiguration {
                    platform_config_state:
                        model::machine::HostPlatformConfigurationState::CheckHostConfig
                }
            }
        )
    })
    .await;
    mh.network_configured(env).await;
    env.run_machine_state_controller_iteration_until_state_condition(&mh.id, 5, |machine| {
        matches!(
            machine.current_state(),
            model::machine::ManagedHostState::Assigned {
                instance_state: model::machine::InstanceState::WaitingForDpusToUp
            }
        )
    })
    .await;
    mh.network_configured(env).await;
    env.run_machine_state_controller_iteration_until_state_condition(&mh.id, 5, |machine| {
        matches!(
            machine.current_state(),
            model::machine::ManagedHostState::Assigned {
                instance_state: model::machine::InstanceState::WaitingForProvisioningComplete { .. }
            }
        )
    })
    .await;
}

/// Completes the provisioning wait. The test site config uses a zero quiet
/// window, so a host that has stopped asking for iPXE instructions is treated as
/// provisioned on the next iteration.
async fn advance_to_instance_ready(env: &TestEnv, mh: &TestManagedHost) {
    env.run_machine_state_controller_iteration_until_state_condition(&mh.id, 2, |machine| {
        matches!(
            machine.current_state(),
            model::machine::ManagedHostState::Assigned {
                instance_state: model::machine::InstanceState::Ready
            }
        )
    })
    .await;
}

async fn invoke_instance_power(
    env: &TestEnv,
    instance_id: InstanceId,
    boot_with_custom_ipxe: bool,
) {
    env.api
        .invoke_instance_power(tonic::Request::new(rpc::forge::InstancePowerRequest {
            instance_id: Some(instance_id),
            operation: rpc::forge::instance_power_request::Operation::PowerReset as _,
            boot_with_custom_ipxe,
            apply_updates_on_reboot: false,
        }))
        .await
        .unwrap();
}

pub(in crate::tests) async fn create_instance<'a, 'b>(
    env: &'a TestEnv,
    mh: &'b TestManagedHost,
    run_provisioning_instructions_on_every_boot: bool,
    segment_id: NetworkSegmentId,
) -> TestInstance<'a, 'b> {
    mh.instance_builer(env)
        .config(instance_config(
            run_provisioning_instructions_on_every_boot,
            segment_id,
        ))
        .build()
        .await
}

/// Creates an instance and stops at the provisioning wait, where the host has
/// been rebooted and the tenant's iPXE script is served for every PXE request.
async fn create_instance_awaiting_provisioning<'a, 'b>(
    env: &'a TestEnv,
    mh: &'b TestManagedHost,
    segment_id: NetworkSegmentId,
) -> TestInstance<'a, 'b> {
    mh.instance_builer(env)
        .config(instance_config(false, segment_id))
        .stop_at_provisioning_wait()
        .build()
        .await
}

fn instance_config(
    run_provisioning_instructions_on_every_boot: bool,
    segment_id: NetworkSegmentId,
) -> rpc::InstanceConfig {
    let mut os: rpc::forge::InstanceOperatingSystemConfig = default_os_config();
    os.run_provisioning_instructions_on_every_boot = run_provisioning_instructions_on_every_boot;

    rpc::InstanceConfig {
        tenant: Some(default_tenant_config()),
        os: Some(os),
        network: Some(single_interface_network_config(segment_id)),
        infiniband: None,
        network_security_group_id: None,
        dpu_extension_services: None,
        nvlink: None,
        spxconfig: None,
        power_profile: None,
    }
}
