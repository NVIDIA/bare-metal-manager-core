/*
 * SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use model::machine::{FailureDetails, ManagedHostState};
use rpc::forge::forge_server::Forge;
use sqlx::{Postgres, Transaction};
use tonic::Request;

use crate::tests::common::api_fixtures::{TestEnv, TestManagedHost};

pub(crate) async fn spdm_attestation_run_to_failed_then_to_success(
    env: &TestEnv,
    nras_should_fail_parsing_flag: Arc<AtomicBool>,
    mh: &TestManagedHost,
    txn: &mut Transaction<'_, Postgres>,
    poll_state: ManagedHostState,
) {
    // first, let's get into a polling state
    env.run_machine_state_controller_iteration_until_state_matches(
        &mh.host().id,
        10,
        poll_state.clone(),
    )
    .await;

    // make sure the attestation is in progress
    // device attestations should be created now
    let machine_ids = env
        .api
        .find_machine_ids_under_attestation(Request::new(()))
        .await
        .expect("Didn't find a machine under attestation")
        .into_inner();

    assert_eq!(1, machine_ids.machine_ids.len());

    let machine_id = machine_ids.machine_ids[0];

    // check that attestation's status is InProgress
    let response = env
        .api
        .get_machine_attestation_status(Request::new(machine_id))
        .await
        .expect("Could not get machine attestation status")
        .into_inner();

    assert_eq!(
        rpc::forge::SpdmAttestationStatus::SpdmAttInProgress,
        response.attestation_status()
    );

    // move the attestation until it reaches the Failed state
    for _ in 0..10 {
        env.run_spdm_controller_iteration_no_requeue().await;
    }

    let response = env
        .api
        .get_machine_attestation_status(Request::new(machine_id))
        .await
        .expect("Could not get machine attestation status")
        .into_inner();

    assert_eq!(
        rpc::forge::SpdmAttestationStatus::SpdmAttFailed,
        response.attestation_status()
    );

    // since we set the NRAS verifier mock flag to fail,
    // we expect it to fail now
    for _ in 0..5 {
        env.run_machine_state_controller_iteration().await;
    }

    let host = mh.host().db_machine(txn).await;
    assert!(
        matches!(
            host.current_state(),
            ManagedHostState::Failed {
                details: FailureDetails {
                    cause: model::machine::FailureCause::SpdmAttestationFailed { .. },
                    ..
                },
                ..
            }
        ),
        "Host state is {}",
        host.current_state()
    );

    // "fix" the NRAS verifier mock to succeed
    nras_should_fail_parsing_flag.store(false, Ordering::Relaxed);

    // manually trigger attestation via admin-cli
    let res = env
        .api
        .trigger_machine_attestation(tonic::Request::new(host.id))
        .await
        .expect("Failed to trigger SPDM attestation")
        .into_inner();
    assert_eq!(3, res.devices_under_attestation);

    // and make sure that the mh state controller has returned to PollResult state
    env.run_machine_state_controller_iteration_until_state_matches(&mh.host().id, 5, poll_state)
        .await;

    // move the spdm state controller until it reaches the Passed state
    for _ in 0..10 {
        env.run_spdm_controller_iteration_no_requeue().await;
    }
    let response = env
        .api
        .get_machine_attestation_status(Request::new(machine_id))
        .await
        .expect("Could not get machine attestation status")
        .into_inner();

    assert_eq!(
        rpc::forge::SpdmAttestationStatus::SpdmAttPassed,
        response.attestation_status()
    );
}
