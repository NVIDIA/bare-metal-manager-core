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

use carbide_uuid::machine::{MachineId, MachineIdSource, MachineType};
use ipnetwork::IpNetwork;
use model::test_support::ManagedHostConfig;
use rpc::forge;
use rpc::forge::forge_server::Forge;

use crate::test_support::fixture_config::ManagedHostConfigExt as _;
use crate::tests::common::api_fixtures;
use crate::tests::common::api_fixtures::network_segment::{
    FIXTURE_ADMIN_NETWORK_SEGMENT_GATEWAY, FIXTURE_HOST_INBAND_NETWORK_SEGMENT_GATEWAY,
    FIXTURE_UNDERLAY_NETWORK_SEGMENT_GATEWAY, create_admin_network_segment,
    create_host_inband_network_segment, create_underlay_network_segment,
};

// On a zero-DPU host, set-primary-dpu has no DPU to resolve to an interface, so
// the alias rejects up-front with `FailedPrecondition` and a message that names
// the underlying reason -- rather than failing later, more confusingly, when the
// DPU-to-interface lookup comes up empty.
#[crate::sqlx_test]
async fn test_set_primary_dpu_rejects_zero_dpu_host(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    // Zero-DPU host ingestion needs a HostInband network segment whose CIDR
    // covers the relay address; the default test env doesn't define one.
    let env = api_fixtures::create_test_env_with_overrides(
        pool,
        api_fixtures::TestEnvOverrides {
            site_prefixes: Some(vec![
                IpNetwork::new(
                    FIXTURE_ADMIN_NETWORK_SEGMENT_GATEWAY.network(),
                    FIXTURE_ADMIN_NETWORK_SEGMENT_GATEWAY.prefix(),
                )
                .unwrap(),
                IpNetwork::new(
                    FIXTURE_HOST_INBAND_NETWORK_SEGMENT_GATEWAY.network(),
                    FIXTURE_HOST_INBAND_NETWORK_SEGMENT_GATEWAY.prefix(),
                )
                .unwrap(),
                IpNetwork::new(
                    FIXTURE_UNDERLAY_NETWORK_SEGMENT_GATEWAY.network(),
                    FIXTURE_UNDERLAY_NETWORK_SEGMENT_GATEWAY.prefix(),
                )
                .unwrap(),
            ]),
            create_network_segments: Some(false),
            ..Default::default()
        },
    )
    .await;
    // HostInband segments must live in a Flat VPC. The test doesn't otherwise
    // need a non-Flat VPC, so create only a Flat one for the segment.
    let flat_vpc_id = api_fixtures::network_segment::create_default_flat_vpc(
        &env.api,
        "set-primary-dpu flat vpc",
    )
    .await;
    create_underlay_network_segment(&env.api).await;
    create_admin_network_segment(&env.api).await;
    create_host_inband_network_segment(&env.api, Some(flat_vpc_id)).await;
    env.run_network_segment_controller_iteration().await;
    env.run_network_segment_controller_iteration().await;

    let zero_dpu_host =
        api_fixtures::site_explorer::new_host(&env, ManagedHostConfig::with_dpus(vec![])).await?;

    let result = env
        .api
        .set_primary_dpu(tonic::Request::new(forge::SetPrimaryDpuRequest {
            host_machine_id: Some(zero_dpu_host.host_snapshot.id),
            // Any well-formed DPU id; the handler bails before reading it.
            dpu_machine_id: Some(MachineId::new(
                MachineIdSource::ProductBoardChassisSerial,
                [0u8; 32],
                MachineType::Dpu,
            )),
            reboot: false,
        }))
        .await;

    match result {
        Err(e) if e.code() == tonic::Code::FailedPrecondition => {
            assert!(
                e.message().contains("zero-DPU"),
                "error message should explicitly name zero-DPU as the reason; got: {}",
                e.message(),
            );
        }
        _ => panic!(
            "Expected zero-DPU host to reject set_primary_dpu with FailedPrecondition, got: {result:?}"
        ),
    };

    Ok(())
}
