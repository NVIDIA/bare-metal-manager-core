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

//! `GetMachineBootInterfaces` gathers one machine's boot-interface view from
//! all four stores -- owned interface rows, predictions, the explored endpoint
//! default, and the retained post-deletion pairs -- and reports the effective
//! boot interface plus a divergence flag. These tests seed the stores for one
//! host and assert the gathered view.

use mac_address::MacAddress;
use model::network_segment::NetworkSegmentType;
use model::predicted_machine_interface::NewPredictedMachineInterface;
use model::test_support::ManagedHostConfig;
use rpc::forge;
use rpc::forge::forge_server::Forge;

use crate::sqlx_test;
use crate::test_support::fixture_config::{FixtureDefault as _, ManagedHostConfigExt as _};
use crate::tests::common::api_fixtures;

#[sqlx_test]
async fn test_get_machine_boot_interfaces_gathers_all_four_stores(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = api_fixtures::create_test_env(pool).await;

    // A real ingested host gives us owned `machine_interfaces` rows, BMC
    // topology, and explored endpoints -- stores 1 and 3.
    let host =
        api_fixtures::site_explorer::new_host(&env, ManagedHostConfig::default().with_dpu_count(1))
            .await?;
    let host_id = host.host_snapshot.id;

    // Read the owned rows the host ended up with: the primary is the effective
    // boot interface `pick_boot_interface` selects, and we reuse its MAC to
    // seed a retained record (store 4).
    let primary_mac = {
        let mut txn = env.pool.begin().await?;
        let interfaces = db::machine_interface::find_by_machine_ids(txn.as_mut(), &[host_id])
            .await?
            .remove(&host_id)
            .expect("host should have interface rows");
        txn.rollback().await?;
        interfaces
            .iter()
            .find(|i| i.primary_interface)
            .expect("a DPU host has a primary interface")
            .mac_address
    };
    // A DPU host's primary carries a boot-interface id; seed a known one so the
    // effective-pick contract is asserted against a concrete value -- a regression
    // to no id then fails loudly instead of defaulting the assertion away.
    let primary_boot_id = "NIC.Primary.1-1-1";

    // Store 2: a prediction for this host, flagged primary, on a MAC that is
    // NOT the owned effective pick -- two disagreeing boot-MAC signals, so the
    // view must flag divergence.
    let predicted_mac: MacAddress = "aa:bb:cc:dd:ee:01".parse()?;
    // Store 4: a retained pair on the primary's MAC, aged well past any window.
    // `find_records_by_macs` ignores the window, so the troubleshooting view
    // surfaces it even though `find_by_mac` would hide a stale record.
    {
        let mut txn = env.pool.begin().await?;
        db::predicted_machine_interface::create(
            NewPredictedMachineInterface {
                machine_id: &host_id,
                mac_address: predicted_mac,
                expected_network_segment_type: NetworkSegmentType::HostInband,
                boot_interface_id: Some("NIC.Predicted.1-1-1".to_string()),
                primary_interface: true,
            },
            txn.as_mut(),
        )
        .await?;

        // Seed the owned primary's boot-interface id so the effective pick has a
        // concrete value to assert.
        db::machine_interface::set_boot_interface_id(primary_mac, primary_boot_id, txn.as_mut())
            .await?;

        // Store 3: give the host's explored BMC endpoint a recorded boot
        // interface so the explored-endpoint store has concrete data to
        // surface. Resolve the BMC IP the same way the handler does (machine ->
        // BMC pairs -> explored endpoint at that address) and set its default to
        // the owned primary -- naming the same boot NIC, so it adds no new
        // distinct boot-MAC signal and leaves the divergence verdict to the
        // conflicting prediction.
        let bmc_ip: std::net::IpAddr =
            db::machine_topology::find_machine_bmc_pairs_by_machine_id(txn.as_mut(), vec![host_id])
                .await?
                .into_iter()
                .find_map(|(_, ip)| ip)
                .expect("the ingested host should have a BMC address")
                .parse()?;
        db::explored_endpoints::set_boot_interface(
            bmc_ip,
            &model::machine_boot_interface::MachineBootInterface {
                mac_address: primary_mac,
                interface_id: primary_boot_id.to_string(),
            },
            txn.as_mut(),
        )
        .await?;

        db::retained_boot_interface::upsert(txn.as_mut(), primary_mac, "NIC.Retained.9-9-9")
            .await?;
        sqlx::query(
            "UPDATE retained_boot_interfaces SET recorded_at = NOW() - INTERVAL '30 days' \
             WHERE mac_address = $1",
        )
        .bind(primary_mac)
        .execute(txn.as_mut())
        .await?;
        txn.commit().await?;
    }

    let report = env
        .api
        .get_machine_boot_interfaces(tonic::Request::new(
            forge::GetMachineBootInterfacesRequest {
                machine_id: Some(host_id),
            },
        ))
        .await?
        .into_inner();

    assert_eq!(report.machine_id, Some(host_id));

    // Store 1: the owned rows include the primary, and the primary is flagged.
    assert!(
        !report.machine_interfaces.is_empty(),
        "owned interface rows should be reported"
    );
    let reported_primary = report
        .machine_interfaces
        .iter()
        .find(|i| i.mac_address == primary_mac.to_string())
        .expect("the primary should appear among owned rows");
    assert!(
        reported_primary.primary_interface,
        "the primary row should carry the primary flag"
    );

    // Store 2: the seeded prediction shows up with its id and primary flag.
    let reported_prediction = report
        .predicted_interfaces
        .iter()
        .find(|p| p.mac_address == predicted_mac.to_string())
        .expect("the seeded prediction should be reported");
    assert!(reported_prediction.primary_interface);
    assert_eq!(
        reported_prediction.boot_interface_id.as_deref(),
        Some("NIC.Predicted.1-1-1"),
        "the prediction's boot interface id should be reported"
    );

    // Store 3: the host's explored BMC endpoint is surfaced with the boot
    // interface we recorded against it.
    let reported_explored = report
        .explored_endpoints
        .iter()
        .find(|e| e.boot_interface_mac.as_deref() == Some(primary_mac.to_string().as_str()))
        .expect("the host's explored endpoint default should be reported");
    assert_eq!(
        reported_explored.boot_interface_id.as_deref(),
        Some(primary_boot_id),
        "the explored endpoint's recorded boot interface id should be reported"
    );

    // Store 4: the stale retained record is surfaced with its recorded_at,
    // proving the un-window-filtered read.
    let reported_retained = report
        .retained_interfaces
        .iter()
        .find(|r| r.mac_address == primary_mac.to_string())
        .expect("the stale retained record should be surfaced");
    assert_eq!(reported_retained.boot_interface_id, "NIC.Retained.9-9-9");
    assert!(
        reported_retained.recorded_at.is_some(),
        "the retained record should carry recorded_at"
    );

    // Effective pick: the owned primary's MAC.
    assert_eq!(
        report.effective_boot_interface_mac.as_deref(),
        Some(primary_mac.to_string().as_str()),
        "the effective boot interface is the owned primary"
    );
    assert_eq!(
        report.effective_boot_interface_id.as_deref(),
        Some(primary_boot_id),
        "the effective boot interface id is the primary row's captured boot-interface id"
    );

    // Divergence: the predicted primary disagrees with the owned pick.
    assert!(
        report.divergent,
        "a predicted primary on a different MAC than the owned pick is a divergence"
    );

    Ok(())
}

#[sqlx_test]
async fn test_get_machine_boot_interfaces_agrees_when_only_owned_rows_exist(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = api_fixtures::create_test_env(pool).await;

    let host =
        api_fixtures::site_explorer::new_host(&env, ManagedHostConfig::default().with_dpu_count(1))
            .await?;
    let host_id = host.host_snapshot.id;

    let report = env
        .api
        .get_machine_boot_interfaces(tonic::Request::new(
            forge::GetMachineBootInterfacesRequest {
                machine_id: Some(host_id),
            },
        ))
        .await?
        .into_inner();

    // No predictions seeded.
    assert!(report.predicted_interfaces.is_empty());
    // The owned primary is the effective pick.
    assert!(report.effective_boot_interface_mac.is_some());

    // With at most one distinct boot-MAC signal (the owned pick; the explored
    // default, when recorded, names the same boot NIC for a DPU host), the
    // stores do not diverge.
    assert!(
        !report.divergent,
        "a freshly ingested host with no conflicting prediction should not diverge"
    );

    Ok(())
}
