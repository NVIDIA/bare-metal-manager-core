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

// tests/integration.rs
//
// Test a whole lifecycle of things.

#[cfg(test)]
mod tests {
    use db::measured_boot::journal;
    use measured_boot::pcr::{PcrRegisterValue, parse_pcr_index_input};
    use measured_boot::records::{MeasurementBundleState, MeasurementMachineState};

    use crate::measured_boot::tests::common::{create_test_machine, load_topology_json};

    // test_measured_boot_integration tests all sorts of
    // things like it was a real active environment.
    #[crate::sqlx_test]
    pub async fn test_measured_boot_integration(
        pool: sqlx::PgPool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut txn = pool.begin().await?;

        let dell_r750_topology = load_topology_json("dell_r750.json");
        let dgx_h100_topology = load_topology_json("lenovo_sr670.json");
        let dgx_h100_v1_topology = load_topology_json("lenovo_sr670_v2.json");

        // princess-network
        let princess_network = create_test_machine(
            &mut txn,
            "fm100hseddco33hvlofuqvg543p6p9aj60g76q5cq491g9m9tgtf2dk0530",
            &dell_r750_topology,
        )
        .await?;

        // beer-louisiana
        let beer_louisiana = create_test_machine(
            &mut txn,
            "fm100htrh18t1lrjg2pqagkh3sfigr9m65dejvkq168ako07sc0uibpp5q0",
            &dell_r750_topology,
        )
        .await?;

        // lime-coconut
        let lime_coconut = create_test_machine(
            &mut txn,
            "fm100htdekjaiocbggbkttpjnjf4i1ac9li56c0ulsef42nien02mgl66tg",
            &dell_r750_topology,
        )
        .await?;

        // slippery-lilac
        let slippery_lilac = create_test_machine(
            &mut txn,
            "fm100ht68sf2m52idrpslcjkpdj5r3tb3j5o0bkfubhoglbq47u18nknfog",
            &dgx_h100_topology,
        )
        .await?;

        // silly-salamander
        let silly_salamander = create_test_machine(
            &mut txn,
            "fm100ht6mda2rgqr432ii8m9dfvph87ckr906kke4oaug7h2t6vi626g86g",
            &dgx_h100_v1_topology,
        )
        .await?;

        // cat-videos
        let cat_videos = create_test_machine(
            &mut txn,
            "fm100htes3rn1npvbtm5qd57dkilaag7ljugl1llmm7rfuq1ov50i0rpl30",
            &dgx_h100_v1_topology,
        )
        .await?;

        let dell_r750_attrs = [
            ("sys_vendor".to_string(), "Dell, Inc.".to_string()),
            ("product_name".to_string(), "PowerEdge R750".to_string()),
            ("bios_version".to_string(), "1.8.2".to_string()),
        ]
        .into_iter()
        .collect();

        let dgx_h100_attrs = [
            ("sys_vendor".to_string(), "Lenovo".to_string()),
            (
                "product_name".to_string(),
                "ThinkSystem SR670 V2".to_string(),
            ),
            ("bios_version".to_string(), "U8E122J-1.51".to_string()),
        ]
        .into_iter()
        .collect();

        //let dgx_h100_v1_attrs: HashMap<String, String> = [
        //    ("vendor".to_string(), "nvidia".to_string()),
        //    ("product".to_string(), "dgx_h100".to_string()),
        //    ("fw".to_string(), "v1".to_string()),
        //]
        //.into_iter()
        //.collect();

        let princess_values: Vec<PcrRegisterValue> = vec![
            PcrRegisterValue {
                pcr_register: 0,
                sha_any: "aa".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 1,
                sha_any: "bb".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 2,
                sha_any: "cc".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 3,
                sha_any: "pppppppppppppppppp".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 4,
                sha_any: "ee".to_string(),
            },
        ];

        let beer_values: Vec<PcrRegisterValue> = vec![
            PcrRegisterValue {
                pcr_register: 0,
                sha_any: "aa".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 1,
                sha_any: "bb".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 2,
                sha_any: "cc".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 3,
                sha_any: "oooooooooooooooooo".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 4,
                sha_any: "ee".to_string(),
            },
        ];

        let bad_dell_values: Vec<PcrRegisterValue> = vec![
            PcrRegisterValue {
                pcr_register: 0,
                sha_any: "aa".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 1,
                sha_any: "xxxxxxxxx".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 2,
                sha_any: "cc".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 3,
                sha_any: "dd".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 4,
                sha_any: "ee".to_string(),
            },
        ];

        let dgx_h100_values: Vec<PcrRegisterValue> = vec![
            PcrRegisterValue {
                pcr_register: 0,
                sha_any: "aa".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 1,
                sha_any: "bb".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 2,
                sha_any: "cc".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 3,
                sha_any: "dd".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 4,
                sha_any: "ee".to_string(),
            },
        ];

        let dgx_h100_v1_values: Vec<PcrRegisterValue> = vec![
            PcrRegisterValue {
                pcr_register: 0,
                sha_any: "xx".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 1,
                sha_any: "yy".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 2,
                sha_any: "zz".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 3,
                sha_any: "dd".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 4,
                sha_any: "pp".to_string(),
            },
        ];

        // deal with princess-network and beer-louisiana

        let dell_r750_profile =
            db::measured_boot::profile::new(&mut txn, None, &dell_r750_attrs).await?;

        let princess_report =
            db::measured_boot::report::new(&mut txn, princess_network.machine_id, &princess_values)
                .await?;
        assert_eq!(princess_report.machine_id, princess_network.machine_id);

        let princess_journal =
            journal::get_latest_for_machine_id(&mut txn, princess_network.machine_id)
                .await?
                .unwrap();
        assert_eq!(
            princess_journal.profile_id,
            Some(dell_r750_profile.profile_id)
        );
        assert_eq!(
            princess_journal.state,
            MeasurementMachineState::PendingBundle
        );
        assert_eq!(princess_journal.bundle_id, None);

        let report =
            db::measured_boot::report::new(&mut txn, beer_louisiana.machine_id, &beer_values)
                .await?;
        assert_eq!(report.machine_id, beer_louisiana.machine_id);

        let beer_journal = db::measured_boot::journal::get_latest_for_machine_id(
            &mut txn,
            beer_louisiana.machine_id,
        )
        .await?
        .unwrap();
        assert_eq!(beer_journal.profile_id, princess_journal.profile_id);
        assert_eq!(beer_journal.state, MeasurementMachineState::PendingBundle);
        assert_eq!(beer_journal.bundle_id, None);

        let lime_report =
            db::measured_boot::report::new(&mut txn, lime_coconut.machine_id, &bad_dell_values)
                .await?;
        assert_eq!(lime_report.machine_id, lime_coconut.machine_id);

        let lime_journal = db::measured_boot::journal::get_latest_for_machine_id(
            &mut txn,
            lime_coconut.machine_id,
        )
        .await?
        .unwrap();
        assert_eq!(beer_journal.profile_id, lime_journal.profile_id);
        assert_eq!(lime_journal.state, MeasurementMachineState::PendingBundle);

        // and now deal with slippery-lilac
        let report =
            db::measured_boot::report::new(&mut txn, slippery_lilac.machine_id, &dgx_h100_values)
                .await?;
        assert_eq!(report.machine_id, slippery_lilac.machine_id);

        let slippery_profile =
            db::measured_boot::profile::load_from_attrs(&mut txn, &dgx_h100_attrs)
                .await?
                .unwrap();

        let slippery_journal = db::measured_boot::journal::get_latest_for_machine_id(
            &mut txn,
            slippery_lilac.machine_id,
        )
        .await?
        .unwrap();
        assert_eq!(
            slippery_journal.profile_id,
            Some(slippery_profile.profile_id)
        );
        assert_ne!(slippery_journal.profile_id, beer_journal.profile_id);
        assert_eq!(
            slippery_journal.state,
            MeasurementMachineState::PendingBundle
        );
        assert_eq!(slippery_journal.bundle_id, None);

        // and now kick off silly-salander and cat-videos
        let report = db::measured_boot::report::new(
            &mut txn,
            silly_salamander.machine_id,
            &dgx_h100_v1_values,
        )
        .await?;
        assert_eq!(report.machine_id, silly_salamander.machine_id);

        let cat_report =
            db::measured_boot::report::new(&mut txn, cat_videos.machine_id, &dgx_h100_v1_values)
                .await?;
        assert_eq!(cat_report.machine_id, cat_videos.machine_id);

        let silly_journal = db::measured_boot::journal::get_latest_for_machine_id(
            &mut txn,
            silly_salamander.machine_id,
        )
        .await?
        .unwrap();

        let cat_journal =
            db::measured_boot::journal::get_latest_for_machine_id(&mut txn, cat_videos.machine_id)
                .await?
                .unwrap();

        assert_eq!(silly_journal.profile_id, cat_journal.profile_id);
        assert_eq!(silly_journal.state, MeasurementMachineState::PendingBundle);
        assert_eq!(silly_journal.state, cat_journal.state);

        let pcr_set = parse_pcr_index_input("0-2,4")?;
        let bundle = db::measured_boot::report::create_active_bundle(
            &mut txn,
            &princess_report,
            &Some(pcr_set),
        )
        .await?;
        assert_eq!(bundle.pcr_values().len(), 4);
        assert_eq!(bundle.state, MeasurementBundleState::Active);

        assert_eq!(
            MeasurementMachineState::Measured,
            db::measured_boot::journal::get_latest_for_machine_id(
                &mut txn,
                princess_network.machine_id
            )
            .await?
            .unwrap()
            .state
        );

        assert_eq!(
            MeasurementMachineState::Measured,
            db::measured_boot::journal::get_latest_for_machine_id(
                &mut txn,
                beer_louisiana.machine_id
            )
            .await?
            .unwrap()
            .state
        );

        assert_eq!(
            MeasurementMachineState::PendingBundle,
            db::measured_boot::journal::get_latest_for_machine_id(
                &mut txn,
                lime_coconut.machine_id
            )
            .await?
            .unwrap()
            .state
        );

        assert_eq!(
            MeasurementMachineState::PendingBundle,
            db::measured_boot::journal::get_latest_for_machine_id(
                &mut txn,
                slippery_lilac.machine_id
            )
            .await?
            .unwrap()
            .state
        );

        assert_eq!(
            MeasurementMachineState::PendingBundle,
            db::measured_boot::journal::get_latest_for_machine_id(
                &mut txn,
                silly_salamander.machine_id
            )
            .await?
            .unwrap()
            .state
        );

        assert_eq!(
            MeasurementMachineState::PendingBundle,
            db::measured_boot::journal::get_latest_for_machine_id(&mut txn, cat_videos.machine_id)
                .await?
                .unwrap()
                .state
        );

        let pcr_set = parse_pcr_index_input("1")?;
        let bundle = db::measured_boot::report::create_revoked_bundle(
            &mut txn,
            &lime_report,
            &Some(pcr_set),
        )
        .await?;
        assert_eq!(bundle.pcr_values().len(), 1);
        assert_eq!(bundle.state, MeasurementBundleState::Revoked);

        assert_eq!(
            MeasurementMachineState::Measured,
            db::measured_boot::journal::get_latest_for_machine_id(
                &mut txn,
                princess_network.machine_id
            )
            .await?
            .unwrap()
            .state
        );

        assert_eq!(
            MeasurementMachineState::Measured,
            db::measured_boot::journal::get_latest_for_machine_id(
                &mut txn,
                beer_louisiana.machine_id
            )
            .await?
            .unwrap()
            .state
        );

        assert_eq!(
            MeasurementMachineState::MeasuringFailed,
            db::measured_boot::journal::get_latest_for_machine_id(
                &mut txn,
                lime_coconut.machine_id
            )
            .await?
            .unwrap()
            .state
        );

        assert_eq!(
            MeasurementMachineState::PendingBundle,
            db::measured_boot::journal::get_latest_for_machine_id(
                &mut txn,
                slippery_lilac.machine_id
            )
            .await?
            .unwrap()
            .state
        );

        assert_eq!(
            MeasurementMachineState::PendingBundle,
            db::measured_boot::journal::get_latest_for_machine_id(
                &mut txn,
                silly_salamander.machine_id
            )
            .await?
            .unwrap()
            .state
        );

        assert_eq!(
            MeasurementMachineState::PendingBundle,
            db::measured_boot::journal::get_latest_for_machine_id(&mut txn, cat_videos.machine_id)
                .await?
                .unwrap()
                .state
        );

        let bundle =
            db::measured_boot::report::create_active_bundle(&mut txn, &cat_report, &None).await?;
        assert_eq!(bundle.pcr_values().len(), 5);
        assert_eq!(bundle.state, MeasurementBundleState::Active);

        assert_eq!(
            MeasurementMachineState::Measured,
            db::measured_boot::journal::get_latest_for_machine_id(
                &mut txn,
                princess_network.machine_id
            )
            .await?
            .unwrap()
            .state
        );

        assert_eq!(
            MeasurementMachineState::Measured,
            db::measured_boot::journal::get_latest_for_machine_id(
                &mut txn,
                beer_louisiana.machine_id
            )
            .await?
            .unwrap()
            .state
        );

        assert_eq!(
            MeasurementMachineState::MeasuringFailed,
            db::measured_boot::journal::get_latest_for_machine_id(
                &mut txn,
                lime_coconut.machine_id
            )
            .await?
            .unwrap()
            .state
        );

        assert_eq!(
            MeasurementMachineState::PendingBundle,
            db::measured_boot::journal::get_latest_for_machine_id(
                &mut txn,
                slippery_lilac.machine_id
            )
            .await?
            .unwrap()
            .state
        );

        assert_eq!(
            MeasurementMachineState::Measured,
            db::measured_boot::journal::get_latest_for_machine_id(
                &mut txn,
                silly_salamander.machine_id
            )
            .await?
            .unwrap()
            .state
        );

        assert_eq!(
            MeasurementMachineState::Measured,
            db::measured_boot::journal::get_latest_for_machine_id(&mut txn, cat_videos.machine_id)
                .await?
                .unwrap()
                .state
        );

        Ok(())
    }
}
