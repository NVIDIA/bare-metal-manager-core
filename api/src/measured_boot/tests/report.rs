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

///////////////////////////////////////////////////////////////////////////////
/// tests/report.rs
///
/// Reports:
/// [x] test_report_crudl: Make sure basic CRUDL works as expected.
/// [x] test_report_journal: Make sure journal is updated on reports.
/// [x] test_report_to_active_bundle: Make sure active bundle promotion works.
/// [x] test_report_to_revoked_bundle: Ensure revoked bundle promotion works.
///////////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use crate::measured_boot::dto::records::{MeasurementBundleState, MeasurementMachineState};
    use crate::measured_boot::interface::common::parse_pcr_index_input;
    use crate::measured_boot::interface::{
        common::{pcr_register_values_to_map, PcrRegisterValue},
        report::{get_all_measurement_report_records, get_all_measurement_report_value_records},
    };
    use crate::measured_boot::model::bundle::MeasurementBundle;
    use crate::measured_boot::model::journal::MeasurementJournal;
    use crate::measured_boot::model::profile::MeasurementSystemProfile;
    use crate::measured_boot::model::report::MeasurementReport;
    use crate::measured_boot::tests::common::{create_test_machine, load_topology_json};
    use std::collections::HashMap;

    // test_profile_crudl creates a new profile with 3 attributes,
    // another new profile with 4 attributes.
    //
    // It makes sure each profile results in the correct number
    // of records being inserted into the database, and also makes
    // sure the records themselves are correct.
    #[sqlx::test]
    pub async fn test_report_crudl(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
        let mut txn = pool.begin().await?;
        let machine = create_test_machine(
            &mut txn,
            "fm100hseddco33hvlofuqvg543p6p9aj60g76q5cq491g9m9tgtf2dk0530",
            &load_topology_json("dell_r750.json"),
        )
        .await?;

        let values: Vec<PcrRegisterValue> = vec![
            PcrRegisterValue {
                pcr_register: 0,
                sha256: "aa".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 1,
                sha256: "bb".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 2,
                sha256: "cc".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 3,
                sha256: "dd".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 4,
                sha256: "ee".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 5,
                sha256: "ff".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 6,
                sha256: "gg".to_string(),
            },
        ];
        let input_value_map = pcr_register_values_to_map(&values)?;
        assert_eq!(input_value_map.len(), 7);

        // Make a report and make sure it looks good.
        let report =
            MeasurementReport::new_with_txn(&mut txn, machine.machine_id.clone(), &values).await?;
        assert_eq!(report.machine_id, machine.machine_id);
        assert_eq!(report.pcr_values().len(), 7);
        let report_value_map = pcr_register_values_to_map(&report.pcr_values())?;

        // Get the same report and make sure its the same as the report we made.
        let same_report = MeasurementReport::from_id_with_txn(&mut txn, report.report_id).await?;
        assert_eq!(report.report_id, same_report.report_id);
        assert_eq!(report.ts, same_report.ts);
        assert_eq!(same_report.machine_id, machine.machine_id);
        assert_eq!(same_report.pcr_values().len(), 7);
        let same_report_value_map = pcr_register_values_to_map(&same_report.pcr_values())?;

        // Now make another report with the same values, which is totally fine,
        // and make sure that all looks good too.

        let report2 =
            MeasurementReport::new_with_txn(&mut txn, machine.machine_id.clone(), &values).await?;
        assert_eq!(report2.machine_id, machine.machine_id);
        assert_eq!(report2.pcr_values().len(), 7);

        assert_ne!(report2.report_id, report.report_id);
        let report2_value_map = pcr_register_values_to_map(&report2.pcr_values())?;

        // Double check values against the input values.
        for (pcr_register, input_value) in input_value_map.iter() {
            let report_value = report_value_map.get(pcr_register);
            assert!(report_value.is_some());
            assert_eq!(report_value.unwrap().sha256, input_value.sha256);
            let same_report_value = same_report_value_map.get(pcr_register);
            assert!(same_report_value.is_some());
            assert_eq!(same_report_value.unwrap().sha256, input_value.sha256);
            let report2_value = report2_value_map.get(pcr_register);
            assert!(report2_value.is_some());
            assert_eq!(report2_value.unwrap().sha256, input_value.sha256);
        }
        assert_eq!(
            serde_json::to_string_pretty(&report).unwrap(),
            serde_json::to_string_pretty(&same_report).unwrap()
        );

        // And then a third report.
        let values3: Vec<PcrRegisterValue> = vec![
            PcrRegisterValue {
                pcr_register: 0,
                sha256: "xx".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 1,
                sha256: "yy".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 2,
                sha256: "zz".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 3,
                sha256: "dd".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 4,
                sha256: "ee".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 5,
                sha256: "ff".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 6,
                sha256: "pp".to_string(),
            },
        ];
        let input3_value_map = pcr_register_values_to_map(&values3)?;
        assert_eq!(input3_value_map.len(), 7);

        // Make a report and make sure it looks good.
        let report3 =
            MeasurementReport::new_with_txn(&mut txn, machine.machine_id.clone(), &values3).await?;
        assert_eq!(report3.machine_id, machine.machine_id);
        assert_eq!(report3.pcr_values().len(), 7);
        let report3_value_map = pcr_register_values_to_map(&report3.pcr_values())?;

        // Get the same report and make sure its the same as the report we made.
        let same_report3 = MeasurementReport::from_id_with_txn(&mut txn, report3.report_id).await?;
        assert_eq!(report3.report_id, same_report3.report_id);
        assert_eq!(report3.ts, same_report3.ts);
        assert_eq!(same_report3.machine_id, machine.machine_id);
        assert_eq!(same_report3.pcr_values().len(), 7);
        let same_report3_value_map = pcr_register_values_to_map(&same_report3.pcr_values())?;

        // Double check values against the input values.
        for (pcr_register, input_value) in input3_value_map.iter() {
            let report3_value = report3_value_map.get(pcr_register);
            assert!(report3_value.is_some());
            assert_eq!(report3_value.unwrap().sha256, input_value.sha256);
            let same_report3_value = same_report3_value_map.get(pcr_register);
            assert!(same_report3_value.is_some());
            assert_eq!(same_report3_value.unwrap().sha256, input_value.sha256);
        }

        // And then get everything thus far.
        let reports = MeasurementReport::get_all(&mut txn).await?;
        assert_eq!(reports.len(), 3);

        // And now lets do some database record checks.
        let report_records = get_all_measurement_report_records(&mut txn).await?;
        assert_eq!(report_records.len(), 3);

        let report_value_records = get_all_measurement_report_value_records(&mut txn).await?;
        assert_eq!(report_value_records.len(), 21);

        Ok(())
    }

    // test_report_journal creates a new profile and makes
    // sure the journal gets updated.
    #[sqlx::test]
    pub async fn test_report_journal(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
        let mut txn = pool.begin().await?;
        let machine = create_test_machine(
            &mut txn,
            "fm100hseddco33hvlofuqvg543p6p9aj60g76q5cq491g9m9tgtf2dk0530",
            &load_topology_json("dell_r750.json"),
        )
        .await?;

        // There should be no profiles yet, so just check
        // to make sure.
        let attrs: HashMap<String, String> = vec![
            ("sys_vendor".to_string(), "Dell, Inc.".to_string()),
            ("product_name".to_string(), "PowerEdge R750".to_string()),
            ("bios_version".to_string(), "1.8.2".to_string()),
        ]
        .into_iter()
        .collect();

        let optional_profile = MeasurementSystemProfile::load_from_attrs(&mut txn, &attrs).await?;
        assert!(optional_profile.is_none());

        let values: Vec<PcrRegisterValue> = vec![
            PcrRegisterValue {
                pcr_register: 0,
                sha256: "aa".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 1,
                sha256: "bb".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 2,
                sha256: "cc".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 3,
                sha256: "dd".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 4,
                sha256: "ee".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 5,
                sha256: "ff".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 6,
                sha256: "gg".to_string(),
            },
        ];
        let input_value_map = pcr_register_values_to_map(&values)?;
        assert_eq!(input_value_map.len(), 7);

        // Make a report and make sure the records themselves are correct.
        let report =
            MeasurementReport::new_with_txn(&mut txn, machine.machine_id.clone(), &values).await?;

        txn.commit().await?;
        let mut txn = pool.begin().await?;

        // And NOW there should be a profile.
        let optional_profile = MeasurementSystemProfile::load_from_attrs(&mut txn, &attrs).await?;
        assert!(optional_profile.is_some());
        let profile = optional_profile.unwrap();

        let journals =
            MeasurementJournal::get_all_for_machine_id(&mut txn, report.machine_id.clone()).await?;
        assert_eq!(journals.len(), 1);

        let journal = &journals[0];
        assert_eq!(journal.machine_id, report.machine_id);
        assert_eq!(journal.report_id, report.report_id);
        assert_eq!(journal.profile_id, Some(profile.profile_id));
        assert_eq!(journal.bundle_id, None);
        assert_eq!(journal.state, MeasurementMachineState::PendingBundle);

        Ok(())
    }

    // test_report_to_active_bundle promotes a report to an active
    // bundle and makes sure all is well.
    #[sqlx::test]
    pub async fn test_report_to_active_bundle(
        pool: sqlx::PgPool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut txn = pool.begin().await?;
        let machine = create_test_machine(
            &mut txn,
            "fm100hseddco33hvlofuqvg543p6p9aj60g76q5cq491g9m9tgtf2dk0530",
            &load_topology_json("dell_r750.json"),
        )
        .await?;

        let values: Vec<PcrRegisterValue> = vec![
            PcrRegisterValue {
                pcr_register: 0,
                sha256: "aa".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 1,
                sha256: "bb".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 2,
                sha256: "cc".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 3,
                sha256: "dd".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 4,
                sha256: "ee".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 5,
                sha256: "ff".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 6,
                sha256: "gg".to_string(),
            },
        ];

        // And then make a report. At this point, we should have a:
        // - machine_id
        // - report_id
        // - profile_id
        //
        // ...which means we have what we need to promote a new bundle,
        // which will result in a second journal entry.
        let report =
            MeasurementReport::new_with_txn(&mut txn, machine.machine_id.clone(), &values).await?;
        let journals =
            MeasurementJournal::get_all_for_machine_id(&mut txn, report.machine_id.clone()).await?;
        assert_eq!(journals.len(), 1);
        let is_latest_journal =
            MeasurementJournal::get_latest_for_machine_id(&mut txn, report.machine_id.clone())
                .await?;
        assert!(is_latest_journal.is_some());
        let latest_journal = is_latest_journal.unwrap();
        assert_eq!(latest_journal.state, MeasurementMachineState::PendingBundle);
        assert_eq!(latest_journal.bundle_id, None);

        // Make a bundle with all of the values from the report,
        // and make sure everything gets updated accordingly.
        let bundle_full = report
            .create_active_bundle_with_txn(&mut txn, &None)
            .await?;
        let bundles = MeasurementBundle::get_all(&mut txn).await?;
        assert_eq!(bundles.len(), 1);
        let journals =
            MeasurementJournal::get_all_for_machine_id(&mut txn, report.machine_id.clone()).await?;
        assert_eq!(journals.len(), 2);
        let first_bundle =
            MeasurementBundle::from_id_with_txn(&mut txn, bundle_full.bundle_id).await?;
        assert_eq!(first_bundle.pcr_values().len(), 7);
        let is_latest_journal =
            MeasurementJournal::get_latest_for_machine_id(&mut txn, report.machine_id.clone())
                .await?;
        assert!(is_latest_journal.is_some());
        let latest_journal = is_latest_journal.unwrap();
        assert_eq!(latest_journal.bundle_id, Some(first_bundle.bundle_id));
        assert_eq!(latest_journal.state, MeasurementMachineState::Measured);

        // Create a new bundle with SOME of the bundles from the report,
        // and make sure it all looks good.
        let pcr_set = parse_pcr_index_input("0-3")?;
        let bundle_partial = report
            .create_active_bundle_with_txn(&mut txn, &Some(pcr_set))
            .await?;
        let bundles = MeasurementBundle::get_all(&mut txn).await?;
        assert_eq!(bundles.len(), 2);
        let journals =
            MeasurementJournal::get_all_for_machine_id(&mut txn, report.machine_id.clone()).await?;
        assert_eq!(journals.len(), 3);
        let second_bundle =
            MeasurementBundle::from_id_with_txn(&mut txn, bundle_partial.bundle_id).await?;
        assert_eq!(second_bundle.pcr_values().len(), 4);

        let is_latest_journal =
            MeasurementJournal::get_latest_for_machine_id(&mut txn, report.machine_id.clone())
                .await?;
        assert!(is_latest_journal.is_some());
        let latest_journal = is_latest_journal.unwrap();
        assert_eq!(latest_journal.bundle_id, Some(second_bundle.bundle_id));
        assert_eq!(latest_journal.state, MeasurementMachineState::Measured);

        // And then create a bundle that won't match, and make
        // sure that it all works.

        let values: Vec<PcrRegisterValue> = vec![
            PcrRegisterValue {
                pcr_register: 0,
                sha256: "aa".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 1,
                sha256: "bb".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 2,
                sha256: "cc".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 3,
                sha256: "dd".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 4,
                sha256: "ee".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 5,
                sha256: "ff".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 6,
                sha256: "gg".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 7,
                sha256: "hh".to_string(),
            },
        ];

        let other_bundle = MeasurementBundle::new_with_txn(
            &mut txn,
            bundle_partial.profile_id,
            None,
            &values,
            Some(MeasurementBundleState::Active),
        )
        .await?;

        let bundles = MeasurementBundle::get_all(&mut txn).await?;
        assert_eq!(bundles.len(), 3);
        let journals =
            MeasurementJournal::get_all_for_machine_id(&mut txn, report.machine_id.clone()).await?;
        assert_eq!(journals.len(), 3);
        let third_bundle =
            MeasurementBundle::from_id_with_txn(&mut txn, other_bundle.bundle_id).await?;
        assert_eq!(third_bundle.pcr_values().len(), 8);

        let is_latest_journal =
            MeasurementJournal::get_latest_for_machine_id(&mut txn, report.machine_id.clone())
                .await?;
        assert!(is_latest_journal.is_some());
        let latest_journal = is_latest_journal.unwrap();
        assert_eq!(latest_journal.bundle_id, Some(second_bundle.bundle_id));
        assert_eq!(latest_journal.state, MeasurementMachineState::Measured);

        Ok(())
    }

    // test_report_to_revoked_bundle "promotes" a report to a
    // revoked bundle and makes sure all is well.
    #[sqlx::test]
    pub async fn test_report_to_revoked_bundle(
        pool: sqlx::PgPool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut txn = pool.begin().await?;
        let machine = create_test_machine(
            &mut txn,
            "fm100hseddco33hvlofuqvg543p6p9aj60g76q5cq491g9m9tgtf2dk0530",
            &load_topology_json("dell_r750.json"),
        )
        .await?;

        let values: Vec<PcrRegisterValue> = vec![
            PcrRegisterValue {
                pcr_register: 0,
                sha256: "aa".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 1,
                sha256: "bb".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 2,
                sha256: "cc".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 3,
                sha256: "dd".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 4,
                sha256: "ee".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 5,
                sha256: "ff".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 6,
                sha256: "gg".to_string(),
            },
        ];

        // And then make a report. At this point, we should have a:
        // - machine_id
        // - report_id
        // - profile_id
        //
        // ...which means we have what we need to promote a new bundle,
        // which will result in a second journal entry.
        let report =
            MeasurementReport::new_with_txn(&mut txn, machine.machine_id.clone(), &values).await?;
        let journals =
            MeasurementJournal::get_all_for_machine_id(&mut txn, report.machine_id.clone()).await?;
        assert_eq!(journals.len(), 1);
        let is_latest_journal =
            MeasurementJournal::get_latest_for_machine_id(&mut txn, report.machine_id.clone())
                .await?;
        assert!(is_latest_journal.is_some());
        let latest_journal = is_latest_journal.unwrap();
        assert_eq!(latest_journal.state, MeasurementMachineState::PendingBundle);
        assert_eq!(latest_journal.bundle_id, None);

        // Make a bundle with some of the values from the report,
        // and make sure everything gets updated accordingly.
        let pcr_set = parse_pcr_index_input("0-3")?;
        let bundle_partial = report
            .create_revoked_bundle_with_txn(&mut txn, &Some(pcr_set))
            .await?;
        let bundles = MeasurementBundle::get_all(&mut txn).await?;
        assert_eq!(bundles.len(), 1);
        let journals =
            MeasurementJournal::get_all_for_machine_id(&mut txn, report.machine_id.clone()).await?;
        assert_eq!(journals.len(), 2);
        let first_bundle =
            MeasurementBundle::from_id_with_txn(&mut txn, bundle_partial.bundle_id).await?;
        assert_eq!(first_bundle.pcr_values().len(), 4);
        let is_latest_journal =
            MeasurementJournal::get_latest_for_machine_id(&mut txn, report.machine_id.clone())
                .await?;
        assert!(is_latest_journal.is_some());
        let latest_journal = is_latest_journal.unwrap();
        assert_eq!(latest_journal.bundle_id, Some(first_bundle.bundle_id));
        assert_eq!(
            latest_journal.state,
            MeasurementMachineState::MeasuringFailed
        );
        Ok(())
    }
}
