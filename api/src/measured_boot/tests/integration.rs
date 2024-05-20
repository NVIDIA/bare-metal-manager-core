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
// tests/integration.rs
//
// Test a whole lifecycle of things.
///////////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use crate::measured_boot::dto::keys::MockMachineId;
    use crate::measured_boot::dto::records::{MeasurementBundleState, MeasurementMachineState};
    use crate::measured_boot::interface::common::parse_pcr_index_input;
    use crate::measured_boot::interface::common::PcrRegisterValue;
    use crate::measured_boot::model::journal::MeasurementJournal;
    use crate::measured_boot::model::machine::MockMachine;
    use crate::measured_boot::model::profile::MeasurementSystemProfile;
    use crate::measured_boot::model::report::MeasurementReport;

    // test_measured_boot_integration tests all sorts of
    // things like it was a real active environment.
    #[sqlx::test]
    pub async fn test_measured_boot_integration(
        pool: sqlx::PgPool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // A machine needs to be created for a report.
        let mut txn = pool.begin().await?;

        let dell_r750_attrs = [
            ("vendor".to_string(), "dell".to_string()),
            ("product".to_string(), "r750".to_string()),
        ]
        .into_iter()
        .collect();

        let dgx_h100_attrs = [
            ("vendor".to_string(), "nvidia".to_string()),
            ("product".to_string(), "dgx_h100".to_string()),
        ]
        .into_iter()
        .collect();

        let dgx_h100_v1_attrs = [
            ("vendor".to_string(), "nvidia".to_string()),
            ("product".to_string(), "dgx_h100".to_string()),
            ("fw".to_string(), "v1".to_string()),
        ]
        .into_iter()
        .collect();

        let princess_network = MockMachine::new_with_txn(
            &mut txn,
            MockMachineId("princess-network".to_string()),
            &dell_r750_attrs,
        )
        .await?;

        let beer_louisiana = MockMachine::new_with_txn(
            &mut txn,
            MockMachineId("beer-louisiana".to_string()),
            &dell_r750_attrs,
        )
        .await?;

        let lime_coconut = MockMachine::new_with_txn(
            &mut txn,
            MockMachineId("lime-coconut".to_string()),
            &dell_r750_attrs,
        )
        .await?;

        let slippery_lilac = MockMachine::new_with_txn(
            &mut txn,
            MockMachineId("slippery-lilac".to_string()),
            &dgx_h100_attrs,
        )
        .await?;

        let silly_salamander = MockMachine::new_with_txn(
            &mut txn,
            MockMachineId("silly-salamander".to_string()),
            &dgx_h100_v1_attrs,
        )
        .await?;

        let cat_videos = MockMachine::new_with_txn(
            &mut txn,
            MockMachineId("cat-videos".to_string()),
            &dgx_h100_v1_attrs,
        )
        .await?;

        let princess_values: Vec<PcrRegisterValue> = vec![
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
                sha256: "pppppppppppppppppp".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 4,
                sha256: "ee".to_string(),
            },
        ];

        let beer_values: Vec<PcrRegisterValue> = vec![
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
                sha256: "oooooooooooooooooo".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 4,
                sha256: "ee".to_string(),
            },
        ];

        let bad_dell_values: Vec<PcrRegisterValue> = vec![
            PcrRegisterValue {
                pcr_register: 0,
                sha256: "aa".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 1,
                sha256: "xxxxxxxxx".to_string(),
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
        ];

        let dgx_h100_values: Vec<PcrRegisterValue> = vec![
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
        ];

        let dgx_h100_v1_values: Vec<PcrRegisterValue> = vec![
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
                sha256: "pp".to_string(),
            },
        ];

        // deal with princess-network and beer-louisiana

        let dell_r750_profile =
            MeasurementSystemProfile::new_with_txn(&mut txn, None, &dell_r750_attrs).await?;

        let princess_report = MeasurementReport::new_with_txn(
            &mut txn,
            princess_network.machine_id.clone(),
            &princess_values,
        )
        .await?;
        assert_eq!(princess_report.machine_id, princess_network.machine_id);

        let princess_journal = MeasurementJournal::get_latest_for_machine_id(
            &mut txn,
            princess_network.machine_id.clone(),
        )
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

        let report = MeasurementReport::new_with_txn(
            &mut txn,
            beer_louisiana.machine_id.clone(),
            &beer_values,
        )
        .await?;
        assert_eq!(report.machine_id, beer_louisiana.machine_id);

        let beer_journal = MeasurementJournal::get_latest_for_machine_id(
            &mut txn,
            beer_louisiana.machine_id.clone(),
        )
        .await?
        .unwrap();
        assert_eq!(beer_journal.profile_id, princess_journal.profile_id);
        assert_eq!(beer_journal.state, MeasurementMachineState::PendingBundle);
        assert_eq!(beer_journal.bundle_id, None);

        let lime_report = MeasurementReport::new_with_txn(
            &mut txn,
            lime_coconut.machine_id.clone(),
            &bad_dell_values,
        )
        .await?;
        assert_eq!(lime_report.machine_id, lime_coconut.machine_id);

        let lime_journal = MeasurementJournal::get_latest_for_machine_id(
            &mut txn,
            lime_coconut.machine_id.clone(),
        )
        .await?
        .unwrap();
        assert_eq!(beer_journal.profile_id, lime_journal.profile_id);
        assert_eq!(lime_journal.state, MeasurementMachineState::PendingBundle);

        // and now deal with slippery-lilac
        let report = MeasurementReport::new_with_txn(
            &mut txn,
            slippery_lilac.machine_id.clone(),
            &dgx_h100_values,
        )
        .await?;
        assert_eq!(report.machine_id, slippery_lilac.machine_id);

        let slippery_profile = MeasurementSystemProfile::load_from_attrs(&mut txn, &dgx_h100_attrs)
            .await?
            .unwrap();

        let slippery_journal = MeasurementJournal::get_latest_for_machine_id(
            &mut txn,
            slippery_lilac.machine_id.clone(),
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
        let report = MeasurementReport::new_with_txn(
            &mut txn,
            silly_salamander.machine_id.clone(),
            &dgx_h100_v1_values,
        )
        .await?;
        assert_eq!(report.machine_id, silly_salamander.machine_id);

        let cat_report = MeasurementReport::new_with_txn(
            &mut txn,
            cat_videos.machine_id.clone(),
            &dgx_h100_v1_values,
        )
        .await?;
        assert_eq!(cat_report.machine_id, cat_videos.machine_id);

        let silly_journal = MeasurementJournal::get_latest_for_machine_id(
            &mut txn,
            silly_salamander.machine_id.clone(),
        )
        .await?
        .unwrap();

        let cat_journal =
            MeasurementJournal::get_latest_for_machine_id(&mut txn, cat_videos.machine_id.clone())
                .await?
                .unwrap();

        assert_eq!(silly_journal.profile_id, cat_journal.profile_id);
        assert_eq!(silly_journal.state, MeasurementMachineState::PendingBundle);
        assert_eq!(silly_journal.state, cat_journal.state);

        let pcr_set = parse_pcr_index_input("0-2,4")?;
        let bundle = princess_report
            .create_active_bundle_with_txn(&mut txn, &Some(pcr_set))
            .await?;
        assert_eq!(bundle.pcr_values().len(), 4);
        assert_eq!(bundle.state, MeasurementBundleState::Active);

        assert_eq!(
            MeasurementMachineState::Measured,
            MeasurementJournal::get_latest_for_machine_id(
                &mut txn,
                princess_network.machine_id.clone()
            )
            .await?
            .unwrap()
            .state
        );

        assert_eq!(
            MeasurementMachineState::Measured,
            MeasurementJournal::get_latest_for_machine_id(
                &mut txn,
                beer_louisiana.machine_id.clone()
            )
            .await?
            .unwrap()
            .state
        );

        assert_eq!(
            MeasurementMachineState::PendingBundle,
            MeasurementJournal::get_latest_for_machine_id(
                &mut txn,
                lime_coconut.machine_id.clone()
            )
            .await?
            .unwrap()
            .state
        );

        assert_eq!(
            MeasurementMachineState::PendingBundle,
            MeasurementJournal::get_latest_for_machine_id(
                &mut txn,
                slippery_lilac.machine_id.clone()
            )
            .await?
            .unwrap()
            .state
        );

        assert_eq!(
            MeasurementMachineState::PendingBundle,
            MeasurementJournal::get_latest_for_machine_id(
                &mut txn,
                silly_salamander.machine_id.clone()
            )
            .await?
            .unwrap()
            .state
        );

        assert_eq!(
            MeasurementMachineState::PendingBundle,
            MeasurementJournal::get_latest_for_machine_id(&mut txn, cat_videos.machine_id.clone())
                .await?
                .unwrap()
                .state
        );

        let pcr_set = parse_pcr_index_input("1")?;
        let bundle = lime_report
            .create_revoked_bundle_with_txn(&mut txn, &Some(pcr_set))
            .await?;
        assert_eq!(bundle.pcr_values().len(), 1);
        assert_eq!(bundle.state, MeasurementBundleState::Revoked);

        assert_eq!(
            MeasurementMachineState::Measured,
            MeasurementJournal::get_latest_for_machine_id(
                &mut txn,
                princess_network.machine_id.clone()
            )
            .await?
            .unwrap()
            .state
        );

        assert_eq!(
            MeasurementMachineState::Measured,
            MeasurementJournal::get_latest_for_machine_id(
                &mut txn,
                beer_louisiana.machine_id.clone()
            )
            .await?
            .unwrap()
            .state
        );

        assert_eq!(
            MeasurementMachineState::MeasuringFailed,
            MeasurementJournal::get_latest_for_machine_id(
                &mut txn,
                lime_coconut.machine_id.clone()
            )
            .await?
            .unwrap()
            .state
        );

        assert_eq!(
            MeasurementMachineState::PendingBundle,
            MeasurementJournal::get_latest_for_machine_id(
                &mut txn,
                slippery_lilac.machine_id.clone()
            )
            .await?
            .unwrap()
            .state
        );

        assert_eq!(
            MeasurementMachineState::PendingBundle,
            MeasurementJournal::get_latest_for_machine_id(
                &mut txn,
                silly_salamander.machine_id.clone()
            )
            .await?
            .unwrap()
            .state
        );

        assert_eq!(
            MeasurementMachineState::PendingBundle,
            MeasurementJournal::get_latest_for_machine_id(&mut txn, cat_videos.machine_id.clone())
                .await?
                .unwrap()
                .state
        );

        let bundle = cat_report
            .create_active_bundle_with_txn(&mut txn, &None)
            .await?;
        assert_eq!(bundle.pcr_values().len(), 5);
        assert_eq!(bundle.state, MeasurementBundleState::Active);

        assert_eq!(
            MeasurementMachineState::Measured,
            MeasurementJournal::get_latest_for_machine_id(
                &mut txn,
                princess_network.machine_id.clone()
            )
            .await?
            .unwrap()
            .state
        );

        assert_eq!(
            MeasurementMachineState::Measured,
            MeasurementJournal::get_latest_for_machine_id(
                &mut txn,
                beer_louisiana.machine_id.clone()
            )
            .await?
            .unwrap()
            .state
        );

        assert_eq!(
            MeasurementMachineState::MeasuringFailed,
            MeasurementJournal::get_latest_for_machine_id(
                &mut txn,
                lime_coconut.machine_id.clone()
            )
            .await?
            .unwrap()
            .state
        );

        assert_eq!(
            MeasurementMachineState::PendingBundle,
            MeasurementJournal::get_latest_for_machine_id(
                &mut txn,
                slippery_lilac.machine_id.clone()
            )
            .await?
            .unwrap()
            .state
        );

        assert_eq!(
            MeasurementMachineState::Measured,
            MeasurementJournal::get_latest_for_machine_id(
                &mut txn,
                silly_salamander.machine_id.clone()
            )
            .await?
            .unwrap()
            .state
        );

        assert_eq!(
            MeasurementMachineState::Measured,
            MeasurementJournal::get_latest_for_machine_id(&mut txn, cat_videos.machine_id.clone())
                .await?
                .unwrap()
                .state
        );

        Ok(())
    }
}
