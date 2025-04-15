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

/*!
 *  RPC handler tests for measured boot.
*/

#[cfg(test)]
mod tests {
    use crate::db::machine_topology::MachineTopology;
    use crate::measured_boot::db;
    use crate::measured_boot::rpc::bundle;
    use crate::measured_boot::rpc::journal;
    use crate::measured_boot::rpc::machine;
    use crate::measured_boot::rpc::profile;
    use crate::measured_boot::rpc::report;
    use crate::measured_boot::rpc::site;
    use crate::measured_boot::tests::common::{create_test_machine, load_topology_json};
    use crate::model::machine::ManagedHostState;
    use crate::model::metadata::Metadata;
    use ::measured_boot::pcr::PcrRegisterValue;
    use ::measured_boot::records::MeasurementApprovedMachineRecord;
    use forge_uuid::machine::MachineId;
    use forge_uuid::measured_boot::TrustedMachineId;
    use rpc::protos::measured_boot as mbrpc;
    use std::str::FromStr;

    // test_measurement_system_profiles is used to test all of the different
    // API handler functions that work with measured boot system profiles,
    // going through the steps of making profiles, making sure they can
    // be read back (via show/list), modified (via update/delete), etc.
    #[crate::sqlx_test]
    pub async fn test_measurement_system_profiles(
        db_conn: sqlx::PgPool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Create a system profile and make sure it works.
        //////////////////////////////////////////////////
        let req = mbrpc::CreateMeasurementSystemProfileRequest {
            name: Some(String::from("test-profile")),
            vendor: String::from("Dell, Inc."),
            product: String::from("PowerEdge R750"),
            extra_attrs: vec![],
        };

        let resp = profile::handle_create_system_measurement_profile(&db_conn, &req).await?;
        assert!(resp.system_profile.is_some());
        let created_profile = resp.system_profile.unwrap();
        assert_eq!(created_profile.name, String::from("test-profile"));

        // And now fetch the first back by ID and make sure it works.
        /////////////////////////////////////////////////////////////
        let req = mbrpc::ShowMeasurementSystemProfileRequest {
            selector: Some(
                mbrpc::show_measurement_system_profile_request::Selector::ProfileId(
                    created_profile.profile_id.as_ref().unwrap().clone(),
                ),
            ),
        };

        let resp = profile::handle_show_measurement_system_profile(&db_conn, &req).await?;
        assert!(resp.system_profile.is_some());
        let read_profile_by_id = resp.system_profile.unwrap();
        assert_eq!(read_profile_by_id.profile_id, created_profile.profile_id);
        assert_eq!(read_profile_by_id.name, created_profile.name);

        // And now fetch it back by name and make sure it works.
        ////////////////////////////////////////////////////////
        let req = mbrpc::ShowMeasurementSystemProfileRequest {
            selector: Some(
                mbrpc::show_measurement_system_profile_request::Selector::ProfileName(
                    created_profile.name.clone(),
                ),
            ),
        };

        let resp = profile::handle_show_measurement_system_profile(&db_conn, &req).await?;
        assert!(resp.system_profile.is_some());
        let read_profile_by_name = resp.system_profile.unwrap();
        assert_eq!(read_profile_by_name.profile_id, created_profile.profile_id);
        assert_eq!(read_profile_by_name.name, created_profile.name);

        // And now show all and make sure the one returned is the right one.
        /////////////////////////////////////////////////////////////////////
        let req = mbrpc::ShowMeasurementSystemProfilesRequest {};
        let resp = profile::handle_show_measurement_system_profiles(&db_conn, &req).await?;
        assert_eq!(1, resp.system_profiles.len());
        let first_profile = &resp.system_profiles[0];
        assert_eq!(first_profile.profile_id, created_profile.profile_id);
        assert_eq!(first_profile.name, created_profile.name);

        // And make sure list all works also.
        /////////////////////////////////////
        let req = mbrpc::ListMeasurementSystemProfilesRequest {};
        let resp = profile::handle_list_measurement_system_profiles(&db_conn, &req).await?;
        assert_eq!(1, resp.system_profiles.len());
        let first_profile = &resp.system_profiles[0];
        assert_eq!(first_profile.profile_id, created_profile.profile_id);
        assert_eq!(first_profile.name, created_profile.name);

        // And make sure rename works.
        //////////////////////////////
        let req = mbrpc::RenameMeasurementSystemProfileRequest {
            new_profile_name: String::from("test-renamed-profile"),
            selector: Some(
                mbrpc::rename_measurement_system_profile_request::Selector::ProfileName(
                    created_profile.name.clone(),
                ),
            ),
        };
        let resp = profile::handle_rename_measurement_system_profile(&db_conn, &req).await?;
        assert!(resp.profile.is_some());
        let renamed_profile = resp.profile.unwrap();

        // ..and now for the moment of truth.. same profile ID, different name?
        assert_eq!(renamed_profile.profile_id, created_profile.profile_id);
        assert_eq!(renamed_profile.name, String::from("test-renamed-profile"));

        // Create a second system profile and make sure it works.
        //////////////////////////////////////////////////
        let req = mbrpc::CreateMeasurementSystemProfileRequest {
            name: Some(String::from("test-profile-2")),
            vendor: String::from("Lenovo"),
            product: String::from("ThinkSystem SR670 V2"),
            extra_attrs: vec![mbrpc::KvPair {
                key: String::from("bios_version"),
                value: String::from("U8E122J-1.51"),
            }],
        };
        let resp = profile::handle_create_system_measurement_profile(&db_conn, &req).await?;
        assert!(resp.system_profile.is_some());
        let created_profile2 = resp.system_profile.unwrap();
        assert_eq!(created_profile2.name, String::from("test-profile-2"));

        // ..and lets delete the first.
        let req = mbrpc::DeleteMeasurementSystemProfileRequest {
            selector: Some(
                mbrpc::delete_measurement_system_profile_request::Selector::ProfileName(
                    renamed_profile.name.clone(),
                ),
            ),
        };
        let resp = profile::handle_delete_measurement_system_profile(&db_conn, &req).await?;
        assert!(resp.system_profile.is_some());
        let deleted_profile_by_name = resp.system_profile.unwrap();
        assert_eq!(
            deleted_profile_by_name.profile_id,
            created_profile.profile_id
        );

        // And make sure list all just shows
        // the other profile that was made.
        /////////////////////////////////////
        let req = mbrpc::ListMeasurementSystemProfilesRequest {};
        let resp = profile::handle_list_measurement_system_profiles(&db_conn, &req).await?;
        assert_eq!(1, resp.system_profiles.len());
        let second_profile = &resp.system_profiles[0];
        assert_eq!(second_profile.profile_id, created_profile2.profile_id);
        assert_eq!(second_profile.name, created_profile2.name);

        // Basic profile-specific machine and bundle checks.
        ////////////////////////////////////////////////////

        // For the machine part, we need to make a machine
        // and actually have it send measurements, so do all
        // of that here.
        let lenovo_sr670_topology = load_topology_json("lenovo_sr670.json");

        // princess-network
        let mut txn = db_conn.begin().await?;
        let princess_network = create_test_machine(
            &mut txn,
            "fm100hseddco33hvlofuqvg543p6p9aj60g76q5cq491g9m9tgtf2dk0530",
            &lenovo_sr670_topology,
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
        ];

        let princess_report =
            db::report::new_with_txn(&mut txn, princess_network.machine_id, &princess_values)
                .await?;
        assert_eq!(princess_report.machine_id, princess_network.machine_id);
        txn.commit().await?;

        // One machine!
        let req = mbrpc::ListMeasurementSystemProfileMachinesRequest {
            selector: Some(
                mbrpc::list_measurement_system_profile_machines_request::Selector::ProfileId(
                    created_profile2.profile_id.as_ref().unwrap().clone(),
                ),
            ),
        };
        let resp = profile::handle_list_measurement_system_profile_machines(&db_conn, &req).await?;
        assert_eq!(1, resp.machine_ids.len());
        assert_eq!(princess_network.machine_id.to_string(), resp.machine_ids[0]);

        // No bundles though.
        let req = mbrpc::ListMeasurementSystemProfileBundlesRequest {
            selector: Some(
                mbrpc::list_measurement_system_profile_bundles_request::Selector::ProfileId(
                    created_profile2.profile_id.as_ref().unwrap().clone(),
                ),
            ),
        };
        let resp = profile::handle_list_measurement_system_profile_bundles(&db_conn, &req).await?;
        assert_eq!(0, resp.bundle_ids.len());

        // And now try to delete the second one by ID,
        // which should fail, since there is corresponding
        // journal data referencing the profile.
        let req = mbrpc::DeleteMeasurementSystemProfileRequest {
            selector: Some(
                mbrpc::delete_measurement_system_profile_request::Selector::ProfileId(
                    created_profile2.profile_id.as_ref().unwrap().clone(),
                ),
            ),
        };
        let resp = profile::handle_delete_measurement_system_profile(&db_conn, &req).await;
        assert!(resp.is_err());
        Ok(())
    }

    // test_machines is used to test all of the different API
    // handler functions that work with measured boot machines (show,
    // list, attest, etc).
    #[crate::sqlx_test]
    pub async fn test_machines(db_conn: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
        // First, lets make a machine behind the scenes.
        let lenovo_sr670_topology = load_topology_json("lenovo_sr670.json");
        let mut txn = db_conn.begin().await?;
        let princess_network = create_test_machine(
            &mut txn,
            "fm100hseddco33hvlofuqvg543p6p9aj60g76q5cq491g9m9tgtf2dk0530",
            &lenovo_sr670_topology,
        )
        .await?;
        txn.commit().await?;

        // Now lets make sure the show(id) call works.
        let req = mbrpc::ShowCandidateMachineRequest {
            selector: Some(mbrpc::show_candidate_machine_request::Selector::MachineId(
                princess_network.machine_id.to_string(),
            )),
        };
        let resp = machine::handle_show_candidate_machine(&db_conn, &req).await?;
        assert!(resp.machine.is_some());
        let machine = resp.machine.unwrap();
        assert_eq!(machine.machine_id, princess_network.machine_id.to_string());

        // And show all works.
        let req = mbrpc::ShowCandidateMachinesRequest {};
        let resp = machine::handle_show_candidate_machines(&db_conn, &req).await?;
        assert_eq!(1, resp.machines.len());
        let machine = &resp.machines[0];
        assert_eq!(machine.machine_id, princess_network.machine_id.to_string());

        // And list all works.
        let req = mbrpc::ListCandidateMachinesRequest {};
        let resp = machine::handle_list_candidate_machines(&db_conn, &req).await?;
        assert_eq!(1, resp.machines.len());
        let machine = &resp.machines[0];
        assert_eq!(machine.machine_id, princess_network.machine_id.to_string());

        // And that attest works.
        let pcr_values: Vec<PcrRegisterValue> = vec![
            PcrRegisterValue {
                pcr_register: 0,
                sha256: "aa".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 1,
                sha256: "bb".to_string(),
            },
        ];
        let req = mbrpc::AttestCandidateMachineRequest {
            machine_id: princess_network.machine_id.to_string(),
            pcr_values: PcrRegisterValue::to_pb_vec(&pcr_values),
        };

        // And that attestation resulted in..

        // - A report.
        let resp = machine::handle_attest_candidate_machine(&db_conn, &req).await?;
        assert!(resp.report.is_some());
        let report = resp.report.unwrap();
        assert_eq!(report.machine_id, princess_network.machine_id.to_string());
        assert_eq!(2, report.values.len());

        // - A profile (and that the profile is wired to the machine)
        let req = mbrpc::ShowMeasurementSystemProfilesRequest {};
        let resp = profile::handle_show_measurement_system_profiles(&db_conn, &req).await?;
        assert_eq!(1, resp.system_profiles.len());
        let profile = &resp.system_profiles[0];
        let req = mbrpc::ListMeasurementSystemProfileMachinesRequest {
            selector: Some(
                mbrpc::list_measurement_system_profile_machines_request::Selector::ProfileId(
                    profile.profile_id.as_ref().unwrap().clone(),
                ),
            ),
        };
        let resp = profile::handle_list_measurement_system_profile_machines(&db_conn, &req).await?;
        assert_eq!(1, resp.machine_ids.len());
        assert_eq!(princess_network.machine_id.to_string(), resp.machine_ids[0]);

        // - A journal entry (with the correct mappings).
        let req = mbrpc::ShowMeasurementJournalsRequest {};
        let resp = journal::handle_show_measurement_journals(&db_conn, &req).await?;
        assert_eq!(1, resp.journals.len());
        let journal = &resp.journals[0];
        assert_eq!(journal.machine_id, princess_network.machine_id.to_string());
        assert_eq!(journal.report_id, report.report_id);
        assert_eq!(journal.profile_id, profile.profile_id);
        assert_eq!(journal.bundle_id, None);

        // - No bundle (since we didn't promote one).
        let req = mbrpc::ShowMeasurementBundlesRequest {};
        let resp = bundle::handle_show_measurement_bundles(&db_conn, &req).await?;
        assert_eq!(0, resp.bundles.len());

        Ok(())
    }

    // test_measurement_reports is used to test all of the API handler
    // functions for, you guessed it, measurement reports. As with the
    // other tests, there's generally some overlap with other areas of
    // measured boot (reports + journals + machines, etc), but this is
    // for focusing specifically on the report calls.
    #[crate::sqlx_test]
    pub async fn test_measurement_reports(
        db_conn: sqlx::PgPool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // A machine is needed for sending a report, so lets inject one.
        let lenovo_sr670_topology = load_topology_json("lenovo_sr670.json");
        let mut txn = db_conn.begin().await?;
        let princess_network = create_test_machine(
            &mut txn,
            "fm100hseddco33hvlofuqvg543p6p9aj60g76q5cq491g9m9tgtf2dk0530",
            &lenovo_sr670_topology,
        )
        .await?;
        txn.commit().await?;

        let pcr_values: Vec<PcrRegisterValue> = vec![
            PcrRegisterValue {
                pcr_register: 0,
                sha256: "aa".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 1,
                sha256: "bb".to_string(),
            },
        ];

        // Make the report.
        let req = mbrpc::CreateMeasurementReportRequest {
            machine_id: princess_network.machine_id.to_string(),
            pcr_values: PcrRegisterValue::to_pb_vec(&pcr_values),
        };
        let result = report::handle_create_measurement_report(&db_conn, &req).await;
        assert!(result.is_ok());
        let resp = result.unwrap();
        assert!(resp.report.is_some());
        let report = resp.report.unwrap();

        // Make sure a profile was created (and wired to the machine).
        let req = mbrpc::ShowMeasurementSystemProfilesRequest {};
        let resp = profile::handle_show_measurement_system_profiles(&db_conn, &req).await?;
        assert_eq!(1, resp.system_profiles.len());
        let profile = &resp.system_profiles[0];
        let req = mbrpc::ListMeasurementSystemProfileMachinesRequest {
            selector: Some(
                mbrpc::list_measurement_system_profile_machines_request::Selector::ProfileId(
                    profile.profile_id.as_ref().unwrap().clone(),
                ),
            ),
        };
        let resp = profile::handle_list_measurement_system_profile_machines(&db_conn, &req).await?;
        assert_eq!(1, resp.machine_ids.len());
        assert_eq!(princess_network.machine_id.to_string(), resp.machine_ids[0]);

        // Make sure a journal entry was added.
        let req = mbrpc::ShowMeasurementJournalsRequest {};
        let resp = journal::handle_show_measurement_journals(&db_conn, &req).await?;
        assert_eq!(1, resp.journals.len());
        let journal = &resp.journals[0];
        assert_eq!(journal.machine_id, princess_network.machine_id.to_string());
        assert_eq!(journal.report_id, report.report_id);
        assert_eq!(journal.profile_id, profile.profile_id);
        assert_eq!(journal.bundle_id, None);

        // Make sure no bundles exist.
        let req = mbrpc::ShowMeasurementBundlesRequest {};
        let resp = bundle::handle_show_measurement_bundles(&db_conn, &req).await?;
        assert_eq!(0, resp.bundles.len());

        // Now lets do a basic show for the report.
        let req = mbrpc::ShowMeasurementReportForIdRequest {
            report_id: report.report_id.clone(),
        };
        let resp = report::handle_show_measurement_report_for_id(&db_conn, &req).await?;
        assert!(resp.report.is_some());
        let read_report = resp.report.unwrap();
        assert_eq!(report.report_id, read_report.report_id);
        assert_eq!(report.machine_id, read_report.machine_id);
        assert_eq!(report.values.len(), read_report.values.len());

        // And now show all reports.
        let req = mbrpc::ShowMeasurementReportsRequest {};
        let resp = report::handle_show_measurement_reports(&db_conn, &req).await?;
        assert_eq!(1, resp.reports.len());
        let read_from_show = &resp.reports[0];
        assert_eq!(report.report_id, read_from_show.report_id);
        assert_eq!(report.machine_id, read_from_show.machine_id);
        assert_eq!(report.values.len(), read_from_show.values.len());

        // And now list all reports.
        let req = mbrpc::ListMeasurementReportRequest { selector: None };
        let resp = report::handle_list_measurement_report(&db_conn, &req).await?;
        assert_eq!(1, resp.reports.len());
        let read_from_list_all = &resp.reports[0];
        assert_eq!(report.report_id, read_from_list_all.report_id);
        assert_eq!(report.machine_id, read_from_list_all.machine_id);

        // And now show reports for our machine (which is
        // just the single report).
        let req = mbrpc::ShowMeasurementReportsForMachineRequest {
            machine_id: princess_network.machine_id.to_string(),
        };
        let resp = report::handle_show_measurement_reports_for_machine(&db_conn, &req).await?;
        assert_eq!(1, resp.reports.len());
        let read_for_machine = &resp.reports[0];
        assert_eq!(report.report_id, read_for_machine.report_id);
        assert_eq!(report.machine_id, read_for_machine.machine_id);
        assert_eq!(report.values.len(), read_for_machine.values.len());

        // And now list reports for the machine.
        let req = mbrpc::ListMeasurementReportRequest {
            selector: Some(mbrpc::list_measurement_report_request::Selector::MachineId(
                princess_network.machine_id.to_string(),
            )),
        };

        let resp = report::handle_list_measurement_report(&db_conn, &req).await?;
        assert_eq!(1, resp.reports.len());
        let read_from_list_machine = &resp.reports[0];
        assert_eq!(report.report_id, read_from_list_machine.report_id);
        assert_eq!(report.machine_id, read_from_list_machine.machine_id);

        // Now that the basic stuff is out of the way, lets try to
        // promote a report into a bundle.
        let req = mbrpc::PromoteMeasurementReportRequest {
            report_id: report.report_id.clone(),
            pcr_registers: String::from(""),
        };
        let resp = report::handle_promote_measurement_report(&db_conn, &req).await?;
        assert!(resp.bundle.is_some());
        let bundle = resp.bundle.unwrap();
        assert_eq!(bundle.profile_id, profile.profile_id);
        assert_eq!(2, bundle.values.len());
        assert_eq!(mbrpc::MeasurementBundleStatePb::Active as i32, bundle.state);

        // And make sure there is now a bundle!
        let req = mbrpc::ShowMeasurementBundlesRequest {};
        let resp = bundle::handle_show_measurement_bundles(&db_conn, &req).await?;
        assert_eq!(1, resp.bundles.len());

        // Now lets make a second revoked bundle from PCR value 0.
        let req = mbrpc::RevokeMeasurementReportRequest {
            report_id: report.report_id.clone(),
            pcr_registers: String::from("0"),
        };
        let resp = report::handle_revoke_measurement_report(&db_conn, &req).await?;
        assert!(resp.bundle.is_some());
        let bundle = resp.bundle.unwrap();
        assert_eq!(bundle.profile_id, profile.profile_id);
        assert_eq!(1, bundle.values.len());
        assert_eq!(
            mbrpc::MeasurementBundleStatePb::Revoked as i32,
            bundle.state
        );

        // And make sure there are now 2 bundles!
        let req = mbrpc::ShowMeasurementBundlesRequest {};
        let resp = bundle::handle_show_measurement_bundles(&db_conn, &req).await?;
        assert_eq!(2, resp.bundles.len());

        Ok(())
    }

    // test_measurement_journals is used to test all of the API handler
    // functions for, you guessed it, measurement journals. As with the
    // other tests, there's generally some overlap with other areas of
    // measured boot (reports + journals + machines, etc), but this is
    // for focusing specifically on the journal calls.
    #[crate::sqlx_test]
    pub async fn test_measurement_journals(
        db_conn: sqlx::PgPool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Make a machine and have it report measurements
        // so we get a journal entry.
        let lenovo_sr670_topology = load_topology_json("lenovo_sr670.json");
        let mut txn = db_conn.begin().await?;
        let princess_network = create_test_machine(
            &mut txn,
            "fm100hseddco33hvlofuqvg543p6p9aj60g76q5cq491g9m9tgtf2dk0530",
            &lenovo_sr670_topology,
        )
        .await?;
        txn.commit().await?;

        let pcr_values: Vec<PcrRegisterValue> = vec![
            PcrRegisterValue {
                pcr_register: 0,
                sha256: "aa".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 1,
                sha256: "bb".to_string(),
            },
        ];

        let req = mbrpc::CreateMeasurementReportRequest {
            machine_id: princess_network.machine_id.to_string(),
            pcr_values: PcrRegisterValue::to_pb_vec(&pcr_values),
        };
        let result = report::handle_create_measurement_report(&db_conn, &req).await;
        assert!(result.is_ok());
        let resp = result.unwrap();
        assert!(resp.report.is_some());
        let report = resp.report.unwrap();

        // And get the profile that was auto-created.
        let req = mbrpc::ShowMeasurementSystemProfilesRequest {};
        let resp = profile::handle_show_measurement_system_profiles(&db_conn, &req).await?;
        assert_eq!(1, resp.system_profiles.len());
        let profile = &resp.system_profiles[0];

        // Show all journals.
        let req = mbrpc::ShowMeasurementJournalsRequest {};
        let resp = journal::handle_show_measurement_journals(&db_conn, &req).await?;
        assert_eq!(1, resp.journals.len());
        let journal = &resp.journals[0];
        assert_eq!(journal.machine_id, princess_network.machine_id.to_string());
        assert_eq!(journal.report_id, report.report_id);
        assert_eq!(journal.profile_id, profile.profile_id);
        assert_eq!(journal.bundle_id, None);

        // Show one of the journals.
        let req = mbrpc::ShowMeasurementJournalRequest {
            selector: Some(
                mbrpc::show_measurement_journal_request::Selector::JournalId(
                    journal.journal_id.clone().unwrap(),
                ),
            ),
        };
        let resp = journal::handle_show_measurement_journal(&db_conn, &req).await?;
        assert!(resp.journal.is_some());
        let same_journal = resp.journal.unwrap();
        assert_eq!(journal.machine_id, same_journal.machine_id);
        assert_eq!(journal.report_id, same_journal.report_id);
        assert_eq!(journal.profile_id, same_journal.profile_id);
        assert_eq!(journal.bundle_id, same_journal.bundle_id);

        // List all journals.
        let req = mbrpc::ListMeasurementJournalRequest { selector: None };
        let resp = journal::handle_list_measurement_journal(&db_conn, &req).await?;
        assert_eq!(1, resp.journals.len());

        // List all journals for the machine.
        let req = mbrpc::ListMeasurementJournalRequest {
            selector: Some(
                mbrpc::list_measurement_journal_request::Selector::MachineId(
                    princess_network.machine_id.to_string(),
                ),
            ),
        };
        let resp = journal::handle_list_measurement_journal(&db_conn, &req).await?;
        assert_eq!(1, resp.journals.len());

        Ok(())
    }

    // test_measurement_bundles is used to test all of the API handler
    // functions for, you guessed it, measurement bundles. As with the
    // other tests, there's generally some overlap with other areas of
    // measured boot (reports + journals + machines, etc), but this is
    // for focusing specifically on the bundle calls.
    #[crate::sqlx_test]
    pub async fn test_measurement_bundles(
        db_conn: sqlx::PgPool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // A bundle needs a profile first, so make a profile.
        let req = mbrpc::CreateMeasurementSystemProfileRequest {
            name: Some(String::from("test-profile-2")),
            vendor: String::from("Lenovo"),
            product: String::from("ThinkSystem SR670 V2"),
            extra_attrs: vec![mbrpc::KvPair {
                key: String::from("bios_version"),
                value: String::from("U8E122J-1.51"),
            }],
        };
        let resp = profile::handle_create_system_measurement_profile(&db_conn, &req).await?;
        assert!(resp.system_profile.is_some());
        let profile = resp.system_profile.unwrap();
        assert_eq!(profile.name, String::from("test-profile-2"));

        // Create a bundle
        let pcr_values: Vec<PcrRegisterValue> = vec![
            PcrRegisterValue {
                pcr_register: 0,
                sha256: "aa".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 1,
                sha256: "bb".to_string(),
            },
        ];
        let req = mbrpc::CreateMeasurementBundleRequest {
            name: Some(String::from("test-bundle")),
            profile_id: profile.profile_id,
            pcr_values: PcrRegisterValue::to_pb_vec(&pcr_values),
            state: mbrpc::MeasurementBundleStatePb::Active.into(),
        };
        let resp = bundle::handle_create_measurement_bundle(&db_conn, &req).await?;
        assert!(resp.bundle.is_some());
        let bundle = resp.bundle.unwrap();
        assert_eq!(bundle.name, String::from("test-bundle"));
        assert_eq!(bundle.values.len(), pcr_values.len());
        assert_eq!(bundle.state, mbrpc::MeasurementBundleStatePb::Active as i32,);

        // Rename it
        let req = mbrpc::RenameMeasurementBundleRequest {
            new_bundle_name: String::from("renamed-bundle"),
            selector: Some(
                mbrpc::rename_measurement_bundle_request::Selector::BundleName(bundle.name.clone()),
            ),
        };
        let resp = bundle::handle_rename_measurement_bundle(&db_conn, &req).await?;
        assert!(resp.bundle.is_some());
        let renamed_bundle = resp.bundle.unwrap();
        assert_eq!(renamed_bundle.name, String::from("renamed-bundle"));
        assert_eq!(renamed_bundle.bundle_id, bundle.bundle_id);

        // Show the bundle. Check by bundle ID and bundle name.
        let req = mbrpc::ShowMeasurementBundleRequest {
            selector: Some(mbrpc::show_measurement_bundle_request::Selector::BundleId(
                renamed_bundle.bundle_id.unwrap(),
            )),
        };
        let resp = bundle::handle_show_measurement_bundle(&db_conn, &req).await?;
        assert!(resp.bundle.is_some());
        let bundle_by_id = resp.bundle.unwrap();
        assert_eq!(bundle_by_id.name, String::from("renamed-bundle"));
        assert_eq!(bundle_by_id.bundle_id, bundle.bundle_id);

        let req = mbrpc::ShowMeasurementBundleRequest {
            selector: Some(
                mbrpc::show_measurement_bundle_request::Selector::BundleName(
                    renamed_bundle.name.clone(),
                ),
            ),
        };
        let resp = bundle::handle_show_measurement_bundle(&db_conn, &req).await?;
        assert!(resp.bundle.is_some());
        let bundle_by_name = resp.bundle.unwrap();
        assert_eq!(bundle_by_name.name, String::from("renamed-bundle"));
        assert_eq!(bundle_by_name.bundle_id, bundle.bundle_id);

        // Show all
        let req = mbrpc::ShowMeasurementBundlesRequest {};
        let resp = bundle::handle_show_measurement_bundles(&db_conn, &req).await?;
        assert_eq!(1, resp.bundles.len());
        let bundle_by_all = &resp.bundles[0];
        assert_eq!(bundle_by_all.name, String::from("renamed-bundle"));
        assert_eq!(bundle_by_all.bundle_id, bundle.bundle_id);

        // List all
        let req = mbrpc::ListMeasurementBundlesRequest {};
        let resp = bundle::handle_list_measurement_bundles(&db_conn, &req).await?;
        assert_eq!(1, resp.bundles.len());
        let bundle_by_list = &resp.bundles[0];
        assert_eq!(bundle_by_list.name, String::from("renamed-bundle"));
        assert_eq!(bundle_by_list.bundle_id, bundle.bundle_id);

        // List machines (for which there are none).
        let req = mbrpc::ListMeasurementBundleMachinesRequest {
            selector: Some(
                mbrpc::list_measurement_bundle_machines_request::Selector::BundleId(
                    bundle_by_list.bundle_id.as_ref().unwrap().clone(),
                ),
            ),
        };
        let resp = bundle::handle_list_measurement_bundle_machines(&db_conn, &req).await?;
        assert_eq!(0, resp.machine_ids.len());

        // Delete it and make sure it worked.
        let req = mbrpc::DeleteMeasurementBundleRequest {
            selector: Some(
                mbrpc::delete_measurement_bundle_request::Selector::BundleId(
                    bundle_by_list.bundle_id.as_ref().unwrap().clone(),
                ),
            ),
        };
        let resp = bundle::handle_delete_measurement_bundle(&db_conn, &req).await?;
        assert!(resp.bundle.is_some());
        let deleted_bundle = resp.bundle.unwrap();
        assert_eq!(deleted_bundle.name, String::from("renamed-bundle"));
        assert_eq!(deleted_bundle.bundle_id, bundle.bundle_id);

        let req = mbrpc::ListMeasurementBundlesRequest {};
        let resp = bundle::handle_list_measurement_bundles(&db_conn, &req).await?;
        assert_eq!(0, resp.bundles.len());

        Ok(())
    }

    //  this tests the ability to find a the closest matching bundle to a
    // a given report
    #[crate::sqlx_test]
    pub async fn test_get_closest_match(
        db_conn: sqlx::PgPool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // A machine is needed for sending a report, so lets inject one.
        let lenovo_sr670_topology = load_topology_json("lenovo_sr670.json");
        let mut txn = db_conn.begin().await?;
        let princess_network = create_test_machine(
            &mut txn,
            "fm100hseddco33hvlofuqvg543p6p9aj60g76q5cq491g9m9tgtf2dk0530",
            &lenovo_sr670_topology,
        )
        .await?;
        txn.commit().await?;

        // create values for a report
        let pcr_values: Vec<PcrRegisterValue> = vec![
            PcrRegisterValue {
                pcr_register: 0,
                sha256: "d86624ca1c77f5420c4a13f3cbca22044230adaeb23f313e5f2e0c903bff522e"
                    .to_string(),
            },
            PcrRegisterValue {
                pcr_register: 1,
                sha256: "4a43aa687655d3a36a3dbec7bd48894f08f51a87f1027fdc5d325748797099c9"
                    .to_string(),
            },
            PcrRegisterValue {
                pcr_register: 2,
                sha256: "1a279c880e6b1ba9c9b0d980760f97801af3d6e84aff0cd33e4fea28e6818d7e"
                    .to_string(),
            },
            PcrRegisterValue {
                pcr_register: 3,
                sha256: "3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969"
                    .to_string(),
            },
            PcrRegisterValue {
                pcr_register: 4,
                sha256: "60dd6f85e62e1e6250f3632c918457f05f1ba88f5b2fe55554d012c5a70d2ca2"
                    .to_string(),
            },
            PcrRegisterValue {
                pcr_register: 5,
                sha256: "f2023fe2729073c1b3c175bd4e6206883661ad21c923bca43c20fc8b503ade09"
                    .to_string(),
            },
            PcrRegisterValue {
                pcr_register: 6,
                sha256: "3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969"
                    .to_string(),
            },
            PcrRegisterValue {
                pcr_register: 7,
                sha256: "59fc09fad43fa9527c3366b820d1f9068392e731992895a4f9654785c300128f"
                    .to_string(),
            },
            PcrRegisterValue {
                pcr_register: 8,
                sha256: "0000000000000000000000000000000000000000000000000000000000000000"
                    .to_string(),
            },
            PcrRegisterValue {
                pcr_register: 9,
                sha256: "d3cab16f23b70f856f44efdb01dd2fdf96d3c80c56c5ebef25077347691e3227"
                    .to_string(),
            },
            PcrRegisterValue {
                pcr_register: 10,
                sha256: "60a8e8fec245e25100b86608a7cf2a284e22db5f90ec49dbe7a1725affef155b"
                    .to_string(),
            },
            PcrRegisterValue {
                pcr_register: 11,
                sha256: "0a41386a6ec4387d5a41229a28e6369cd75325082371e3e18e6338dcb578c783"
                    .to_string(),
            },
        ];

        // Make the report.
        let req = mbrpc::CreateMeasurementReportRequest {
            machine_id: princess_network.machine_id.to_string(),
            pcr_values: PcrRegisterValue::to_pb_vec(&pcr_values),
        };
        let result = report::handle_create_measurement_report(&db_conn, &req).await;
        assert!(result.is_ok());
        let resp = result.unwrap();
        assert!(resp.report.is_some());
        let report = resp.report.unwrap();

        // Make sure a profile was created (and wired to the machine).
        let req = mbrpc::ShowMeasurementSystemProfilesRequest {};
        let resp = profile::handle_show_measurement_system_profiles(&db_conn, &req).await?;
        assert_eq!(1, resp.system_profiles.len());
        let profile = &resp.system_profiles[0];
        let req = mbrpc::ListMeasurementSystemProfileMachinesRequest {
            selector: Some(
                mbrpc::list_measurement_system_profile_machines_request::Selector::ProfileId(
                    profile.profile_id.as_ref().unwrap().clone(),
                ),
            ),
        };
        let resp = profile::handle_list_measurement_system_profile_machines(&db_conn, &req).await?;
        assert_eq!(1, resp.machine_ids.len());
        assert_eq!(princess_network.machine_id.to_string(), resp.machine_ids[0]);

        // Create four partial bundles + 1 full bundle

        // 3 elements, 3 matching
        let pcr_values: Vec<PcrRegisterValue> = vec![
            PcrRegisterValue {
                pcr_register: 3,
                sha256: "3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969"
                    .to_string(),
            },
            PcrRegisterValue {
                pcr_register: 9,
                sha256: "d3cab16f23b70f856f44efdb01dd2fdf96d3c80c56c5ebef25077347691e3227"
                    .to_string(),
            },
            PcrRegisterValue {
                pcr_register: 11,
                sha256: "0a41386a6ec4387d5a41229a28e6369cd75325082371e3e18e6338dcb578c783"
                    .to_string(),
            },
        ];
        let req = mbrpc::CreateMeasurementBundleRequest {
            name: Some(String::from("3-elem_3m")),
            profile_id: profile.profile_id.clone(),
            pcr_values: PcrRegisterValue::to_pb_vec(&pcr_values),
            state: mbrpc::MeasurementBundleStatePb::Active.into(),
        };
        let resp = bundle::handle_create_measurement_bundle(&db_conn, &req).await?;
        assert!(resp.bundle.is_some());
        let bundle = resp.bundle.unwrap();
        assert_eq!(bundle.name, String::from("3-elem_3m"));
        assert_eq!(bundle.values.len(), pcr_values.len());
        assert_eq!(bundle.state, mbrpc::MeasurementBundleStatePb::Active as i32,);

        // 5 elements, 2 matching
        let pcr_values: Vec<PcrRegisterValue> = vec![
            PcrRegisterValue {
                pcr_register: 1,
                sha256: "20".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 2,
                sha256: "1a279c880e6b1ba9c9b0d980760f97801af3d6e84aff0cd33e4fea28e6818d7e"
                    .to_string(),
            },
            PcrRegisterValue {
                pcr_register: 3,
                sha256: "30".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 4,
                sha256: "60dd6f85e62e1e6250f3632c918457f05f1ba88f5b2fe55554d012c5a70d2ca2"
                    .to_string(),
            },
            PcrRegisterValue {
                pcr_register: 5,
                sha256: "50".to_string(),
            },
        ];
        let req = mbrpc::CreateMeasurementBundleRequest {
            name: Some(String::from("5-elem_2m")),
            profile_id: profile.profile_id.clone(),
            pcr_values: PcrRegisterValue::to_pb_vec(&pcr_values),
            state: mbrpc::MeasurementBundleStatePb::Active.into(),
        };
        let resp = bundle::handle_create_measurement_bundle(&db_conn, &req).await?;
        assert!(resp.bundle.is_some());
        let bundle = resp.bundle.unwrap();
        assert_eq!(bundle.name, String::from("5-elem_2m"));
        assert_eq!(bundle.values.len(), pcr_values.len());
        assert_eq!(bundle.state, mbrpc::MeasurementBundleStatePb::Active as i32,);

        // 5 elements, 0 matching
        let pcr_values: Vec<PcrRegisterValue> = vec![
            PcrRegisterValue {
                pcr_register: 0,
                sha256: "10".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 1,
                sha256: "20".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 2,
                sha256: "30".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 3,
                sha256: "30".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 4,
                sha256: "40".to_string(),
            },
        ];
        let req = mbrpc::CreateMeasurementBundleRequest {
            name: Some(String::from("5-elem_0m")),
            profile_id: profile.profile_id.clone(),
            pcr_values: PcrRegisterValue::to_pb_vec(&pcr_values),
            state: mbrpc::MeasurementBundleStatePb::Active.into(),
        };
        let resp = bundle::handle_create_measurement_bundle(&db_conn, &req).await?;
        assert!(resp.bundle.is_some());
        let bundle = resp.bundle.unwrap();
        assert_eq!(bundle.name, String::from("5-elem_0m"));
        assert_eq!(bundle.values.len(), pcr_values.len());
        assert_eq!(bundle.state, mbrpc::MeasurementBundleStatePb::Active as i32,);

        // 4 elements, 3 matching
        let pcr_values: Vec<PcrRegisterValue> = vec![
            PcrRegisterValue {
                pcr_register: 1,
                sha256: "20".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 3,
                sha256: "3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969"
                    .to_string(),
            },
            PcrRegisterValue {
                pcr_register: 9,
                sha256: "d3cab16f23b70f856f44efdb01dd2fdf96d3c80c56c5ebef25077347691e3227"
                    .to_string(),
            },
            PcrRegisterValue {
                pcr_register: 11,
                sha256: "0a41386a6ec4387d5a41229a28e6369cd75325082371e3e18e6338dcb578c783"
                    .to_string(),
            },
        ];
        let req = mbrpc::CreateMeasurementBundleRequest {
            name: Some(String::from("4-elem_3m")),
            profile_id: profile.profile_id.clone(),
            pcr_values: PcrRegisterValue::to_pb_vec(&pcr_values),
            state: mbrpc::MeasurementBundleStatePb::Active.into(),
        };
        let resp = bundle::handle_create_measurement_bundle(&db_conn, &req).await?;
        assert!(resp.bundle.is_some());
        let bundle = resp.bundle.unwrap();
        assert_eq!(bundle.name, String::from("4-elem_3m"));
        assert_eq!(bundle.values.len(), pcr_values.len());
        assert_eq!(bundle.state, mbrpc::MeasurementBundleStatePb::Active as i32,);

        // 3 elements, 1 matching
        let pcr_values: Vec<PcrRegisterValue> = vec![
            PcrRegisterValue {
                pcr_register: 1,
                sha256: "20".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 3,
                sha256: "40".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 6,
                sha256: "3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969"
                    .to_string(),
            },
        ];
        let req = mbrpc::CreateMeasurementBundleRequest {
            name: Some(String::from("3-elem_1m")),
            profile_id: profile.profile_id.clone(),
            pcr_values: PcrRegisterValue::to_pb_vec(&pcr_values),
            state: mbrpc::MeasurementBundleStatePb::Active.into(),
        };
        let resp = bundle::handle_create_measurement_bundle(&db_conn, &req).await?;
        assert!(resp.bundle.is_some());
        let bundle = resp.bundle.unwrap();
        assert_eq!(bundle.name, String::from("3-elem_1m"));
        assert_eq!(bundle.values.len(), pcr_values.len());
        assert_eq!(bundle.state, mbrpc::MeasurementBundleStatePb::Active as i32,);

        // test 0 - call get closest match -> error as fully matching bundle found
        let req = mbrpc::FindClosestBundleMatchRequest {
            report_id: report.report_id.clone(),
        };
        let res = bundle::handle_find_closest_match(&db_conn, &req).await;
        assert!(res.is_err());
        assert_eq!(
            &res.err().unwrap().message()[..31],
            "Fully matching bundle(s) found:"
        );

        // retire fully matching bundle
        let req = mbrpc::UpdateMeasurementBundleRequest {
            selector: Some(
                mbrpc::update_measurement_bundle_request::Selector::BundleName(
                    "3-elem_3m".to_string(),
                ),
            ),
            state: mbrpc::MeasurementBundleStatePb::Retired.into(),
        };
        let resp = bundle::handle_update_measurement_bundle(&db_conn, &req).await?;
        assert!(resp.bundle.is_some());

        // test 1 - call get closest match -> 4-elem-3m
        let req = mbrpc::FindClosestBundleMatchRequest {
            report_id: report.report_id.clone(),
        };
        let resp = bundle::handle_find_closest_match(&db_conn, &req).await?;
        assert!(resp.bundle.is_some());
        let bundle = resp.bundle.unwrap();
        assert_eq!(bundle.name, String::from("4-elem_3m"));

        // disable 4-elem-3m, match again -> 5-elem-2m
        let req = mbrpc::UpdateMeasurementBundleRequest {
            selector: Some(
                mbrpc::update_measurement_bundle_request::Selector::BundleId(
                    bundle.bundle_id.unwrap(),
                ),
            ),
            state: mbrpc::MeasurementBundleStatePb::Retired.into(),
        };
        let resp = bundle::handle_update_measurement_bundle(&db_conn, &req).await?;
        assert!(resp.bundle.is_some());

        let req = mbrpc::FindClosestBundleMatchRequest {
            report_id: report.report_id.clone(),
        };
        let resp = bundle::handle_find_closest_match(&db_conn, &req).await?;
        assert!(resp.bundle.is_some());
        let bundle = resp.bundle.unwrap();
        assert_eq!(bundle.name, String::from("5-elem_2m"));

        // disable 5-elem-2m, match again -> 3-elem-1m
        let req = mbrpc::UpdateMeasurementBundleRequest {
            selector: Some(
                mbrpc::update_measurement_bundle_request::Selector::BundleId(
                    bundle.bundle_id.unwrap(),
                ),
            ),
            state: mbrpc::MeasurementBundleStatePb::Retired.into(),
        };
        let resp = bundle::handle_update_measurement_bundle(&db_conn, &req).await?;
        assert!(resp.bundle.is_some());

        let req = mbrpc::FindClosestBundleMatchRequest {
            report_id: report.report_id.clone(),
        };
        let resp = bundle::handle_find_closest_match(&db_conn, &req).await?;
        assert!(resp.bundle.is_some());
        let bundle = resp.bundle.unwrap();
        assert_eq!(bundle.name, String::from("3-elem_1m"));

        // disable 3-elem-1m, match again -> none
        let req = mbrpc::UpdateMeasurementBundleRequest {
            selector: Some(
                mbrpc::update_measurement_bundle_request::Selector::BundleId(
                    bundle.bundle_id.unwrap(),
                ),
            ),
            state: mbrpc::MeasurementBundleStatePb::Retired.into(),
        };
        let resp = bundle::handle_update_measurement_bundle(&db_conn, &req).await?;
        assert!(resp.bundle.is_some());

        let req = mbrpc::FindClosestBundleMatchRequest {
            report_id: report.report_id.clone(),
        };
        let resp = bundle::handle_find_closest_match(&db_conn, &req).await?;
        assert!(resp.bundle.is_none());

        Ok(())
    }

    // test_measurement_site is used to test all of the API handler
    // functions for site-specific management handlers for measured
    // boot, including import/export, and management of trusted
    // machine and profile approvals.
    #[crate::sqlx_test]
    pub async fn test_measurement_site(
        db_conn: sqlx::PgPool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // First make a couple of profiles to export.
        // A bundle needs a profile first, so make a profile.
        let req = mbrpc::CreateMeasurementSystemProfileRequest {
            name: Some(String::from("test-profile")),
            vendor: String::from("Dell, Inc."),
            product: String::from("PowerEdge R750"),
            extra_attrs: vec![mbrpc::KvPair {
                key: String::from("bios_version"),
                value: String::from("1.8.2"),
            }],
        };
        let resp = profile::handle_create_system_measurement_profile(&db_conn, &req).await?;
        assert!(resp.system_profile.is_some());
        let profile1 = resp.system_profile.unwrap();

        // A bundle needs a profile first, so make a profile.
        let req = mbrpc::CreateMeasurementSystemProfileRequest {
            name: Some(String::from("test-profile-2")),
            vendor: String::from("Lenovo"),
            product: String::from("ThinkSystem SR670 V2"),
            extra_attrs: vec![mbrpc::KvPair {
                key: String::from("bios_version"),
                value: String::from("U8E122J-1.51"),
            }],
        };
        let resp = profile::handle_create_system_measurement_profile(&db_conn, &req).await?;
        assert!(resp.system_profile.is_some());
        let profile2 = resp.system_profile.unwrap();

        // And make a couple of bundles to export.
        // Create a bundle
        let pcr_values1: Vec<PcrRegisterValue> = vec![
            PcrRegisterValue {
                pcr_register: 0,
                sha256: "aa".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 1,
                sha256: "bb".to_string(),
            },
        ];

        let pcr_values2: Vec<PcrRegisterValue> = vec![
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
        ];

        let req = mbrpc::CreateMeasurementBundleRequest {
            name: Some(String::from("test-bundle")),
            profile_id: profile1.profile_id,
            pcr_values: PcrRegisterValue::to_pb_vec(&pcr_values1),
            state: mbrpc::MeasurementBundleStatePb::Active.into(),
        };
        let resp = bundle::handle_create_measurement_bundle(&db_conn, &req).await?;
        assert!(resp.bundle.is_some());
        let bundle = resp.bundle.unwrap();
        assert_eq!(bundle.name, String::from("test-bundle"));
        assert_eq!(bundle.values.len(), pcr_values1.len());
        assert_eq!(bundle.state, mbrpc::MeasurementBundleStatePb::Active as i32,);

        let req = mbrpc::CreateMeasurementBundleRequest {
            name: Some(String::from("test-bundle-2")),
            profile_id: profile2.profile_id,
            pcr_values: PcrRegisterValue::to_pb_vec(&pcr_values2),
            state: mbrpc::MeasurementBundleStatePb::Active.into(),
        };
        let resp = bundle::handle_create_measurement_bundle(&db_conn, &req).await?;
        assert!(resp.bundle.is_some());
        let bundle2 = resp.bundle.unwrap();
        assert_eq!(bundle2.name, String::from("test-bundle-2"));
        assert_eq!(bundle2.values.len(), pcr_values2.len());
        assert_eq!(
            bundle2.state,
            mbrpc::MeasurementBundleStatePb::Active as i32,
        );

        // And now do the export and make sure it looks good.
        let req = mbrpc::ExportSiteMeasurementsRequest {};
        let resp = site::handle_export_site_measurements(&db_conn, &req).await?;
        assert!(resp.model.is_some());
        let site_model = resp.model.unwrap();
        assert_eq!(2, site_model.measurement_system_profiles.len());
        assert_eq!(6, site_model.measurement_system_profiles_attrs.len());
        assert_eq!(2, site_model.measurement_bundles.len());
        assert_eq!(5, site_model.measurement_bundles_values.len());

        // Okay, so before trusted machine approvals, lets make a machine.
        let lenovo_sr670_topology = load_topology_json("lenovo_sr670.json");
        let mut txn = db_conn.begin().await?;
        let princess_network = create_test_machine(
            &mut txn,
            "fm100hseddco33hvlofuqvg543p6p9aj60g76q5cq491g9m9tgtf2dk0530",
            &lenovo_sr670_topology,
        )
        .await?;
        txn.commit().await?;

        // Now create a trusted machine approval.
        let req = mbrpc::AddMeasurementTrustedMachineRequest {
            machine_id: princess_network.machine_id.to_string(),
            approval_type: mbrpc::MeasurementApprovedTypePb::Oneshot.into(),
            pcr_registers: String::from("0-1"),
            comments: String::from(""),
        };
        let resp = site::handle_add_measurement_trusted_machine(&db_conn, &req).await?;
        assert!(resp.approval_record.is_some());
        let machine_approval = resp.approval_record.unwrap();
        assert_eq!(
            princess_network.machine_id.to_string(),
            machine_approval.machine_id
        );

        // List trusted machine approvals.
        let req = mbrpc::ListMeasurementTrustedMachinesRequest {};
        let resp = site::handle_list_measurement_trusted_machines(&db_conn, &req).await?;
        assert_eq!(1, resp.approval_records.len());

        // Now send measurements, and confirm they transitioned into a
        // bundle with the expected values. Note that these values
        // are different than the previous bundle created in this test,
        // because otherwise the machine matches them (and no auto-approvals
        // end up happening).
        let pcr_values: Vec<PcrRegisterValue> = vec![
            PcrRegisterValue {
                pcr_register: 0,
                sha256: "ww".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 1,
                sha256: "xx".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 2,
                sha256: "yy".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 3,
                sha256: "zz".to_string(),
            },
        ];

        let req = mbrpc::CreateMeasurementReportRequest {
            machine_id: princess_network.machine_id.to_string(),
            pcr_values: PcrRegisterValue::to_pb_vec(&pcr_values),
        };
        let result = report::handle_create_measurement_report(&db_conn, &req).await;
        assert!(result.is_ok());
        let resp = result.unwrap();
        assert!(resp.report.is_some());
        let report = resp.report.unwrap();
        assert_eq!(report.machine_id, princess_network.machine_id.to_string());

        // And confirm the bundle was created (there are now three bundles, since
        // the two made previously for the site export are still there also).
        let req = mbrpc::ShowMeasurementBundlesRequest {};
        let resp = bundle::handle_show_measurement_bundles(&db_conn, &req).await?;
        assert_eq!(3, resp.bundles.len());

        // And now get the latest journal record for the machine, so we can pluck out
        // the profile_id (to make a profile approval) and bundle_id (to make sure the
        // bundle looks good).
        let req = mbrpc::ListMeasurementJournalRequest {
            selector: Some(
                mbrpc::list_measurement_journal_request::Selector::MachineId(
                    princess_network.machine_id.to_string(),
                ),
            ),
        };
        let resp = journal::handle_list_measurement_journal(&db_conn, &req).await?;
        // One journal for the initial report, another journal for when it was matched with
        // the auto-promoted bundle.
        assert_eq!(2, resp.journals.len());
        let latest_journal = &resp.journals[1];
        assert!(latest_journal.bundle_id.is_some());
        assert!(latest_journal.profile_id.is_some());
        let bundle_id = latest_journal.bundle_id.as_ref().unwrap().clone();

        let req = mbrpc::ShowMeasurementBundleRequest {
            selector: Some(mbrpc::show_measurement_bundle_request::Selector::BundleId(
                bundle_id,
            )),
        };
        let resp = bundle::handle_show_measurement_bundle(&db_conn, &req).await?;
        assert!(resp.bundle.is_some());
        let auto_bundle = resp.bundle.unwrap();
        assert_eq!(2, auto_bundle.values.len());
        assert_eq!("ww".to_string(), auto_bundle.values[0].sha256);
        assert_eq!("xx".to_string(), auto_bundle.values[1].sha256);

        // And that the machine is measured.
        let req = mbrpc::ShowCandidateMachineRequest {
            selector: Some(mbrpc::show_candidate_machine_request::Selector::MachineId(
                princess_network.machine_id.to_string(),
            )),
        };
        let resp = machine::handle_show_candidate_machine(&db_conn, &req).await?;
        assert!(resp.machine.is_some());
        let machine = resp.machine.unwrap();
        assert_eq!(machine.machine_id, princess_network.machine_id.to_string());
        assert_eq!(
            machine.state,
            mbrpc::MeasurementMachineStatePb::Measured as i32
        );

        // List again, confirming the oneshot approval removed the approval.
        let req = mbrpc::ListMeasurementTrustedMachinesRequest {};
        let resp = site::handle_list_measurement_trusted_machines(&db_conn, &req).await?;
        assert_eq!(0, resp.approval_records.len());

        // Create a trusted profile approval.
        let req = mbrpc::AddMeasurementTrustedProfileRequest {
            profile_id: latest_journal.profile_id.clone(),
            approval_type: mbrpc::MeasurementApprovedTypePb::Oneshot.into(),
            pcr_registers: Some(String::from("2,3")),
            comments: None,
        };
        let resp = site::handle_add_measurement_trusted_profile(&db_conn, &req).await?;
        assert!(resp.approval_record.is_some());
        let profile_approval = resp.approval_record.unwrap();
        assert_eq!(latest_journal.profile_id, profile_approval.profile_id);

        // List trusted profile approvals.
        let req = mbrpc::ListMeasurementTrustedProfilesRequest {};
        let resp = site::handle_list_measurement_trusted_profiles(&db_conn, &req).await?;
        assert_eq!(1, resp.approval_records.len());

        // Now send measurements, and confirm they transitioned into a
        // bundle with the expected values. Note that these values
        // are different than the previous bundle created in this test,
        // because otherwise the machine matches them (and no auto-approvals
        // end up happening).
        let pcr_values: Vec<PcrRegisterValue> = vec![
            PcrRegisterValue {
                pcr_register: 0,
                sha256: "ll".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 1,
                sha256: "mm".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 2,
                sha256: "nn".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 3,
                sha256: "oo".to_string(),
            },
        ];

        let req = mbrpc::CreateMeasurementReportRequest {
            machine_id: princess_network.machine_id.to_string(),
            pcr_values: PcrRegisterValue::to_pb_vec(&pcr_values),
        };
        let result = report::handle_create_measurement_report(&db_conn, &req).await;
        assert!(result.is_ok());
        let resp = result.unwrap();
        assert!(resp.report.is_some());
        let report = resp.report.unwrap();
        assert_eq!(report.machine_id, princess_network.machine_id.to_string());

        // And confirm the bundle was created (there are now three bundles, since
        // the two made previously for the site export are still there also).
        let req = mbrpc::ShowMeasurementBundlesRequest {};
        let resp = bundle::handle_show_measurement_bundles(&db_conn, &req).await?;
        assert_eq!(4, resp.bundles.len());

        // And now get the latest journal record for the machine, so we can pluck out
        // the profile_id (to make a profile approval) and bundle_id (to make sure the
        // bundle looks good).
        let req = mbrpc::ListMeasurementJournalRequest {
            selector: Some(
                mbrpc::list_measurement_journal_request::Selector::MachineId(
                    princess_network.machine_id.to_string(),
                ),
            ),
        };
        let resp = journal::handle_list_measurement_journal(&db_conn, &req).await?;
        // One journal for the initial report, another journal for when it was matched with
        // the auto-promoted bundle. And then two more for the same thing w/ auto-profile approvals
        assert_eq!(4, resp.journals.len());
        let latest_journal = &resp.journals[3]; // grab the latest
        assert!(latest_journal.bundle_id.is_some());
        assert!(latest_journal.profile_id.is_some());
        let bundle_id = latest_journal.bundle_id.as_ref().unwrap().clone();

        let req = mbrpc::ShowMeasurementBundleRequest {
            selector: Some(mbrpc::show_measurement_bundle_request::Selector::BundleId(
                bundle_id,
            )),
        };
        let resp = bundle::handle_show_measurement_bundle(&db_conn, &req).await?;
        assert!(resp.bundle.is_some());
        let auto_bundle = resp.bundle.unwrap();
        assert_eq!(2, auto_bundle.values.len());
        assert_eq!("nn".to_string(), auto_bundle.values[0].sha256);
        assert_eq!("oo".to_string(), auto_bundle.values[1].sha256);

        // And that the machine is measured.
        let req = mbrpc::ShowCandidateMachineRequest {
            selector: Some(mbrpc::show_candidate_machine_request::Selector::MachineId(
                princess_network.machine_id.to_string(),
            )),
        };
        let resp = machine::handle_show_candidate_machine(&db_conn, &req).await?;
        assert!(resp.machine.is_some());
        let machine = resp.machine.unwrap();
        assert_eq!(machine.machine_id, princess_network.machine_id.to_string());
        assert_eq!(
            machine.state,
            mbrpc::MeasurementMachineStatePb::Measured as i32
        );

        // List again, confirming the oneshot approval removed the approval.
        let req = mbrpc::ListMeasurementTrustedProfilesRequest {};
        let resp = site::handle_list_measurement_trusted_profiles(&db_conn, &req).await?;
        assert_eq!(0, resp.approval_records.len());

        Ok(())
    }

    // test_permissive_approvals is used to make sure that
    // having a site-wide "permissive" approval of "*" works
    // as intended.
    #[crate::sqlx_test]
    pub async fn test_permissive_approvals(
        db_conn: sqlx::PgPool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Pre-flight: this should go into a more generic unit testing
        // location, but I'm putting it here for now. -Chet
        let trusted_all = TrustedMachineId::from_str("*")?;
        assert_eq!(trusted_all, TrustedMachineId::Any);
        let trusted_princess = TrustedMachineId::from_str(
            "fm100hseddco33hvlofuqvg543p6p9aj60g76q5cq491g9m9tgtf2dk0530",
        )?;
        if let TrustedMachineId::MachineId(machine_id) = trusted_princess {
            assert_eq!(
                "fm100hseddco33hvlofuqvg543p6p9aj60g76q5cq491g9m9tgtf2dk0530",
                machine_id.to_string()
            );
        };

        // First, create the permissive machine approval with "*",
        // making sure the response is as expected, including converting
        // the MeasurementApprovedMachineRecordPb back into a
        // MeasurementApprovedMachineRecord.
        let req = mbrpc::AddMeasurementTrustedMachineRequest {
            machine_id: "*".to_string(),
            approval_type: mbrpc::MeasurementApprovedTypePb::Persist.into(),
            pcr_registers: String::from("0-6,8"),
            comments: String::from(""),
        };
        let resp = site::handle_add_measurement_trusted_machine(&db_conn, &req).await?;
        assert!(resp.approval_record.is_some());
        let machine_approval =
            MeasurementApprovedMachineRecord::from_grpc(resp.approval_record.as_ref())?;
        assert_eq!("*".to_string(), machine_approval.machine_id.to_string());

        // And then re-fetch the "*" approval just to make sure
        // all of the `TrustedMachineId` stuff is working, even though
        // the above result should have been based on RETURNING *.
        let req = mbrpc::ListMeasurementTrustedMachinesRequest {};
        let resp = site::handle_list_measurement_trusted_machines(&db_conn, &req).await?;
        assert_eq!(1, resp.approval_records.len());
        let permissive_approval =
            MeasurementApprovedMachineRecord::from_grpc(Some(&resp.approval_records[0]))?;
        assert_eq!(
            permissive_approval.machine_id.to_string(),
            String::from("*")
        );

        // Now, lets create three different machines, report
        // measurements, and make sure both get Measured, which means
        // there should be resulting profiles, bundles, and journal
        // entries for both.
        let dell_r750_topology = load_topology_json("dell_r750.json");
        let lenovo_sr670_topology = load_topology_json("lenovo_sr670.json");
        let lenovo_sr670_v2_topology = load_topology_json("lenovo_sr670_v2.json");

        let mut txn = db_conn.begin().await?;
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
            &lenovo_sr670_topology,
        )
        .await?;
        // lime-coconut
        let lime_coconut = create_test_machine(
            &mut txn,
            "fm100htdekjaiocbggbkttpjnjf4i1ac9li56c0ulsef42nien02mgl66tg",
            &lenovo_sr670_v2_topology,
        )
        .await?;
        txn.commit().await?;

        // Now send for both machines.
        // TODO(chet): Just make these fixtures that I
        // can load up.
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
            PcrRegisterValue {
                pcr_register: 8,
                sha256: "ii".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 9,
                sha256: "jj".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 10,
                sha256: "kk".to_string(),
            },
        ];

        let req = mbrpc::CreateMeasurementReportRequest {
            machine_id: princess_network.machine_id.to_string(),
            pcr_values: PcrRegisterValue::to_pb_vec(&princess_values),
        };
        let result = report::handle_create_measurement_report(&db_conn, &req).await;
        assert!(result.is_ok());
        let resp = result.unwrap();
        assert!(resp.report.is_some());
        let report = resp.report.unwrap();
        assert_eq!(report.machine_id, princess_network.machine_id.to_string());

        let beer_values: Vec<PcrRegisterValue> = vec![
            PcrRegisterValue {
                pcr_register: 0,
                sha256: "pp".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 1,
                sha256: "qq".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 2,
                sha256: "rr".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 3,
                sha256: "ss".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 4,
                sha256: "tt".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 5,
                sha256: "uu".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 6,
                sha256: "vv".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 7,
                sha256: "ww".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 8,
                sha256: "xx".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 9,
                sha256: "yy".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 10,
                sha256: "zz".to_string(),
            },
        ];

        let req = mbrpc::CreateMeasurementReportRequest {
            machine_id: beer_louisiana.machine_id.to_string(),
            pcr_values: PcrRegisterValue::to_pb_vec(&beer_values),
        };
        let result = report::handle_create_measurement_report(&db_conn, &req).await;
        assert!(result.is_ok());
        let resp = result.unwrap();
        assert!(resp.report.is_some());
        let report = resp.report.unwrap();
        assert_eq!(report.machine_id, beer_louisiana.machine_id.to_string());

        let lime_values: Vec<PcrRegisterValue> = vec![
            PcrRegisterValue {
                pcr_register: 0,
                sha256: "kk".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 1,
                sha256: "ll".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 2,
                sha256: "mm".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 3,
                sha256: "nn".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 4,
                sha256: "oo".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 5,
                sha256: "pp".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 6,
                sha256: "qq".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 7,
                sha256: "rr".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 8,
                sha256: "ss".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 9,
                sha256: "tt".to_string(),
            },
            PcrRegisterValue {
                pcr_register: 10,
                sha256: "uu".to_string(),
            },
        ];

        let req = mbrpc::CreateMeasurementReportRequest {
            machine_id: lime_coconut.machine_id.to_string(),
            pcr_values: PcrRegisterValue::to_pb_vec(&lime_values),
        };
        let result = report::handle_create_measurement_report(&db_conn, &req).await;
        assert!(result.is_ok());
        let resp = result.unwrap();
        assert!(resp.report.is_some());
        let report = resp.report.unwrap();
        assert_eq!(report.machine_id, lime_coconut.machine_id.to_string());

        // And confirm bundles were created for both. index[0] will contain the first
        // bundle, for princess-network. index[1] will contain the second bundle, for
        // beer-louisiana.
        let req = mbrpc::ShowMeasurementBundlesRequest {};
        let resp = bundle::handle_show_measurement_bundles(&db_conn, &req).await?;
        assert_eq!(3, resp.bundles.len());

        // bundles[0] is the princess bundle.
        let princess_bundle = &resp.bundles[0];
        assert_eq!(8, princess_bundle.values.len());
        assert_eq!("aa".to_string(), princess_bundle.values[0].sha256);
        assert_eq!("ii".to_string(), princess_bundle.values[7].sha256);

        // bundles[1] is the beer bundle.
        let beer_bundle = &resp.bundles[1];
        assert_eq!(8, beer_bundle.values.len());
        assert_eq!("pp".to_string(), beer_bundle.values[0].sha256);
        assert_eq!("xx".to_string(), beer_bundle.values[7].sha256);

        // bundles[2] is the lime bundle.
        let lime_bundle = &resp.bundles[2];
        assert_eq!(8, lime_bundle.values.len());
        assert_eq!("kk".to_string(), lime_bundle.values[0].sha256);
        assert_eq!("ss".to_string(), lime_bundle.values[7].sha256);

        // And make sure the machines are measured.
        let req = mbrpc::ShowCandidateMachineRequest {
            selector: Some(mbrpc::show_candidate_machine_request::Selector::MachineId(
                princess_network.machine_id.to_string(),
            )),
        };
        let resp = machine::handle_show_candidate_machine(&db_conn, &req).await?;
        assert!(resp.machine.is_some());
        let machine = resp.machine.unwrap();
        assert_eq!(machine.machine_id, princess_network.machine_id.to_string());
        assert_eq!(
            machine.state,
            mbrpc::MeasurementMachineStatePb::Measured as i32
        );

        let req = mbrpc::ShowCandidateMachineRequest {
            selector: Some(mbrpc::show_candidate_machine_request::Selector::MachineId(
                beer_louisiana.machine_id.to_string(),
            )),
        };
        let resp = machine::handle_show_candidate_machine(&db_conn, &req).await?;
        assert!(resp.machine.is_some());
        let machine = resp.machine.unwrap();
        assert_eq!(machine.machine_id, beer_louisiana.machine_id.to_string());
        assert_eq!(
            machine.state,
            mbrpc::MeasurementMachineStatePb::Measured as i32
        );

        let req = mbrpc::ShowCandidateMachineRequest {
            selector: Some(mbrpc::show_candidate_machine_request::Selector::MachineId(
                lime_coconut.machine_id.to_string(),
            )),
        };
        let resp = machine::handle_show_candidate_machine(&db_conn, &req).await?;
        assert!(resp.machine.is_some());
        let machine = resp.machine.unwrap();
        assert_eq!(machine.machine_id, lime_coconut.machine_id.to_string());
        assert_eq!(
            machine.state,
            mbrpc::MeasurementMachineStatePb::Measured as i32
        );

        // And then do a force-cleanup on all of them to make sure
        // that bit works (which will clean up all reports and journals).
        let mut txn = db_conn.begin().await?;
        assert!(
            crate::db::machine::force_cleanup(&mut txn, &princess_network.machine_id)
                .await
                .is_ok()
        );
        assert!(
            crate::db::machine::force_cleanup(&mut txn, &beer_louisiana.machine_id)
                .await
                .is_ok()
        );
        assert!(
            crate::db::machine::force_cleanup(&mut txn, &lime_coconut.machine_id)
                .await
                .is_ok()
        );
        txn.commit().await?;

        let req = mbrpc::ShowMeasurementJournalsRequest {};
        let resp = journal::handle_show_measurement_journals(&db_conn, &req).await?;
        assert_eq!(0, resp.journals.len());

        let req = mbrpc::ShowMeasurementReportsRequest {};
        let resp = report::handle_show_measurement_reports(&db_conn, &req).await?;
        assert_eq!(0, resp.reports.len());

        Ok(())
    }

    #[crate::sqlx_test]
    async fn test_handle_show_candidate_machines_should_filter_out_predicted_host(
        db_conn: sqlx::PgPool,
    ) {
        // First, lets make a machine behind the scenes.
        let lenovo_sr670_topology = load_topology_json("lenovo_sr670.json");
        let mut dell_r750_topology = load_topology_json("dell_r750.json");

        // let's pretend the second machine is a predicted one
        dell_r750_topology.dmi_data = None;

        // create "real" machine
        let mut txn = db_conn.begin().await.unwrap();
        let princess_network = create_test_machine(
            &mut txn,
            "fm100hseddco33hvlofuqvg543p6p9aj60g76q5cq491g9m9tgtf2dk0530",
            &lenovo_sr670_topology,
        )
        .await
        .unwrap();

        // create predicted machine "beer-louisiana"
        let machine_id =
            MachineId::from_str("fm100ptrh18t1lrjg2pqagkh3sfigr9m65dejvkq168ako07sc0uibpp5q0")
                .unwrap();
        crate::db::machine::create(
            &mut txn,
            None,
            &machine_id,
            ManagedHostState::Ready,
            &Metadata {
                name: machine_id.to_string(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        MachineTopology::create_or_update(&mut txn, &machine_id, &dell_r750_topology)
            .await
            .unwrap();

        txn.commit().await.unwrap();

        let req = mbrpc::ShowCandidateMachinesRequest {};
        let resp = machine::handle_show_candidate_machines(&db_conn, &req)
            .await
            .unwrap();
        assert_eq!(1, resp.machines.len());
        let machine = &resp.machines[0];
        assert_eq!(machine.machine_id, princess_network.machine_id.to_string());
    }
}
