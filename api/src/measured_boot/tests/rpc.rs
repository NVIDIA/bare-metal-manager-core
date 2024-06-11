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
    use crate::measured_boot::interface::common::PcrRegisterValue;
    use crate::measured_boot::model::report::MeasurementReport;
    use crate::measured_boot::rpc::profile;
    use crate::measured_boot::tests::common::{create_test_machine, load_topology_json};
    use rpc::protos::measured_boot;

    // test_system_profiles is used to test all of the different API
    // handler functions that work with measured boot system profiles,
    // going through the steps of making profiles, making sure they can
    // be read back (via show/list), modified (via update/delete), etc.
    #[sqlx::test]
    pub async fn test_system_profiles(
        pool: sqlx::PgPool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Create a system profile and make sure it works.
        //////////////////////////////////////////////////
        let req = measured_boot::CreateMeasurementSystemProfileRequest {
            name: Some(String::from("test-profile")),
            vendor: String::from("Dell, Inc."),
            product: String::from("PowerEdge R750"),
            extra_attrs: vec![],
        };

        let resp = profile::handle_create_system_measurement_profile(&pool, &req).await?;
        assert!(resp.system_profile.is_some());
        let created_profile = resp.system_profile.unwrap();
        assert_eq!(created_profile.name, String::from("test-profile"));

        // And now fetch the first back by ID and make sure it works.
        /////////////////////////////////////////////////////////////
        let req = measured_boot::ShowMeasurementSystemProfileRequest {
            selector: Some(
                measured_boot::show_measurement_system_profile_request::Selector::ProfileId(
                    created_profile.profile_id.as_ref().unwrap().clone(),
                ),
            ),
        };

        let resp = profile::handle_show_measurement_system_profile(&pool, &req).await?;
        assert!(resp.system_profile.is_some());
        let read_profile_by_id = resp.system_profile.unwrap();
        assert_eq!(read_profile_by_id.profile_id, created_profile.profile_id);
        assert_eq!(read_profile_by_id.name, created_profile.name);

        // And now fetch it back by name and make sure it works.
        ////////////////////////////////////////////////////////
        let req = measured_boot::ShowMeasurementSystemProfileRequest {
            selector: Some(
                measured_boot::show_measurement_system_profile_request::Selector::ProfileName(
                    created_profile.name.clone(),
                ),
            ),
        };

        let resp = profile::handle_show_measurement_system_profile(&pool, &req).await?;
        assert!(resp.system_profile.is_some());
        let read_profile_by_name = resp.system_profile.unwrap();
        assert_eq!(read_profile_by_name.profile_id, created_profile.profile_id);
        assert_eq!(read_profile_by_name.name, created_profile.name);

        // And now show all and make sure the one returned is the right one.
        /////////////////////////////////////////////////////////////////////
        let req = measured_boot::ShowMeasurementSystemProfilesRequest {};
        let resp = profile::handle_show_measurement_system_profiles(&pool, &req).await?;
        assert_eq!(1, resp.system_profiles.len());
        let first_profile = &resp.system_profiles[0];
        assert_eq!(first_profile.profile_id, created_profile.profile_id);
        assert_eq!(first_profile.name, created_profile.name);

        // And make sure list all works also.
        /////////////////////////////////////
        let req = measured_boot::ListMeasurementSystemProfilesRequest {};
        let resp = profile::handle_list_measurement_system_profiles(&pool, &req).await?;
        assert_eq!(1, resp.system_profiles.len());
        let first_profile = &resp.system_profiles[0];
        assert_eq!(first_profile.profile_id, created_profile.profile_id);
        assert_eq!(first_profile.name, created_profile.name);

        // And make sure rename works.
        //////////////////////////////
        let req = measured_boot::RenameMeasurementSystemProfileRequest {
            new_profile_name: String::from("test-renamed-profile"),
            selector: Some(
                measured_boot::rename_measurement_system_profile_request::Selector::ProfileName(
                    created_profile.name.clone(),
                ),
            ),
        };
        let resp = profile::handle_rename_measurement_system_profile(&pool, &req).await?;
        assert!(resp.profile.is_some());
        let renamed_profile = resp.profile.unwrap();

        // ..and now for the moment of truth.. same profile ID, different name?
        assert_eq!(renamed_profile.profile_id, created_profile.profile_id);
        assert_eq!(renamed_profile.name, String::from("test-renamed-profile"));

        // Create a second system profile and make sure it works.
        //////////////////////////////////////////////////
        let req = measured_boot::CreateMeasurementSystemProfileRequest {
            name: Some(String::from("test-profile-2")),
            vendor: String::from("Lenovo"),
            product: String::from("ThinkSystem SR670 V2"),
            extra_attrs: vec![measured_boot::KvPair {
                key: String::from("bios_version"),
                value: String::from("U8E122J-1.51"),
            }],
        };
        let resp = profile::handle_create_system_measurement_profile(&pool, &req).await?;
        assert!(resp.system_profile.is_some());
        let created_profile2 = resp.system_profile.unwrap();
        assert_eq!(created_profile2.name, String::from("test-profile-2"));

        // ..and lets delete the first.
        let req = measured_boot::DeleteMeasurementSystemProfileRequest {
            selector: Some(
                measured_boot::delete_measurement_system_profile_request::Selector::ProfileName(
                    renamed_profile.name.clone(),
                ),
            ),
        };
        let resp = profile::handle_delete_measurement_system_profile(&pool, &req).await?;
        assert!(resp.system_profile.is_some());
        let deleted_profile_by_name = resp.system_profile.unwrap();
        assert_eq!(
            deleted_profile_by_name.profile_id,
            created_profile.profile_id
        );

        // And make sure list all just shows
        // the other profile that was made.
        /////////////////////////////////////
        let req = measured_boot::ListMeasurementSystemProfilesRequest {};
        let resp = profile::handle_list_measurement_system_profiles(&pool, &req).await?;
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

        let mut txn = pool.begin().await?;
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

        let princess_report = MeasurementReport::new_with_txn(
            &mut txn,
            princess_network.machine_id.clone(),
            &princess_values,
        )
        .await?;
        assert_eq!(princess_report.machine_id, princess_network.machine_id);
        txn.commit().await?;

        // One machine!
        let req = measured_boot::ListMeasurementSystemProfileMachinesRequest{
            selector: Some(
                measured_boot::list_measurement_system_profile_machines_request::Selector::ProfileId(
                    created_profile2.profile_id.as_ref().unwrap().clone(),
                ),
            ),
        };
        let resp = profile::handle_list_measurement_system_profile_machines(&pool, &req).await?;
        assert_eq!(1, resp.machine_ids.len());
        assert_eq!(princess_network.machine_id.to_string(), resp.machine_ids[0]);

        // No bundles though.
        let req = measured_boot::ListMeasurementSystemProfileBundlesRequest {
            selector: Some(
                measured_boot::list_measurement_system_profile_bundles_request::Selector::ProfileId(
                    created_profile2.profile_id.as_ref().unwrap().clone(),
                ),
            ),
        };
        let resp = profile::handle_list_measurement_system_profile_bundles(&pool, &req).await?;
        assert_eq!(0, resp.bundle_ids.len());

        // And now try to delete the second one by ID,
        // which should fail, since there is corresponding
        // journal data referencing the profile.
        let req = measured_boot::DeleteMeasurementSystemProfileRequest {
            selector: Some(
                measured_boot::delete_measurement_system_profile_request::Selector::ProfileId(
                    created_profile2.profile_id.as_ref().unwrap().clone(),
                ),
            ),
        };
        let resp = profile::handle_delete_measurement_system_profile(&pool, &req).await;
        assert!(resp.is_err());
        Ok(())
    }
}
