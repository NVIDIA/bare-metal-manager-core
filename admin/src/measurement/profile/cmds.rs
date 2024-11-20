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

//!
//! `measurement profile` subcommand dispatcher + backing functions.
//!

use crate::measurement::global;
use crate::measurement::global::cmds::{get_identifier, IdentifierType};
use crate::measurement::profile::args::{
    CmdProfile, Create, Delete, List, ListBundles, ListMachines, Rename, Show,
};
use crate::measurement::MachineIdList;
use ::rpc::forge_tls_client::ForgeClientT;
use ::rpc::protos::measured_boot::delete_measurement_system_profile_request;
use ::rpc::protos::measured_boot::list_measurement_system_profile_bundles_request;
use ::rpc::protos::measured_boot::list_measurement_system_profile_machines_request;
use ::rpc::protos::measured_boot::rename_measurement_system_profile_request;
use ::rpc::protos::measured_boot::show_measurement_system_profile_request;
use ::rpc::protos::measured_boot::{
    CreateMeasurementSystemProfileRequest, DeleteMeasurementSystemProfileRequest, KvPair,
    ListMeasurementSystemProfileBundlesRequest, ListMeasurementSystemProfileMachinesRequest,
    ListMeasurementSystemProfilesRequest, RenameMeasurementSystemProfileRequest,
    ShowMeasurementSystemProfileRequest, ShowMeasurementSystemProfilesRequest,
};
use forge_uuid::machine::MachineId;
use forge_uuid::measured_boot::{MeasurementBundleId, MeasurementSystemProfileId};
use measured_boot::profile::MeasurementSystemProfile;
use measured_boot::records::MeasurementSystemProfileRecord;
use serde::Serialize;
use std::str::FromStr;
use utils::admin_cli::{cli_output, CarbideCliError, CarbideCliResult, ToTable};

/// dispatch matches + dispatches the correct command for
/// the `profile` subcommand (e.g. create, delete, etc).
pub async fn dispatch(
    cmd: &CmdProfile,
    cli: &mut global::cmds::CliData<'_, '_>,
) -> CarbideCliResult<()> {
    match cmd {
        CmdProfile::Create(local_args) => {
            cli_output(
                create(cli.grpc_conn, local_args).await?,
                &cli.args.format,
                utils::admin_cli::Destination::Stdout(),
            )?;
        }
        CmdProfile::Delete(local_args) => {
            cli_output(
                delete(cli.grpc_conn, local_args).await?,
                &cli.args.format,
                utils::admin_cli::Destination::Stdout(),
            )?;
        }
        CmdProfile::Rename(local_args) => {
            cli_output(
                rename(cli.grpc_conn, local_args).await?,
                &cli.args.format,
                utils::admin_cli::Destination::Stdout(),
            )?;
        }
        CmdProfile::Show(local_args) => {
            if local_args.identifier.is_some() {
                cli_output(
                    show_by_id_or_name(cli.grpc_conn, local_args).await?,
                    &cli.args.format,
                    utils::admin_cli::Destination::Stdout(),
                )?;
            } else {
                cli_output(
                    show_all(cli.grpc_conn).await?,
                    &cli.args.format,
                    utils::admin_cli::Destination::Stdout(),
                )?;
            }
        }
        CmdProfile::List(selector) => match selector {
            List::Bundles(local_args) => {
                cli_output(
                    list_bundles_for_id_or_name(cli.grpc_conn, local_args).await?,
                    &cli.args.format,
                    utils::admin_cli::Destination::Stdout(),
                )?;
            }
            List::Machines(local_args) => {
                cli_output(
                    list_machines_for_id_or_name(cli.grpc_conn, local_args).await?,
                    &cli.args.format,
                    utils::admin_cli::Destination::Stdout(),
                )?;
            }
            List::All(_) => {
                cli_output(
                    list_all(cli.grpc_conn).await?,
                    &cli.args.format,
                    utils::admin_cli::Destination::Stdout(),
                )?;
            }
        },
    }
    Ok(())
}

/// create is `profile create` and used for creating
/// a new profile.
pub async fn create(
    grpc_conn: &mut ForgeClientT,
    create: &Create,
) -> CarbideCliResult<MeasurementSystemProfile> {
    // Prepare.
    let extra_attrs = create
        .extra_attrs
        .iter()
        .map(|kv_pair| KvPair {
            key: kv_pair.key.clone(),
            value: kv_pair.value.clone(),
        })
        .collect();

    // Request.
    let request = CreateMeasurementSystemProfileRequest {
        name: Some(create.name.clone()),
        vendor: create.vendor.clone(),
        product: create.product.clone(),
        extra_attrs,
    };

    // Response.
    let response = grpc_conn
        .create_measurement_system_profile(request)
        .await
        .map_err(CarbideCliError::ApiInvocationError)?;

    MeasurementSystemProfile::from_grpc(response.get_ref().system_profile.as_ref())
        .map_err(|e| CarbideCliError::GenericError(e.to_string()))
}

/// delete is `delete <profile-id|profile-name>` and is used
/// for deleting an existing profile by ID or name.
pub async fn delete(
    grpc_conn: &mut ForgeClientT,
    delete: &Delete,
) -> CarbideCliResult<MeasurementSystemProfile> {
    // Prepare.
    let selector = match get_identifier(delete)? {
        IdentifierType::ForId => {
            let profile_id: MeasurementSystemProfileId =
                MeasurementSystemProfileId::from_str(&delete.identifier.clone())
                    .map_err(|e| CarbideCliError::GenericError(e.to_string()))?;
            Some(delete_measurement_system_profile_request::Selector::ProfileId(profile_id.into()))
        }
        IdentifierType::ForName => Some(
            delete_measurement_system_profile_request::Selector::ProfileName(
                delete.identifier.clone(),
            ),
        ),
        IdentifierType::Detect => {
            match MeasurementSystemProfileId::from_str(&delete.identifier.clone()) {
                Ok(profile_id) => Some(
                    delete_measurement_system_profile_request::Selector::ProfileId(
                        profile_id.into(),
                    ),
                ),
                Err(_) => Some(
                    delete_measurement_system_profile_request::Selector::ProfileName(
                        delete.identifier.clone(),
                    ),
                ),
            }
        }
    };

    // Request.
    let request = DeleteMeasurementSystemProfileRequest { selector };

    // Response.
    let response = grpc_conn
        .delete_measurement_system_profile(request)
        .await
        .map_err(CarbideCliError::ApiInvocationError)?;

    MeasurementSystemProfile::from_grpc(response.get_ref().system_profile.as_ref())
        .map_err(|e| CarbideCliError::GenericError(e.to_string()))
}

/// rename renames a measurement bundle with the provided name or ID.
pub async fn rename(
    grpc_conn: &mut ForgeClientT,
    rename: &Rename,
) -> CarbideCliResult<MeasurementSystemProfile> {
    let selector = match get_identifier(rename)? {
        IdentifierType::ForId => {
            let profile_id = MeasurementSystemProfileId::from_str(&rename.identifier.clone())
                .map_err(|e| CarbideCliError::GenericError(e.to_string()))?;
            Some(rename_measurement_system_profile_request::Selector::ProfileId(profile_id.into()))
        }
        IdentifierType::ForName => Some(
            rename_measurement_system_profile_request::Selector::ProfileName(
                rename.identifier.clone(),
            ),
        ),
        IdentifierType::Detect => {
            match MeasurementSystemProfileId::from_str(&rename.identifier.clone()) {
                Ok(profile_id) => Some(
                    rename_measurement_system_profile_request::Selector::ProfileId(
                        profile_id.into(),
                    ),
                ),
                Err(_) => Some(
                    rename_measurement_system_profile_request::Selector::ProfileName(
                        rename.identifier.clone(),
                    ),
                ),
            }
        }
    };

    // Request.
    let request = RenameMeasurementSystemProfileRequest {
        new_profile_name: rename.new_profile_name.clone(),
        selector,
    };

    // Response.
    let response = grpc_conn
        .rename_measurement_system_profile(request)
        .await
        .map_err(CarbideCliError::ApiInvocationError)?;

    MeasurementSystemProfile::from_grpc(response.get_ref().profile.as_ref())
        .map_err(|e| CarbideCliError::GenericError(e.to_string()))
}

/// show_all is `show`, and is used for showing all
/// profiles with details (when no <profile_id> is
/// specified on the command line).
pub async fn show_all(
    grpc_conn: &mut ForgeClientT,
) -> CarbideCliResult<MeasurementSystemProfileList> {
    // Request.
    let request = ShowMeasurementSystemProfilesRequest {};

    // Response.
    Ok(MeasurementSystemProfileList(
        grpc_conn
            .show_measurement_system_profiles(request)
            .await
            .map_err(CarbideCliError::ApiInvocationError)?
            .get_ref()
            .system_profiles
            .iter()
            .map(|system_profile| {
                MeasurementSystemProfile::try_from(system_profile.clone())
                    .map_err(|e| CarbideCliError::GenericError(e.to_string()))
            })
            .collect::<CarbideCliResult<Vec<MeasurementSystemProfile>>>()?,
    ))
}

/// show_by_id_or_name is `show <profile-id|profile-name>` and is used for
/// showing a profile (and its details) by ID or name.
pub async fn show_by_id_or_name(
    grpc_conn: &mut ForgeClientT,
    show: &Show,
) -> CarbideCliResult<MeasurementSystemProfile> {
    // Prepare.
    let identifier = show
        .identifier
        .as_ref()
        .ok_or(CarbideCliError::GenericError(String::from(
            "identifier expected to be set here",
        )))?;

    let selector = match get_identifier(show)? {
        IdentifierType::ForId => {
            let profile_id: MeasurementSystemProfileId =
                MeasurementSystemProfileId::from_str(&identifier.clone())
                    .map_err(|e| CarbideCliError::GenericError(e.to_string()))?;
            Some(show_measurement_system_profile_request::Selector::ProfileId(profile_id.into()))
        }
        IdentifierType::ForName => {
            Some(show_measurement_system_profile_request::Selector::ProfileName(identifier.clone()))
        }
        IdentifierType::Detect => match MeasurementSystemProfileId::from_str(&identifier.clone()) {
            Ok(profile_id) => Some(
                show_measurement_system_profile_request::Selector::ProfileId(profile_id.into()),
            ),
            Err(_) => Some(
                show_measurement_system_profile_request::Selector::ProfileName(identifier.clone()),
            ),
        },
    };

    // Request.
    let request = ShowMeasurementSystemProfileRequest { selector };

    // Response.
    let response = grpc_conn
        .show_measurement_system_profile(request)
        .await
        .map_err(CarbideCliError::ApiInvocationError)?;

    MeasurementSystemProfile::from_grpc(response.get_ref().system_profile.as_ref())
        .map_err(|e| CarbideCliError::GenericError(e.to_string()))
}

/// list_all is `list all` and is used for listing all
/// high level profile info (just IDs). For actual
/// details, use `show`.
pub async fn list_all(
    grpc_conn: &mut ForgeClientT,
) -> CarbideCliResult<MeasurementSystemProfileRecordList> {
    // Request.
    let request = ListMeasurementSystemProfilesRequest {};

    // Response.
    Ok(MeasurementSystemProfileRecordList(
        grpc_conn
            .list_measurement_system_profiles(request)
            .await
            .map_err(CarbideCliError::ApiInvocationError)?
            .get_ref()
            .system_profiles
            .iter()
            .map(|rec| {
                MeasurementSystemProfileRecord::try_from(rec.clone())
                    .map_err(|e| CarbideCliError::GenericError(e.to_string()))
            })
            .collect::<CarbideCliResult<Vec<MeasurementSystemProfileRecord>>>()?,
    ))
}

/// list_bundles_by_id_or_name is `list bundles <profile-id|profile-name>` and
/// is used to list all configured bundles for a given profile ID or name.
pub async fn list_bundles_for_id_or_name(
    grpc_conn: &mut ForgeClientT,
    list_bundles: &ListBundles,
) -> CarbideCliResult<MeasurementBundleIdList> {
    // Prepare.
    let selector = match get_identifier(list_bundles)? {
        IdentifierType::ForId => {
            let profile_id: MeasurementSystemProfileId =
                MeasurementSystemProfileId::from_str(&list_bundles.identifier.clone())
                    .map_err(|e| CarbideCliError::GenericError(e.to_string()))?;
            Some(
                list_measurement_system_profile_bundles_request::Selector::ProfileId(
                    profile_id.into(),
                ),
            )
        }
        IdentifierType::ForName => Some(
            list_measurement_system_profile_bundles_request::Selector::ProfileName(
                list_bundles.identifier.clone(),
            ),
        ),
        IdentifierType::Detect => {
            match MeasurementSystemProfileId::from_str(&list_bundles.identifier.clone()) {
                Ok(profile_id) => Some(
                    list_measurement_system_profile_bundles_request::Selector::ProfileId(
                        profile_id.into(),
                    ),
                ),
                Err(_) => Some(
                    list_measurement_system_profile_bundles_request::Selector::ProfileName(
                        list_bundles.identifier.clone(),
                    ),
                ),
            }
        }
    };

    // Request.
    let request = ListMeasurementSystemProfileBundlesRequest { selector };

    // Response.
    Ok(MeasurementBundleIdList(
        grpc_conn
            .list_measurement_system_profile_bundles(request)
            .await
            .map_err(CarbideCliError::ApiInvocationError)?
            .get_ref()
            .bundle_ids
            .iter()
            .map(|rec| {
                MeasurementBundleId::try_from(rec.clone())
                    .map_err(|e| CarbideCliError::GenericError(e.to_string()))
            })
            .collect::<CarbideCliResult<Vec<MeasurementBundleId>>>()?,
    ))
}

/// list_machines_for_id_or_name is `list machines <profile-id|profile-name>`
/// and is used to list all configured machines associated with a given profile
/// ID or name.
pub async fn list_machines_for_id_or_name(
    grpc_conn: &mut ForgeClientT,
    list_machines: &ListMachines,
) -> CarbideCliResult<MachineIdList> {
    // Prepare.
    let selector = match get_identifier(list_machines)? {
        IdentifierType::ForId => {
            let profile_id: MeasurementSystemProfileId =
                MeasurementSystemProfileId::from_str(&list_machines.identifier.clone())
                    .map_err(|e| CarbideCliError::GenericError(e.to_string()))?;
            Some(
                list_measurement_system_profile_machines_request::Selector::ProfileId(
                    profile_id.into(),
                ),
            )
        }
        IdentifierType::ForName => Some(
            list_measurement_system_profile_machines_request::Selector::ProfileName(
                list_machines.identifier.clone(),
            ),
        ),
        IdentifierType::Detect => {
            match MeasurementSystemProfileId::from_str(&list_machines.identifier.clone()) {
                Ok(profile_id) => Some(
                    list_measurement_system_profile_machines_request::Selector::ProfileId(
                        profile_id.into(),
                    ),
                ),
                Err(_) => Some(
                    list_measurement_system_profile_machines_request::Selector::ProfileName(
                        list_machines.identifier.clone(),
                    ),
                ),
            }
        }
    };

    // Request.
    let request = ListMeasurementSystemProfileMachinesRequest { selector };

    // Response.
    Ok(MachineIdList(
        grpc_conn
            .list_measurement_system_profile_machines(request)
            .await
            .map_err(CarbideCliError::ApiInvocationError)?
            .get_ref()
            .machine_ids
            .iter()
            .map(|rec| {
                MachineId::from_str(rec).map_err(|e| CarbideCliError::GenericError(e.to_string()))
            })
            .collect::<CarbideCliResult<Vec<MachineId>>>()?,
    ))
}

/// MeasurementSystemProfileRecordList just implements a newtype pattern
/// for a Vec<MeasurementSystemProfileRecord> so the ToTable trait can
/// be leveraged (since we don't define Vec).
#[derive(Serialize)]
pub struct MeasurementSystemProfileRecordList(Vec<MeasurementSystemProfileRecord>);

impl ToTable for MeasurementSystemProfileRecordList {
    fn to_table(&self) -> eyre::Result<String> {
        let mut table = prettytable::Table::new();
        table.add_row(prettytable::row!["profile_id", "name", "created_ts"]);
        for profile in self.0.iter() {
            table.add_row(prettytable::row![
                profile.profile_id,
                profile.name,
                profile.ts
            ]);
        }
        Ok(table.to_string())
    }
}

/// MeasurementBundleIdList just implements a newtype pattern
/// for a Vec<MeasurementBundleId> so the ToTable trait can
/// be leveraged (since we don't define Vec).
#[derive(Serialize)]
pub struct MeasurementBundleIdList(Vec<MeasurementBundleId>);

impl ToTable for MeasurementBundleIdList {
    fn to_table(&self) -> eyre::Result<String> {
        let mut table = prettytable::Table::new();
        table.add_row(prettytable::row!["bundle_id"]);
        for bundle_id in self.0.iter() {
            table.add_row(prettytable::row![bundle_id]);
        }
        Ok(table.to_string())
    }
}

/// MeasurementSystemProfileList just implements a newtype
/// pattern for a Vec<MeasurementSystemProfile> so the ToTable
/// trait can be leveraged (since we don't define Vec).
#[derive(Serialize)]
pub struct MeasurementSystemProfileList(Vec<MeasurementSystemProfile>);

// When `profile show` gets called (for all entries), and the output format
// is the default table view, this gets used to print a pretty table.
impl ToTable for MeasurementSystemProfileList {
    fn to_table(&self) -> eyre::Result<String> {
        let mut table = prettytable::Table::new();
        table.add_row(prettytable::row![
            "profile_id",
            "name",
            "created_ts",
            "attributes"
        ]);
        for profile in self.0.iter() {
            let mut attrs_table = prettytable::Table::new();
            attrs_table.add_row(prettytable::row!["name", "value"]);
            for attr_record in profile.attrs.iter() {
                attrs_table.add_row(prettytable::row![attr_record.key, attr_record.value]);
            }
            table.add_row(prettytable::row![
                profile.profile_id,
                profile.name,
                profile.ts,
                attrs_table
            ]);
        }
        Ok(table.to_string())
    }
}
