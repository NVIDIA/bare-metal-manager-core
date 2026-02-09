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

//!
//! `measurement profile` subcommand dispatcher + backing functions.
//!

use std::str::FromStr;

use ::rpc::admin_cli::{CarbideCliError, CarbideCliResult, ToTable, cli_output};
use ::rpc::protos::measured_boot::{
    CreateMeasurementSystemProfileRequest, DeleteMeasurementSystemProfileRequest, KvPair,
    ListMeasurementSystemProfileBundlesRequest, ListMeasurementSystemProfileMachinesRequest,
    RenameMeasurementSystemProfileRequest, ShowMeasurementSystemProfileRequest,
    delete_measurement_system_profile_request, list_measurement_system_profile_bundles_request,
    list_measurement_system_profile_machines_request, rename_measurement_system_profile_request,
    show_measurement_system_profile_request,
};
use carbide_uuid::machine::MachineId;
use carbide_uuid::measured_boot::{MeasurementBundleId, MeasurementSystemProfileId};
use measured_boot::profile::MeasurementSystemProfile;
use measured_boot::records::MeasurementSystemProfileRecord;
use serde::Serialize;

use crate::measurement::global::cmds::{IdentifierType, get_identifier};
use crate::measurement::profile::args::{
    CmdProfile, Create, Delete, List, ListBundles, ListMachines, Rename, Show,
};
use crate::measurement::{MachineIdList, global};
use crate::rpc::ApiClient;

/// dispatch matches + dispatches the correct command for
/// the `profile` subcommand (e.g. create, delete, etc).
pub async fn dispatch(
    cmd: CmdProfile,
    cli: &mut global::cmds::CliData<'_, '_>,
) -> CarbideCliResult<()> {
    match cmd {
        CmdProfile::Create(local_args) => {
            cli_output(
                create(cli.grpc_conn, local_args).await?,
                &cli.args.format,
                ::rpc::admin_cli::Destination::Stdout(),
            )?;
        }
        CmdProfile::Delete(local_args) => {
            cli_output(
                delete(cli.grpc_conn, local_args).await?,
                &cli.args.format,
                ::rpc::admin_cli::Destination::Stdout(),
            )?;
        }
        CmdProfile::Rename(local_args) => {
            cli_output(
                rename(cli.grpc_conn, local_args).await?,
                &cli.args.format,
                ::rpc::admin_cli::Destination::Stdout(),
            )?;
        }
        CmdProfile::Show(local_args) => {
            if local_args.identifier.is_some() {
                cli_output(
                    show_by_id_or_name(cli.grpc_conn, local_args).await?,
                    &cli.args.format,
                    ::rpc::admin_cli::Destination::Stdout(),
                )?;
            } else {
                cli_output(
                    show_all(cli.grpc_conn).await?,
                    &cli.args.format,
                    ::rpc::admin_cli::Destination::Stdout(),
                )?;
            }
        }
        CmdProfile::List(selector) => match selector {
            List::Bundles(local_args) => {
                cli_output(
                    list_bundles_for_id_or_name(cli.grpc_conn, local_args).await?,
                    &cli.args.format,
                    ::rpc::admin_cli::Destination::Stdout(),
                )?;
            }
            List::Machines(local_args) => {
                cli_output(
                    list_machines_for_id_or_name(cli.grpc_conn, local_args).await?,
                    &cli.args.format,
                    ::rpc::admin_cli::Destination::Stdout(),
                )?;
            }
            List::All(_) => {
                cli_output(
                    list_all(cli.grpc_conn).await?,
                    &cli.args.format,
                    ::rpc::admin_cli::Destination::Stdout(),
                )?;
            }
        },
    }
    Ok(())
}

/// create is `profile create` and used for creating
/// a new profile.
pub async fn create(
    grpc_conn: &ApiClient,
    create: Create,
) -> CarbideCliResult<MeasurementSystemProfile> {
    // Prepare.
    let extra_attrs = create
        .extra_attrs
        .into_iter()
        .map(|kv_pair| KvPair {
            key: kv_pair.key,
            value: kv_pair.value,
        })
        .collect();

    // Request.
    let request = CreateMeasurementSystemProfileRequest {
        name: Some(create.name),
        vendor: create.vendor,
        product: create.product,
        extra_attrs,
    };

    // Response.
    let response = grpc_conn
        .0
        .create_measurement_system_profile(request)
        .await?;

    MeasurementSystemProfile::from_grpc(response.system_profile.as_ref())
        .map_err(|e| CarbideCliError::GenericError(e.to_string()))
}

/// delete is `delete <profile-id|profile-name>` and is used
/// for deleting an existing profile by ID or name.
pub async fn delete(
    grpc_conn: &ApiClient,
    delete: Delete,
) -> CarbideCliResult<MeasurementSystemProfile> {
    // Prepare.
    let selector = match get_identifier(&delete)? {
        IdentifierType::ForId => {
            let profile_id: MeasurementSystemProfileId =
                MeasurementSystemProfileId::from_str(&delete.identifier)
                    .map_err(|e| CarbideCliError::GenericError(e.to_string()))?;
            Some(delete_measurement_system_profile_request::Selector::ProfileId(profile_id))
        }
        IdentifierType::ForName => Some(
            delete_measurement_system_profile_request::Selector::ProfileName(delete.identifier),
        ),
        IdentifierType::Detect => match MeasurementSystemProfileId::from_str(&delete.identifier) {
            Ok(profile_id) => {
                Some(delete_measurement_system_profile_request::Selector::ProfileId(profile_id))
            }
            Err(_) => Some(
                delete_measurement_system_profile_request::Selector::ProfileName(delete.identifier),
            ),
        },
    };

    // Request.
    let request = DeleteMeasurementSystemProfileRequest { selector };

    // Response.
    let response = grpc_conn
        .0
        .delete_measurement_system_profile(request)
        .await?;

    MeasurementSystemProfile::from_grpc(response.system_profile.as_ref())
        .map_err(|e| CarbideCliError::GenericError(e.to_string()))
}

/// rename renames a measurement bundle with the provided name or ID.
pub async fn rename(
    grpc_conn: &ApiClient,
    rename: Rename,
) -> CarbideCliResult<MeasurementSystemProfile> {
    let selector = match get_identifier(&rename)? {
        IdentifierType::ForId => {
            let profile_id = MeasurementSystemProfileId::from_str(&rename.identifier)
                .map_err(|e| CarbideCliError::GenericError(e.to_string()))?;
            Some(rename_measurement_system_profile_request::Selector::ProfileId(profile_id))
        }
        IdentifierType::ForName => Some(
            rename_measurement_system_profile_request::Selector::ProfileName(rename.identifier),
        ),
        IdentifierType::Detect => match MeasurementSystemProfileId::from_str(&rename.identifier) {
            Ok(profile_id) => {
                Some(rename_measurement_system_profile_request::Selector::ProfileId(profile_id))
            }
            Err(_) => Some(
                rename_measurement_system_profile_request::Selector::ProfileName(rename.identifier),
            ),
        },
    };

    // Request.
    let request = RenameMeasurementSystemProfileRequest {
        new_profile_name: rename.new_profile_name,
        selector,
    };

    // Response.
    let response = grpc_conn
        .0
        .rename_measurement_system_profile(request)
        .await?;

    MeasurementSystemProfile::from_grpc(response.profile.as_ref())
        .map_err(|e| CarbideCliError::GenericError(e.to_string()))
}

/// show_all is `show`, and is used for showing all
/// profiles with details (when no <profile_id> is
/// specified on the command line).
pub async fn show_all(grpc_conn: &ApiClient) -> CarbideCliResult<MeasurementSystemProfileList> {
    Ok(MeasurementSystemProfileList(
        grpc_conn
            .0
            .show_measurement_system_profiles()
            .await?
            .system_profiles
            .into_iter()
            .map(|system_profile| {
                MeasurementSystemProfile::try_from(system_profile)
                    .map_err(|e| CarbideCliError::GenericError(e.to_string()))
            })
            .collect::<CarbideCliResult<Vec<MeasurementSystemProfile>>>()?,
    ))
}

/// show_by_id_or_name is `show <profile-id|profile-name>` and is used for
/// showing a profile (and its details) by ID or name.
pub async fn show_by_id_or_name(
    grpc_conn: &ApiClient,
    show: Show,
) -> CarbideCliResult<MeasurementSystemProfile> {
    let identifier_type = get_identifier(&show)?;
    // Prepare.
    let identifier = show
        .identifier
        .ok_or(CarbideCliError::GenericError(String::from(
            "identifier expected to be set here",
        )))?;

    let selector = match identifier_type {
        IdentifierType::ForId => {
            let profile_id: MeasurementSystemProfileId =
                MeasurementSystemProfileId::from_str(&identifier)
                    .map_err(|e| CarbideCliError::GenericError(e.to_string()))?;
            Some(show_measurement_system_profile_request::Selector::ProfileId(profile_id))
        }
        IdentifierType::ForName => {
            Some(show_measurement_system_profile_request::Selector::ProfileName(identifier))
        }
        IdentifierType::Detect => match MeasurementSystemProfileId::from_str(&identifier) {
            Ok(profile_id) => {
                Some(show_measurement_system_profile_request::Selector::ProfileId(profile_id))
            }
            Err(_) => {
                Some(show_measurement_system_profile_request::Selector::ProfileName(identifier))
            }
        },
    };

    // Request.
    let request = ShowMeasurementSystemProfileRequest { selector };

    // Response.
    let response = grpc_conn.0.show_measurement_system_profile(request).await?;

    MeasurementSystemProfile::from_grpc(response.system_profile.as_ref())
        .map_err(|e| CarbideCliError::GenericError(e.to_string()))
}

/// list_all is `list all` and is used for listing all
/// high level profile info (just IDs). For actual
/// details, use `show`.
pub async fn list_all(
    grpc_conn: &ApiClient,
) -> CarbideCliResult<MeasurementSystemProfileRecordList> {
    Ok(MeasurementSystemProfileRecordList(
        grpc_conn
            .0
            .list_measurement_system_profiles()
            .await?
            .system_profiles
            .into_iter()
            .map(|rec| {
                MeasurementSystemProfileRecord::try_from(rec)
                    .map_err(|e| CarbideCliError::GenericError(e.to_string()))
            })
            .collect::<CarbideCliResult<Vec<MeasurementSystemProfileRecord>>>()?,
    ))
}

/// list_bundles_by_id_or_name is `list bundles <profile-id|profile-name>` and
/// is used to list all configured bundles for a given profile ID or name.
pub async fn list_bundles_for_id_or_name(
    grpc_conn: &ApiClient,
    list_bundles: ListBundles,
) -> CarbideCliResult<MeasurementBundleIdList> {
    // Prepare.
    let selector = match get_identifier(&list_bundles)? {
        IdentifierType::ForId => {
            let profile_id: MeasurementSystemProfileId =
                MeasurementSystemProfileId::from_str(&list_bundles.identifier)
                    .map_err(|e| CarbideCliError::GenericError(e.to_string()))?;
            Some(list_measurement_system_profile_bundles_request::Selector::ProfileId(profile_id))
        }
        IdentifierType::ForName => Some(
            list_measurement_system_profile_bundles_request::Selector::ProfileName(
                list_bundles.identifier,
            ),
        ),
        IdentifierType::Detect => {
            match MeasurementSystemProfileId::from_str(&list_bundles.identifier) {
                Ok(profile_id) => Some(
                    list_measurement_system_profile_bundles_request::Selector::ProfileId(
                        profile_id,
                    ),
                ),
                Err(_) => Some(
                    list_measurement_system_profile_bundles_request::Selector::ProfileName(
                        list_bundles.identifier,
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
            .0
            .list_measurement_system_profile_bundles(request)
            .await?
            .bundle_ids,
    ))
}

/// list_machines_for_id_or_name is `list machines <profile-id|profile-name>`
/// and is used to list all configured machines associated with a given profile
/// ID or name.
pub async fn list_machines_for_id_or_name(
    grpc_conn: &ApiClient,
    list_machines: ListMachines,
) -> CarbideCliResult<MachineIdList> {
    // Prepare.
    let selector = match get_identifier(&list_machines)? {
        IdentifierType::ForId => {
            let profile_id: MeasurementSystemProfileId =
                MeasurementSystemProfileId::from_str(&list_machines.identifier)
                    .map_err(|e| CarbideCliError::GenericError(e.to_string()))?;
            Some(list_measurement_system_profile_machines_request::Selector::ProfileId(profile_id))
        }
        IdentifierType::ForName => Some(
            list_measurement_system_profile_machines_request::Selector::ProfileName(
                list_machines.identifier,
            ),
        ),
        IdentifierType::Detect => {
            match MeasurementSystemProfileId::from_str(&list_machines.identifier) {
                Ok(profile_id) => Some(
                    list_measurement_system_profile_machines_request::Selector::ProfileId(
                        profile_id,
                    ),
                ),
                Err(_) => Some(
                    list_measurement_system_profile_machines_request::Selector::ProfileName(
                        list_machines.identifier,
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
            .0
            .list_measurement_system_profile_machines(request)
            .await?
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
    fn into_table(self) -> eyre::Result<String> {
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
    fn into_table(self) -> eyre::Result<String> {
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
    fn into_table(self) -> eyre::Result<String> {
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
