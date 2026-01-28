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
//! `measurement bundle` subcommand dispatcher + backing functions.
//!

use std::str::FromStr;

use ::rpc::admin_cli::{CarbideCliError, CarbideCliResult, ToTable, cli_output};
use ::rpc::protos::measured_boot::{
    CreateMeasurementBundleRequest, DeleteMeasurementBundleRequest, FindClosestBundleMatchRequest,
    ListMeasurementBundleMachinesRequest, MeasurementBundleStatePb, RenameMeasurementBundleRequest,
    ShowMeasurementBundleRequest, UpdateMeasurementBundleRequest,
    delete_measurement_bundle_request, list_measurement_bundle_machines_request,
    rename_measurement_bundle_request, show_measurement_bundle_request,
    update_measurement_bundle_request,
};
use carbide_uuid::machine::MachineId;
use carbide_uuid::measured_boot::MeasurementBundleId;
use measured_boot::bundle::MeasurementBundle;
use measured_boot::records::MeasurementBundleRecord;
use serde::Serialize;

use crate::measurement::bundle::args::{
    CmdBundle, Create, Delete, FindClosestMatch, List, ListMachines, Rename, SetState, Show,
};
use crate::measurement::global::cmds::{IdentifierType, get_identifier};
use crate::measurement::{MachineIdList, global};
use crate::rpc::ApiClient;

/// dispatch matches + dispatches the correct command for
/// the `bundle` subcommand (e.g. create, delete, set-state).
pub async fn dispatch(
    cmd: CmdBundle,
    cli: &mut global::cmds::CliData<'_, '_>,
) -> CarbideCliResult<()> {
    match cmd {
        CmdBundle::Create(local_args) => {
            cli_output(
                create_for_id(cli.grpc_conn, local_args).await?,
                &cli.args.format,
                ::rpc::admin_cli::Destination::Stdout(),
            )?;
        }
        CmdBundle::Delete(local_args) => {
            cli_output(
                delete(cli.grpc_conn, local_args).await?,
                &cli.args.format,
                ::rpc::admin_cli::Destination::Stdout(),
            )?;
        }
        CmdBundle::Rename(local_args) => {
            cli_output(
                rename(cli.grpc_conn, local_args).await?,
                &cli.args.format,
                ::rpc::admin_cli::Destination::Stdout(),
            )?;
        }
        CmdBundle::SetState(local_args) => {
            cli_output(
                set_state(cli.grpc_conn, local_args).await?,
                &cli.args.format,
                ::rpc::admin_cli::Destination::Stdout(),
            )?;
        }
        CmdBundle::Show(local_args) => {
            if local_args.identifier.is_some() {
                cli_output(
                    show_by_id_or_name(cli.grpc_conn, local_args).await?,
                    &cli.args.format,
                    ::rpc::admin_cli::Destination::Stdout(),
                )?;
            } else {
                cli_output(
                    show_all(cli.grpc_conn, local_args).await?,
                    &cli.args.format,
                    ::rpc::admin_cli::Destination::Stdout(),
                )?;
            }
        }
        CmdBundle::FindClosestMatch(local_args) => {
            match find_closest_match(cli.grpc_conn, local_args).await? {
                Some(measurement_bundle) => cli_output(
                    measurement_bundle,
                    &cli.args.format,
                    ::rpc::admin_cli::Destination::Stdout(),
                )?,
                None => tracing::info!("No partially matching bundle found"),
            };
        }
        CmdBundle::List(selector) => match selector {
            List::Machines(local_args) => {
                cli_output(
                    list_machines(cli.grpc_conn, local_args).await?,
                    &cli.args.format,
                    ::rpc::admin_cli::Destination::Stdout(),
                )?;
            }
            List::All(_) => {
                cli_output(
                    list(cli.grpc_conn).await?,
                    &cli.args.format,
                    ::rpc::admin_cli::Destination::Stdout(),
                )?;
            }
        },
    }
    Ok(())
}

/// create_for_id creates a new measurement bundle associated with the
/// profile w/ the provided profile ID.
pub async fn create_for_id(
    grpc_conn: &ApiClient,
    create: Create,
) -> CarbideCliResult<MeasurementBundle> {
    // Prepare.
    let state: MeasurementBundleStatePb = match create.state {
        Some(input_state) => input_state.into(),
        None => MeasurementBundleStatePb::Active,
    };

    // Request.
    let request = CreateMeasurementBundleRequest {
        name: Some(create.name),
        profile_id: Some(create.profile_id),
        pcr_values: create.values.into_iter().map(Into::into).collect(),
        state: state.into(),
    };

    // Response.
    let response = grpc_conn.0.create_measurement_bundle(request).await?;

    MeasurementBundle::from_grpc(response.bundle.as_ref())
        .map_err(|e| crate::CarbideCliError::GenericError(e.to_string()))
}

/// delete deletes a measurement bundle with the provided ID.
pub async fn delete(grpc_conn: &ApiClient, delete: Delete) -> CarbideCliResult<MeasurementBundle> {
    // Request.
    let request = DeleteMeasurementBundleRequest {
        selector: Some(delete_measurement_bundle_request::Selector::BundleId(
            delete.bundle_id,
        )),
    };

    // Response.
    let response = grpc_conn.0.delete_measurement_bundle(request).await?;

    MeasurementBundle::from_grpc(response.bundle.as_ref())
        .map_err(|e| crate::CarbideCliError::GenericError(e.to_string()))
}

/// rename renames a measurement bundle with the provided name or ID.
pub async fn rename(grpc_conn: &ApiClient, rename: Rename) -> CarbideCliResult<MeasurementBundle> {
    // Prepare.
    let selector = match get_identifier(&rename)? {
        IdentifierType::ForId => {
            let bundle_id = MeasurementBundleId::from_str(&rename.identifier)
                .map_err(|e| crate::CarbideCliError::GenericError(e.to_string()))?;
            Some(rename_measurement_bundle_request::Selector::BundleId(
                bundle_id,
            ))
        }
        IdentifierType::ForName => Some(rename_measurement_bundle_request::Selector::BundleName(
            rename.identifier,
        )),
        IdentifierType::Detect => match MeasurementBundleId::from_str(&rename.identifier) {
            Ok(bundle_id) => Some(rename_measurement_bundle_request::Selector::BundleId(
                bundle_id,
            )),
            Err(_) => Some(rename_measurement_bundle_request::Selector::BundleName(
                rename.identifier,
            )),
        },
    };

    // Request.
    let request = RenameMeasurementBundleRequest {
        new_bundle_name: rename.new_bundle_name,
        selector,
    };

    // Response.
    let response = grpc_conn.0.rename_measurement_bundle(request).await?;

    MeasurementBundle::from_grpc(response.bundle.as_ref())
        .map_err(|e| crate::CarbideCliError::GenericError(e.to_string()))
}

/// set_state updates the state of the bundle (e.g. active, obsolete, retired).
pub async fn set_state(
    grpc_conn: &ApiClient,
    set_state: SetState,
) -> CarbideCliResult<MeasurementBundle> {
    // Prepare.
    let state: MeasurementBundleStatePb = set_state.state.into();

    let selector = match get_identifier(&set_state)? {
        IdentifierType::ForId => {
            let bundle_id = MeasurementBundleId::from_str(&set_state.identifier)
                .map_err(|e| crate::CarbideCliError::GenericError(e.to_string()))?;
            Some(update_measurement_bundle_request::Selector::BundleId(
                bundle_id,
            ))
        }
        IdentifierType::ForName => Some(update_measurement_bundle_request::Selector::BundleName(
            set_state.identifier,
        )),
        IdentifierType::Detect => match MeasurementBundleId::from_str(&set_state.identifier) {
            Ok(bundle_id) => Some(update_measurement_bundle_request::Selector::BundleId(
                bundle_id,
            )),
            Err(_) => Some(update_measurement_bundle_request::Selector::BundleName(
                set_state.identifier,
            )),
        },
    };

    // Request.
    let request = UpdateMeasurementBundleRequest {
        state: state.into(),
        selector,
    };

    // Response.
    let response = grpc_conn.0.update_measurement_bundle(request).await?;

    MeasurementBundle::from_grpc(response.bundle.as_ref())
        .map_err(|e| crate::CarbideCliError::GenericError(e.to_string()))
}

/// show_by_id dumps all info about a bundle for the given ID or name.
pub async fn show_by_id_or_name(
    grpc_conn: &ApiClient,
    show: Show,
) -> CarbideCliResult<MeasurementBundle> {
    let identifier_type = get_identifier(&show)?;
    // Prepare.
    let identifier = show
        .identifier
        .ok_or(CarbideCliError::GenericError(String::from(
            "identifier expected to be set here",
        )))?;

    let selector = match identifier_type {
        IdentifierType::ForId => {
            let bundle_id = MeasurementBundleId::from_str(&identifier)
                .map_err(|e| crate::CarbideCliError::GenericError(e.to_string()))?;
            Some(show_measurement_bundle_request::Selector::BundleId(
                bundle_id,
            ))
        }
        IdentifierType::ForName => Some(show_measurement_bundle_request::Selector::BundleName(
            identifier,
        )),
        IdentifierType::Detect => match MeasurementBundleId::from_str(&identifier) {
            Ok(bundle_id) => Some(show_measurement_bundle_request::Selector::BundleId(
                bundle_id,
            )),
            Err(_) => Some(show_measurement_bundle_request::Selector::BundleName(
                identifier,
            )),
        },
    };

    // Request.
    let request = ShowMeasurementBundleRequest { selector };

    // Response.
    let response = grpc_conn.0.show_measurement_bundle(request).await?;

    MeasurementBundle::from_grpc(response.bundle.as_ref())
        .map_err(|e| crate::CarbideCliError::GenericError(e.to_string()))
}

/// show_all dumps all info about all bundles.
pub async fn show_all(
    grpc_conn: &ApiClient,
    _get_by_id: Show,
) -> CarbideCliResult<MeasurementBundleList> {
    Ok(MeasurementBundleList(
        grpc_conn
            .0
            .show_measurement_bundles()
            .await?
            .bundles
            .into_iter()
            .map(|bundle| {
                MeasurementBundle::try_from(bundle)
                    .map_err(|e| CarbideCliError::GenericError(format!("conversion failed: {e}")))
            })
            .collect::<CarbideCliResult<Vec<MeasurementBundle>>>()?,
    ))
}

/// list lists all bundle ids.
pub async fn list(grpc_conn: &ApiClient) -> CarbideCliResult<MeasurementBundleRecordList> {
    Ok(MeasurementBundleRecordList(
        grpc_conn
            .0
            .list_measurement_bundles()
            .await?
            .bundles
            .into_iter()
            .map(|rec| {
                MeasurementBundleRecord::try_from(rec)
                    .map_err(|e| CarbideCliError::GenericError(format!("conversion failed: {e}")))
            })
            .collect::<CarbideCliResult<Vec<MeasurementBundleRecord>>>()?,
    ))
}

/// list_machines lists all machines associated with the provided
/// bundle ID or bundle name.
pub async fn list_machines(
    grpc_conn: &ApiClient,
    list_machines: ListMachines,
) -> CarbideCliResult<MachineIdList> {
    // Prepare.
    let selector = match get_identifier(&list_machines)? {
        IdentifierType::ForId => {
            let bundle_id = MeasurementBundleId::from_str(&list_machines.identifier)
                .map_err(|e| crate::CarbideCliError::GenericError(e.to_string()))?;
            Some(list_measurement_bundle_machines_request::Selector::BundleId(bundle_id))
        }
        IdentifierType::ForName => Some(
            list_measurement_bundle_machines_request::Selector::BundleName(
                list_machines.identifier,
            ),
        ),
        IdentifierType::Detect => match MeasurementBundleId::from_str(&list_machines.identifier) {
            Ok(bundle_id) => {
                Some(list_measurement_bundle_machines_request::Selector::BundleId(bundle_id))
            }
            Err(_) => Some(
                list_measurement_bundle_machines_request::Selector::BundleName(
                    list_machines.identifier,
                ),
            ),
        },
    };

    // Request.
    let request = ListMeasurementBundleMachinesRequest { selector };

    // Response.
    Ok(MachineIdList(
        grpc_conn
            .0
            .list_measurement_bundle_machines(request)
            .await?
            .machine_ids
            .iter()
            .map(|rec| {
                MachineId::from_str(rec)
                    .map_err(|e| CarbideCliError::GenericError(format!("conversion failed: {e}")))
            })
            .collect::<CarbideCliResult<Vec<MachineId>>>()?,
    ))
}

pub async fn find_closest_match(
    grpc_conn: &ApiClient,
    args: FindClosestMatch,
) -> CarbideCliResult<Option<MeasurementBundle>> {
    // At the moment, the request only contains report id
    // but this can be expanded to contain journal id also
    let request = match args {
        FindClosestMatch::Report(report_id) => FindClosestBundleMatchRequest {
            report_id: Some(report_id.id),
        },
    };

    // Response.
    let response = grpc_conn.0.find_closest_bundle_match(request).await?;

    if response.bundle.is_none() {
        return Ok(None);
    }

    Ok(Some(
        MeasurementBundle::from_grpc(response.bundle.as_ref())
            .map_err(|e| crate::CarbideCliError::GenericError(e.to_string()))?,
    ))
}

/// MeasurementBundleRecordList just implements a newtype pattern
/// for a Vec<MeasurementBundleRecord> so the ToTable trait can
/// be leveraged (since we don't define Vec).
#[derive(Serialize)]
pub struct MeasurementBundleRecordList(Vec<MeasurementBundleRecord>);

impl ToTable for MeasurementBundleRecordList {
    fn into_table(self) -> eyre::Result<String> {
        let mut table = prettytable::Table::new();
        table.add_row(prettytable::row![
            Fg->"bundle_id",
            Fg->"profile_id",
            Fg->"name",
            Fg->"state",
            Fg->"created_ts"
        ]);
        for bundle in self.0.iter() {
            table.add_row(prettytable::row![
                bundle.bundle_id,
                bundle.profile_id,
                bundle.name,
                bundle.state,
                bundle.ts
            ]);
        }
        Ok(table.to_string())
    }
}

/// MeasurementBundleList just implements a newtype
/// pattern for a Vec<MeasurementBundle> so the ToTable
/// trait can be leveraged (since we don't define Vec).
#[derive(Serialize)]
pub struct MeasurementBundleList(Vec<MeasurementBundle>);

// When `bundle show` gets called (for all entries), and the output format
// is the default table view, this gets used to print a pretty table.
impl ToTable for MeasurementBundleList {
    fn into_table(self) -> eyre::Result<String> {
        let mut table = prettytable::Table::new();
        table.add_row(prettytable::row!["bundle_id", "details", "values"]);
        for bundle in self.0.iter() {
            let mut details_table = prettytable::Table::new();
            details_table.add_row(prettytable::row!["profile_id", bundle.profile_id]);
            details_table.add_row(prettytable::row!["name", bundle.name]);
            details_table.add_row(prettytable::row!["state", bundle.state]);
            details_table.add_row(prettytable::row!["created_ts", bundle.ts]);
            let mut values_table = prettytable::Table::new();
            values_table.add_row(prettytable::row!["pcr_register", "value"]);
            for value_record in bundle.values.iter() {
                values_table.add_row(prettytable::row![
                    value_record.pcr_register,
                    value_record.sha_any
                ]);
            }
            table.add_row(prettytable::row![
                bundle.bundle_id,
                details_table,
                values_table
            ]);
        }
        Ok(table.to_string())
    }
}
