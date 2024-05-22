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

use crate::measurement::bundle::args::{
    CmdBundle, Create, Delete, List, ListMachines, Rename, SetState, Show,
};
use crate::measurement::global;
use crate::measurement::global::cmds::cli_output;
use crate::measurement::global::cmds::{get_identifier, IdentifierType};
use ::rpc::forge_tls_client::ForgeClientT;
use ::rpc::protos::measured_boot::{
    delete_measurement_bundle_request, list_measurement_bundle_machines_request,
    rename_measurement_bundle_request, show_measurement_bundle_request,
    update_measurement_bundle_request,
};
use ::rpc::protos::measured_boot::{
    CreateMeasurementBundleRequest, DeleteMeasurementBundleRequest,
    ListMeasurementBundleMachinesRequest, ListMeasurementBundlesRequest, MeasurementBundleStatePb,
    RenameMeasurementBundleRequest, ShowMeasurementBundleRequest, ShowMeasurementBundlesRequest,
    UpdateMeasurementBundleRequest,
};
use carbide::measured_boot::dto::{
    keys::MeasurementBundleId, keys::MockMachineId, records::MeasurementBundleRecord,
};
use carbide::measured_boot::interface::common::PcrRegisterValue;
use carbide::measured_boot::model::bundle::MeasurementBundle;

///////////////////////////////////////////////////////////////////////////////
/// dispatch matches + dispatches the correct command for
/// the `bundle` subcommand (e.g. create, delete, set-state).
///////////////////////////////////////////////////////////////////////////////

pub async fn dispatch(
    cmd: &CmdBundle,
    cli: &mut global::cmds::CliData<'_, '_>,
) -> eyre::Result<()> {
    match cmd {
        CmdBundle::Create(local_args) => {
            cli_output(
                create_for_id(cli.grpc_conn, local_args).await?,
                &cli.args.format,
                global::cmds::Destination::Stdout(),
            )?;
        }
        CmdBundle::Delete(local_args) => {
            cli_output(
                delete(cli.grpc_conn, local_args).await?,
                &cli.args.format,
                global::cmds::Destination::Stdout(),
            )?;
        }
        CmdBundle::Rename(local_args) => {
            cli_output(
                rename(cli.grpc_conn, local_args).await?,
                &cli.args.format,
                global::cmds::Destination::Stdout(),
            )?;
        }
        CmdBundle::SetState(local_args) => {
            cli_output(
                set_state(cli.grpc_conn, local_args).await?,
                &cli.args.format,
                global::cmds::Destination::Stdout(),
            )?;
        }
        CmdBundle::Show(local_args) => {
            if local_args.identifier.is_some() {
                cli_output(
                    show_by_id_or_name(cli.grpc_conn, local_args).await?,
                    &cli.args.format,
                    global::cmds::Destination::Stdout(),
                )?;
            } else {
                cli_output(
                    show_all(cli.grpc_conn, local_args).await?,
                    &cli.args.format,
                    global::cmds::Destination::Stdout(),
                )?;
            }
        }
        CmdBundle::List(selector) => match selector {
            List::Machines(local_args) => {
                cli_output(
                    list_machines(cli.grpc_conn, local_args).await?,
                    &cli.args.format,
                    global::cmds::Destination::Stdout(),
                )?;
            }
            List::All(_) => {
                cli_output(
                    list(cli.grpc_conn).await?,
                    &cli.args.format,
                    global::cmds::Destination::Stdout(),
                )?;
            }
        },
    }
    Ok(())
}

///////////////////////////////////////////////////////////////////////////////
/// create_for_id creates a new measurement bundle associated with the
/// profile w/ the provided profile ID.
///////////////////////////////////////////////////////////////////////////////

pub async fn create_for_id(
    grpc_conn: &mut ForgeClientT,
    create: &Create,
) -> eyre::Result<MeasurementBundle> {
    // Prepare.
    let state: MeasurementBundleStatePb = match create.state {
        Some(input_state) => input_state.into(),
        None => MeasurementBundleStatePb::Active,
    };

    // Request.
    let request = CreateMeasurementBundleRequest {
        name: Some(create.name.clone()),
        profile_id: Some(create.profile_id.into()),
        pcr_values: PcrRegisterValue::to_pb_vec(&create.values),
        state: state.into(),
    };

    // Response.
    let response = grpc_conn
        .create_measurement_bundle(request)
        .await
        .map_err(|e| eyre::eyre!(e.to_string()))?;

    MeasurementBundle::from_grpc(response.get_ref().bundle.as_ref())
}

///////////////////////////////////////////////////////////////////////////////
/// delete deletes a measurement bundle with the provided ID.
///////////////////////////////////////////////////////////////////////////////

pub async fn delete(
    grpc_conn: &mut ForgeClientT,
    delete: &Delete,
) -> eyre::Result<MeasurementBundle> {
    // Request.
    let request = DeleteMeasurementBundleRequest {
        selector: Some(delete_measurement_bundle_request::Selector::BundleId(
            delete.bundle_id.into(),
        )),
    };

    // Response.
    let response = grpc_conn
        .delete_measurement_bundle(request)
        .await
        .map_err(|e| eyre::eyre!(e.to_string()))?;

    MeasurementBundle::from_grpc(response.get_ref().bundle.as_ref())
}

///////////////////////////////////////////////////////////////////////////////
/// rename renames a measurement bundle with the provided name or ID.
///////////////////////////////////////////////////////////////////////////////

pub async fn rename(
    grpc_conn: &mut ForgeClientT,
    rename: &Rename,
) -> eyre::Result<MeasurementBundle> {
    // Prepare.
    let selector = match get_identifier(rename)? {
        IdentifierType::ForId => {
            let bundle_id = MeasurementBundleId::from_str(&rename.identifier.clone())?;
            Some(rename_measurement_bundle_request::Selector::BundleId(
                bundle_id.into(),
            ))
        }
        IdentifierType::ForName => Some(rename_measurement_bundle_request::Selector::BundleName(
            rename.identifier.clone(),
        )),
        IdentifierType::Detect => match MeasurementBundleId::from_str(&rename.identifier.clone()) {
            Ok(bundle_id) => Some(rename_measurement_bundle_request::Selector::BundleId(
                bundle_id.into(),
            )),
            Err(_) => Some(rename_measurement_bundle_request::Selector::BundleName(
                rename.identifier.clone(),
            )),
        },
    };

    // Request.
    let request = RenameMeasurementBundleRequest {
        new_bundle_name: rename.new_bundle_name.clone(),
        selector,
    };

    // Response.
    let response = grpc_conn
        .rename_measurement_bundle(request)
        .await
        .map_err(|e| eyre::eyre!(e.to_string()))?;

    MeasurementBundle::from_grpc(response.get_ref().bundle.as_ref())
}

///////////////////////////////////////////////////////////////////////////////
/// set_state updates the state of the bundle (e.g. active, obsolete, retired).
///////////////////////////////////////////////////////////////////////////////

pub async fn set_state(
    grpc_conn: &mut ForgeClientT,
    set_state: &SetState,
) -> eyre::Result<MeasurementBundle> {
    // Prepare.
    let state: MeasurementBundleStatePb = set_state.state.into();

    let selector = match get_identifier(set_state)? {
        IdentifierType::ForId => {
            let bundle_id = MeasurementBundleId::from_str(&set_state.identifier.clone())?;
            Some(update_measurement_bundle_request::Selector::BundleId(
                bundle_id.into(),
            ))
        }
        IdentifierType::ForName => Some(update_measurement_bundle_request::Selector::BundleName(
            set_state.identifier.clone(),
        )),
        IdentifierType::Detect => {
            match MeasurementBundleId::from_str(&set_state.identifier.clone()) {
                Ok(bundle_id) => Some(update_measurement_bundle_request::Selector::BundleId(
                    bundle_id.into(),
                )),
                Err(_) => Some(update_measurement_bundle_request::Selector::BundleName(
                    set_state.identifier.clone(),
                )),
            }
        }
    };

    // Request.
    let request = UpdateMeasurementBundleRequest {
        state: state.into(),
        selector,
    };

    // Response.
    let response = grpc_conn
        .update_measurement_bundle(request)
        .await
        .map_err(|e| eyre::eyre!(e.to_string()))?;

    MeasurementBundle::from_grpc(response.get_ref().bundle.as_ref())
}

///////////////////////////////////////////////////////////////////////////////
/// show_by_id dumps all info about a bundle for the given ID or name.
///////////////////////////////////////////////////////////////////////////////

pub async fn show_by_id_or_name(
    grpc_conn: &mut ForgeClientT,
    show: &Show,
) -> eyre::Result<MeasurementBundle> {
    // Prepare.
    let identifier = show
        .identifier
        .as_ref()
        .ok_or(eyre::eyre!("identifier expected to be set here"))?;

    let selector = match get_identifier(show)? {
        IdentifierType::ForId => {
            let bundle_id = MeasurementBundleId::from_str(&identifier.clone())?;
            Some(show_measurement_bundle_request::Selector::BundleId(
                bundle_id.into(),
            ))
        }
        IdentifierType::ForName => Some(show_measurement_bundle_request::Selector::BundleName(
            identifier.clone(),
        )),
        IdentifierType::Detect => match MeasurementBundleId::from_str(&identifier.clone()) {
            Ok(bundle_id) => Some(show_measurement_bundle_request::Selector::BundleId(
                bundle_id.into(),
            )),
            Err(_) => Some(show_measurement_bundle_request::Selector::BundleName(
                identifier.clone(),
            )),
        },
    };

    // Request.
    let request = ShowMeasurementBundleRequest { selector };

    // Response.
    let response = grpc_conn
        .show_measurement_bundle(request)
        .await
        .map_err(|e| eyre::eyre!(e.to_string()))?;

    MeasurementBundle::from_grpc(response.get_ref().bundle.as_ref())
}

///////////////////////////////////////////////////////////////////////////////
/// show_all dumps all info about all bundles.
///////////////////////////////////////////////////////////////////////////////

pub async fn show_all(
    grpc_conn: &mut ForgeClientT,
    _get_by_id: &Show,
) -> eyre::Result<Vec<MeasurementBundle>> {
    // Request.
    let request = ShowMeasurementBundlesRequest {};

    // Response.
    grpc_conn
        .show_measurement_bundles(request)
        .await
        .map_err(|e| eyre::eyre!(e.to_string()))?
        .get_ref()
        .bundles
        .iter()
        .map(|bundle| {
            MeasurementBundle::try_from(bundle.clone()).map_err(|e| eyre::eyre!(e.to_string()))
        })
        .collect::<eyre::Result<Vec<MeasurementBundle>>>()
}

///////////////////////////////////////////////////////////////////////////////
/// list lists all bundle ids.
///////////////////////////////////////////////////////////////////////////////

pub async fn list(grpc_conn: &mut ForgeClientT) -> eyre::Result<Vec<MeasurementBundleRecord>> {
    // Request.
    let request = ListMeasurementBundlesRequest {};

    // Response.
    grpc_conn
        .list_measurement_bundles(request)
        .await
        .map_err(|e| eyre::eyre!(e.to_string()))?
        .get_ref()
        .bundles
        .iter()
        .map(|rec| {
            MeasurementBundleRecord::try_from(rec.clone())
                .map_err(|e| eyre::eyre!("conversion failed: {}", e))
        })
        .collect::<eyre::Result<Vec<MeasurementBundleRecord>>>()
}

///////////////////////////////////////////////////////////////////////////////
/// list_machines lists all machines associated with the provided
/// bundle ID or bundle name.
///////////////////////////////////////////////////////////////////////////////

pub async fn list_machines(
    grpc_conn: &mut ForgeClientT,
    list_machines: &ListMachines,
) -> eyre::Result<Vec<MockMachineId>> {
    // Prepare.
    let selector = match get_identifier(list_machines)? {
        IdentifierType::ForId => {
            let bundle_id = MeasurementBundleId::from_str(&list_machines.identifier.clone())?;
            Some(list_measurement_bundle_machines_request::Selector::BundleId(bundle_id.into()))
        }
        IdentifierType::ForName => Some(
            list_measurement_bundle_machines_request::Selector::BundleName(
                list_machines.identifier.clone(),
            ),
        ),
        IdentifierType::Detect => {
            match MeasurementBundleId::from_str(&list_machines.identifier.clone()) {
                Ok(bundle_id) => Some(
                    list_measurement_bundle_machines_request::Selector::BundleId(bundle_id.into()),
                ),
                Err(_) => Some(
                    list_measurement_bundle_machines_request::Selector::BundleName(
                        list_machines.identifier.clone(),
                    ),
                ),
            }
        }
    };

    // Request.
    let request = ListMeasurementBundleMachinesRequest { selector };

    // Response.
    Ok(grpc_conn
        .list_measurement_bundle_machines(request)
        .await
        .map_err(|e| eyre::eyre!(e.to_string()))?
        .get_ref()
        .machine_ids
        .iter()
        .map(|rec| MockMachineId(rec.clone()))
        .collect::<Vec<MockMachineId>>())
}
