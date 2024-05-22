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
//! `measurement site` subcommand dispatcher + backing functions.
//!

use crate::measurement::global;
use crate::measurement::global::cmds::cli_output;
use crate::measurement::site::args::{
    ApproveMachine, ApproveProfile, CmdSite, Export, Import, RemoveMachine,
    RemoveMachineByApprovalId, RemoveMachineByMachineId, RemoveProfile, RemoveProfileByApprovalId,
    RemoveProfileByProfileId, TrustedMachine, TrustedProfile,
};
use carbide::measured_boot::model::site::{ImportResult, SiteModel};

use carbide::measured_boot::dto::records::{
    MeasurementApprovedMachineRecord, MeasurementApprovedProfileRecord,
};

use ::rpc::forge_tls_client::ForgeClientT;
use ::rpc::protos::measured_boot::remove_measurement_trusted_machine_request;
use ::rpc::protos::measured_boot::remove_measurement_trusted_profile_request;
use ::rpc::protos::measured_boot::{
    AddMeasurementTrustedMachineRequest, AddMeasurementTrustedProfileRequest,
    ExportSiteMeasurementsRequest, ImportSiteMeasurementsRequest,
    ListMeasurementTrustedMachinesRequest, ListMeasurementTrustedProfilesRequest,
    MeasurementApprovedTypePb, RemoveMeasurementTrustedMachineRequest,
    RemoveMeasurementTrustedProfileRequest,
};
use std::fs::File;
use std::io::BufReader;
use utils::admin_cli::set_summary;

/// dispatch matches + dispatches the correct command
/// for this subcommand.
pub async fn dispatch(cmd: &CmdSite, cli: &mut global::cmds::CliData<'_, '_>) -> eyre::Result<()> {
    match cmd {
        CmdSite::Import(local_args) => {
            cli_output(
                import(cli.grpc_conn, local_args).await?,
                &cli.args.format,
                global::cmds::Destination::Stdout(),
            )?;
        }
        CmdSite::Export(local_args) => {
            let dest: global::cmds::Destination = match &local_args.path {
                Some(path) => global::cmds::Destination::Path(path.clone()),
                None => global::cmds::Destination::Stdout(),
            };
            cli_output(
                export(cli.grpc_conn, local_args).await?,
                &cli.args.format,
                dest,
            )?;
        }
        CmdSite::TrustedMachine(selector) => match selector {
            TrustedMachine::Approve(local_args) => {
                cli_output(
                    approve_machine(cli.grpc_conn, local_args).await?,
                    &cli.args.format,
                    global::cmds::Destination::Stdout(),
                )?;
            }
            TrustedMachine::Remove(selector) => match selector {
                RemoveMachine::ByApprovalId(local_args) => {
                    cli_output(
                        remove_machine_by_approval_id(cli.grpc_conn, local_args).await?,
                        &cli.args.format,
                        global::cmds::Destination::Stdout(),
                    )?;
                }
                RemoveMachine::ByMachineId(local_args) => {
                    cli_output(
                        remove_machine_by_machine_id(cli.grpc_conn, local_args).await?,
                        &cli.args.format,
                        global::cmds::Destination::Stdout(),
                    )?;
                }
            },
            TrustedMachine::List(_) => {
                cli_output(
                    list_machines(cli.grpc_conn).await?,
                    &cli.args.format,
                    global::cmds::Destination::Stdout(),
                )?;
            }
        },
        CmdSite::TrustedProfile(selector) => match selector {
            TrustedProfile::Approve(local_args) => {
                cli_output(
                    approve_profile(cli.grpc_conn, local_args).await?,
                    &cli.args.format,
                    global::cmds::Destination::Stdout(),
                )?;
            }
            TrustedProfile::Remove(selector) => match selector {
                RemoveProfile::ByApprovalId(local_args) => {
                    cli_output(
                        remove_profile_by_approval_id(cli.grpc_conn, local_args).await?,
                        &cli.args.format,
                        global::cmds::Destination::Stdout(),
                    )?;
                }
                RemoveProfile::ByProfileId(local_args) => {
                    cli_output(
                        remove_profile_by_profile_id(cli.grpc_conn, local_args).await?,
                        &cli.args.format,
                        global::cmds::Destination::Stdout(),
                    )?;
                }
            },
            TrustedProfile::List(_) => {
                cli_output(
                    list_profiles(cli.grpc_conn).await?,
                    &cli.args.format,
                    global::cmds::Destination::Stdout(),
                )?;
            }
        },
    }
    Ok(())
}

/// Import imports a serialized SiteModel back into the database.
pub async fn import(grpc_conn: &mut ForgeClientT, import: &Import) -> eyre::Result<ImportResult> {
    // Prepare.
    let reader = BufReader::new(File::open(import.path.clone())?);
    let site_model: SiteModel = serde_json::from_reader(reader)?;

    // Request.
    let request = ImportSiteMeasurementsRequest {
        model: Some(SiteModel::to_pb(&site_model)?),
    };

    // Response + process and return.
    Ok(ImportResult::from(
        grpc_conn.import_site_measurements(request).await?.get_ref(),
    ))
}

/// Export grabs all of the data needed to build a SiteModel.
/// Summary is explicitly set to false so all data is serialized.
pub async fn export(grpc_conn: &mut ForgeClientT, _export: &Export) -> eyre::Result<SiteModel> {
    // Prepare.
    // Force != summarized output, so all keys
    // accompany the serialized data.
    set_summary(false);

    // Request.
    let request = ExportSiteMeasurementsRequest {};

    // Response.
    let response = grpc_conn
        .export_site_measurements(request)
        .await
        .map_err(|e| eyre::eyre!(e.to_string()))?;

    SiteModel::from_grpc(response.get_ref().model.as_ref())
}

///////////////////////////////////////////////////////////////////////////////
/// approve_machine is used to approve a trusted machine by machine ID.
///////////////////////////////////////////////////////////////////////////////

pub async fn approve_machine(
    grpc_conn: &mut ForgeClientT,
    approve: &ApproveMachine,
) -> eyre::Result<MeasurementApprovedMachineRecord> {
    // Prepare.
    let approval_type: MeasurementApprovedTypePb = approve.approval_type.into();

    // Request.
    let request = AddMeasurementTrustedMachineRequest {
        machine_id: approve.machine_id.to_string(),
        approval_type: approval_type.into(),
        pcr_registers: approve.pcr_registers.clone().unwrap_or_default(),
        comments: approve.comments.clone().unwrap_or_default(),
    };

    // Response.
    let response = grpc_conn
        .add_measurement_trusted_machine(request)
        .await
        .map_err(|e| eyre::eyre!(e.to_string()))?;

    // Process and return.
    Ok(MeasurementApprovedMachineRecord::from_grpc(
        response.get_ref().approval_record.as_ref(),
    )?)
}

///////////////////////////////////////////////////////////////////////////////
/// remove_machine_by_approval_id removes a trusted machine approval
/// by its approval ID.
///////////////////////////////////////////////////////////////////////////////

pub async fn remove_machine_by_approval_id(
    grpc_conn: &mut ForgeClientT,
    by_approval_id: &RemoveMachineByApprovalId,
) -> eyre::Result<MeasurementApprovedMachineRecord> {
    // Request.
    let request = RemoveMeasurementTrustedMachineRequest {
        selector: Some(
            remove_measurement_trusted_machine_request::Selector::ApprovalId(
                by_approval_id.approval_id.into(),
            ),
        ),
    };

    // Response.
    let response = grpc_conn
        .remove_measurement_trusted_machine(request)
        .await
        .map_err(|e| eyre::eyre!(e.to_string()))?;

    // Process and return.
    Ok(MeasurementApprovedMachineRecord::from_grpc(
        response.get_ref().approval_record.as_ref(),
    )?)
}

///////////////////////////////////////////////////////////////////////////////
/// remove_machine_by_machine_id removes a trusted machine approval
/// by its machine ID.
///////////////////////////////////////////////////////////////////////////////

pub async fn remove_machine_by_machine_id(
    grpc_conn: &mut ForgeClientT,
    by_machine_id: &RemoveMachineByMachineId,
) -> eyre::Result<MeasurementApprovedMachineRecord> {
    // Request
    let request = RemoveMeasurementTrustedMachineRequest {
        selector: Some(
            remove_measurement_trusted_machine_request::Selector::MachineId(
                by_machine_id.machine_id.to_string(),
            ),
        ),
    };

    // Response
    let response = grpc_conn
        .remove_measurement_trusted_machine(request)
        .await
        .map_err(|e| eyre::eyre!(e.to_string()))?;

    // Process and return.
    Ok(MeasurementApprovedMachineRecord::from_grpc(
        response.get_ref().approval_record.as_ref(),
    )?)
}

///////////////////////////////////////////////////////////////////////////////
/// list_machines lists all trusted machine approvals.
///////////////////////////////////////////////////////////////////////////////

pub async fn list_machines(
    grpc_conn: &mut ForgeClientT,
) -> eyre::Result<Vec<MeasurementApprovedMachineRecord>> {
    // Request.
    let request = ListMeasurementTrustedMachinesRequest {};

    // Response.
    grpc_conn
        .list_measurement_trusted_machines(request)
        .await
        .map_err(|e| eyre::eyre!(e.to_string()))?
        .get_ref()
        .approval_records
        .iter()
        .map(|record| {
            MeasurementApprovedMachineRecord::try_from(record.clone())
                .map_err(|e| eyre::eyre!("failed to translate record: {}", e))
        })
        .collect::<eyre::Result<Vec<MeasurementApprovedMachineRecord>>>()
}

///////////////////////////////////////////////////////////////////////////////
/// approve_profile is used to approve a trusted profile by profile ID.
///////////////////////////////////////////////////////////////////////////////

pub async fn approve_profile(
    grpc_conn: &mut ForgeClientT,
    approve: &ApproveProfile,
) -> eyre::Result<MeasurementApprovedProfileRecord> {
    // Request.
    let approval_type: MeasurementApprovedTypePb = approve.approval_type.into();
    let request = AddMeasurementTrustedProfileRequest {
        profile_id: Some(approve.profile_id.into()),
        approval_type: approval_type.into(),
        pcr_registers: approve.pcr_registers.as_ref().cloned(),
        comments: approve.comments.as_ref().cloned(),
    };

    // Response.
    let response = grpc_conn
        .add_measurement_trusted_profile(request)
        .await
        .map_err(|e| eyre::eyre!(e.to_string()))?;

    // Process and return.
    Ok(MeasurementApprovedProfileRecord::from_grpc(
        response.get_ref().approval_record.as_ref(),
    )?)
}

///////////////////////////////////////////////////////////////////////////////
/// remove_profile_by_approval_id removes a trusted profile approval
/// by its approval ID.
///////////////////////////////////////////////////////////////////////////////

pub async fn remove_profile_by_approval_id(
    grpc_conn: &mut ForgeClientT,
    by_approval_id: &RemoveProfileByApprovalId,
) -> eyre::Result<MeasurementApprovedProfileRecord> {
    // Request.
    let request = RemoveMeasurementTrustedProfileRequest {
        selector: Some(
            remove_measurement_trusted_profile_request::Selector::ApprovalId(
                by_approval_id.approval_id.into(),
            ),
        ),
    };

    // Response.
    let response = grpc_conn
        .remove_measurement_trusted_profile(request)
        .await
        .map_err(|e| eyre::eyre!(e.to_string()))?;

    // Process and return.
    Ok(MeasurementApprovedProfileRecord::from_grpc(
        response.get_ref().approval_record.as_ref(),
    )?)
}

///////////////////////////////////////////////////////////////////////////////
/// remove_profile_by_machine_id removes a trusted machine approval
/// by its profile ID.
///////////////////////////////////////////////////////////////////////////////

pub async fn remove_profile_by_profile_id(
    grpc_conn: &mut ForgeClientT,
    by_profile_id: &RemoveProfileByProfileId,
) -> eyre::Result<MeasurementApprovedProfileRecord> {
    // Request.
    let request = RemoveMeasurementTrustedProfileRequest {
        selector: Some(
            remove_measurement_trusted_profile_request::Selector::ProfileId(
                by_profile_id.profile_id.into(),
            ),
        ),
    };

    // Response.
    let response = grpc_conn
        .remove_measurement_trusted_profile(request)
        .await
        .map_err(|e| eyre::eyre!(e.to_string()))?;

    // Process and return.
    Ok(MeasurementApprovedProfileRecord::from_grpc(
        response.get_ref().approval_record.as_ref(),
    )?)
}

///////////////////////////////////////////////////////////////////////////////
/// list_profiles lists all trusted profile approvals.
///////////////////////////////////////////////////////////////////////////////

pub async fn list_profiles(
    grpc_conn: &mut ForgeClientT,
) -> eyre::Result<Vec<MeasurementApprovedProfileRecord>> {
    // Request.
    let request = ListMeasurementTrustedProfilesRequest {};

    // Response.
    grpc_conn
        .list_measurement_trusted_profiles(request)
        .await
        .map_err(|e| eyre::eyre!(e.to_string()))?
        .get_ref()
        .approval_records
        .iter()
        .map(|record| {
            MeasurementApprovedProfileRecord::try_from(record.clone())
                .map_err(|e| eyre::eyre!("failed to translate record: {}", e))
        })
        .collect::<eyre::Result<Vec<MeasurementApprovedProfileRecord>>>()
}
