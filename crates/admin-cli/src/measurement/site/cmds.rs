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
//! `measurement site` subcommand dispatcher + backing functions.
//!

use std::fs::File;
use std::io::BufReader;

use ::rpc::admin_cli::{CarbideCliResult, ToTable, cli_output, set_summary};
use ::rpc::protos::measured_boot::{
    AddMeasurementTrustedMachineRequest, AddMeasurementTrustedProfileRequest,
    ImportSiteMeasurementsRequest, MeasurementApprovedTypePb,
    RemoveMeasurementTrustedMachineRequest, RemoveMeasurementTrustedProfileRequest,
    remove_measurement_trusted_machine_request, remove_measurement_trusted_profile_request,
};
use measured_boot::records::{MeasurementApprovedMachineRecord, MeasurementApprovedProfileRecord};
use measured_boot::site::{ImportResult, SiteModel};
use serde::Serialize;

use crate::measurement::global;
use crate::measurement::site::args::{
    ApproveMachine, ApproveProfile, CmdSite, Export, Import, RemoveMachine,
    RemoveMachineByApprovalId, RemoveMachineByMachineId, RemoveProfile, RemoveProfileByApprovalId,
    RemoveProfileByProfileId, TrustedMachine, TrustedProfile,
};
use crate::rpc::ApiClient;

/// dispatch matches + dispatches the correct command
/// for this subcommand.
pub async fn dispatch(
    cmd: CmdSite,
    cli: &mut global::cmds::CliData<'_, '_>,
) -> CarbideCliResult<()> {
    match cmd {
        CmdSite::Import(local_args) => {
            cli_output(
                import(cli.grpc_conn, local_args).await?,
                &cli.args.format,
                ::rpc::admin_cli::Destination::Stdout(),
            )?;
        }
        CmdSite::Export(local_args) => {
            let dest: ::rpc::admin_cli::Destination = match &local_args.path {
                Some(path) => ::rpc::admin_cli::Destination::Path(path.clone()),
                None => ::rpc::admin_cli::Destination::Stdout(),
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
                    ::rpc::admin_cli::Destination::Stdout(),
                )?;
            }
            TrustedMachine::Remove(selector) => match selector {
                RemoveMachine::ByApprovalId(local_args) => {
                    cli_output(
                        remove_machine_by_approval_id(cli.grpc_conn, local_args).await?,
                        &cli.args.format,
                        ::rpc::admin_cli::Destination::Stdout(),
                    )?;
                }
                RemoveMachine::ByMachineId(local_args) => {
                    cli_output(
                        remove_machine_by_machine_id(cli.grpc_conn, local_args).await?,
                        &cli.args.format,
                        ::rpc::admin_cli::Destination::Stdout(),
                    )?;
                }
            },
            TrustedMachine::List(_) => {
                cli_output(
                    list_machines(cli.grpc_conn).await?,
                    &cli.args.format,
                    ::rpc::admin_cli::Destination::Stdout(),
                )?;
            }
        },
        CmdSite::TrustedProfile(selector) => match selector {
            TrustedProfile::Approve(local_args) => {
                cli_output(
                    approve_profile(cli.grpc_conn, local_args).await?,
                    &cli.args.format,
                    ::rpc::admin_cli::Destination::Stdout(),
                )?;
            }
            TrustedProfile::Remove(selector) => match selector {
                RemoveProfile::ByApprovalId(local_args) => {
                    cli_output(
                        remove_profile_by_approval_id(cli.grpc_conn, local_args).await?,
                        &cli.args.format,
                        ::rpc::admin_cli::Destination::Stdout(),
                    )?;
                }
                RemoveProfile::ByProfileId(local_args) => {
                    cli_output(
                        remove_profile_by_profile_id(cli.grpc_conn, local_args).await?,
                        &cli.args.format,
                        ::rpc::admin_cli::Destination::Stdout(),
                    )?;
                }
            },
            TrustedProfile::List(_) => {
                cli_output(
                    list_profiles(cli.grpc_conn).await?,
                    &cli.args.format,
                    ::rpc::admin_cli::Destination::Stdout(),
                )?;
            }
        },
    }
    Ok(())
}

/// Import imports a serialized SiteModel back into the database.
pub async fn import(grpc_conn: &ApiClient, import: Import) -> CarbideCliResult<ImportResult> {
    // Prepare.
    let reader = BufReader::new(File::open(import.path)?);
    let site_model: SiteModel = serde_json::from_reader(reader)?;

    // Request.
    let request = ImportSiteMeasurementsRequest {
        model: Some(
            SiteModel::to_pb(&site_model)
                .map_err(|e| crate::CarbideCliError::GenericError(e.to_string()))?,
        ),
    };

    // Response + process and return.
    Ok(ImportResult::from(
        &grpc_conn.0.import_site_measurements(request).await?,
    ))
}

/// Export grabs all of the data needed to build a SiteModel.
/// Summary is explicitly set to false so all data is serialized.
pub async fn export(grpc_conn: &ApiClient, _export: Export) -> CarbideCliResult<SiteModel> {
    // Prepare.
    // Force != summarized output, so all keys
    // accompany the serialized data.
    set_summary(false);

    let response = grpc_conn.0.export_site_measurements().await?;

    SiteModel::from_grpc(response.model.as_ref())
        .map_err(|e| crate::CarbideCliError::GenericError(e.to_string()))
}

/// approve_machine is used to approve a trusted machine by machine ID.
pub async fn approve_machine(
    grpc_conn: &ApiClient,
    approve: ApproveMachine,
) -> CarbideCliResult<MeasurementApprovedMachineRecord> {
    // Prepare.
    let approval_type: MeasurementApprovedTypePb = approve.approval_type.into();

    // Request.
    let request = AddMeasurementTrustedMachineRequest {
        machine_id: approve.machine_id.to_string(),
        approval_type: approval_type.into(),
        pcr_registers: approve.pcr_registers.unwrap_or_default(),
        comments: approve.comments.unwrap_or_default(),
    };

    // Response.
    let response = grpc_conn.0.add_measurement_trusted_machine(request).await?;

    // Process and return.
    MeasurementApprovedMachineRecord::from_grpc(response.approval_record.as_ref())
        .map_err(|e| crate::CarbideCliError::GenericError(e.to_string()))
}

/// remove_machine_by_approval_id removes a trusted machine approval
/// by its approval ID.
pub async fn remove_machine_by_approval_id(
    grpc_conn: &ApiClient,
    by_approval_id: RemoveMachineByApprovalId,
) -> CarbideCliResult<MeasurementApprovedMachineRecord> {
    // Request.
    let request = RemoveMeasurementTrustedMachineRequest {
        selector: Some(
            remove_measurement_trusted_machine_request::Selector::ApprovalId(
                by_approval_id.approval_id,
            ),
        ),
    };

    // Response.
    let response = grpc_conn
        .0
        .remove_measurement_trusted_machine(request)
        .await?;

    // Process and return.
    MeasurementApprovedMachineRecord::from_grpc(response.approval_record.as_ref())
        .map_err(|e| crate::CarbideCliError::GenericError(e.to_string()))
}

/// remove_machine_by_machine_id removes a trusted machine approval
/// by its machine ID.
pub async fn remove_machine_by_machine_id(
    grpc_conn: &ApiClient,
    by_machine_id: RemoveMachineByMachineId,
) -> CarbideCliResult<MeasurementApprovedMachineRecord> {
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
        .0
        .remove_measurement_trusted_machine(request)
        .await?;

    // Process and return.
    MeasurementApprovedMachineRecord::from_grpc(response.approval_record.as_ref())
        .map_err(|e| crate::CarbideCliError::GenericError(e.to_string()))
}

/// list_machines lists all trusted machine approvals.
pub async fn list_machines(
    grpc_conn: &ApiClient,
) -> CarbideCliResult<MeasurementApprovedMachineRecordList> {
    Ok(MeasurementApprovedMachineRecordList(
        grpc_conn
            .0
            .list_measurement_trusted_machines()
            .await?
            .approval_records
            .into_iter()
            .map(|record| {
                MeasurementApprovedMachineRecord::try_from(record)
                    .map_err(|e| crate::CarbideCliError::GenericError(e.to_string()))
            })
            .collect::<CarbideCliResult<Vec<MeasurementApprovedMachineRecord>>>()?,
    ))
}

/// approve_profile is used to approve a trusted profile by profile ID.
pub async fn approve_profile(
    grpc_conn: &ApiClient,
    approve: ApproveProfile,
) -> CarbideCliResult<MeasurementApprovedProfileRecord> {
    // Request.
    let approval_type: MeasurementApprovedTypePb = approve.approval_type.into();
    let request = AddMeasurementTrustedProfileRequest {
        profile_id: Some(approve.profile_id),
        approval_type: approval_type.into(),
        pcr_registers: approve.pcr_registers.as_ref().cloned(),
        comments: approve.comments.as_ref().cloned(),
    };

    // Response.
    let response = grpc_conn.0.add_measurement_trusted_profile(request).await?;

    // Process and return.
    MeasurementApprovedProfileRecord::from_grpc(response.approval_record.as_ref())
        .map_err(|e| crate::CarbideCliError::GenericError(e.to_string()))
}

/// remove_profile_by_approval_id removes a trusted profile approval
/// by its approval ID.
pub async fn remove_profile_by_approval_id(
    grpc_conn: &ApiClient,
    by_approval_id: RemoveProfileByApprovalId,
) -> CarbideCliResult<MeasurementApprovedProfileRecord> {
    // Request.
    let request = RemoveMeasurementTrustedProfileRequest {
        selector: Some(
            remove_measurement_trusted_profile_request::Selector::ApprovalId(
                by_approval_id.approval_id,
            ),
        ),
    };

    // Response.
    let response = grpc_conn
        .0
        .remove_measurement_trusted_profile(request)
        .await?;

    // Process and return.
    MeasurementApprovedProfileRecord::from_grpc(response.approval_record.as_ref())
        .map_err(|e| crate::CarbideCliError::GenericError(e.to_string()))
}

/// remove_profile_by_machine_id removes a trusted machine approval
/// by its profile ID.
pub async fn remove_profile_by_profile_id(
    grpc_conn: &ApiClient,
    by_profile_id: RemoveProfileByProfileId,
) -> CarbideCliResult<MeasurementApprovedProfileRecord> {
    // Request.
    let request = RemoveMeasurementTrustedProfileRequest {
        selector: Some(
            remove_measurement_trusted_profile_request::Selector::ProfileId(
                by_profile_id.profile_id,
            ),
        ),
    };

    // Response.
    let response = grpc_conn
        .0
        .remove_measurement_trusted_profile(request)
        .await?;

    // Process and return.
    MeasurementApprovedProfileRecord::from_grpc(response.approval_record.as_ref())
        .map_err(|e| crate::CarbideCliError::GenericError(e.to_string()))
}

/// list_profiles lists all trusted profile approvals.
pub async fn list_profiles(
    grpc_conn: &ApiClient,
) -> CarbideCliResult<MeasurementApprovedProfileRecordList> {
    Ok(MeasurementApprovedProfileRecordList(
        grpc_conn
            .0
            .list_measurement_trusted_profiles()
            .await?
            .approval_records
            .into_iter()
            .map(|record| {
                MeasurementApprovedProfileRecord::try_from(record)
                    .map_err(|e| crate::CarbideCliError::GenericError(e.to_string()))
            })
            .collect::<CarbideCliResult<Vec<MeasurementApprovedProfileRecord>>>()?,
    ))
}

/// MeasurementApprovedMachineRecordList just implements a newtype
/// pattern for a Vec<MeasurementApprovedMachineRecord> so the ToTable
/// trait can be leveraged (since we don't define Vec).
#[derive(Serialize)]
pub struct MeasurementApprovedMachineRecordList(Vec<MeasurementApprovedMachineRecord>);

impl ToTable for MeasurementApprovedMachineRecordList {
    fn into_table(self) -> eyre::Result<String> {
        let mut table = prettytable::Table::new();
        table.add_row(prettytable::row![
            "approval_id",
            "machine_id",
            "approval_type",
            "ts",
            "comments",
        ]);
        for rec in self.0 {
            let pcr_registers: String = match rec.pcr_registers {
                Some(pcr_registers) => pcr_registers,
                None => "".to_string(),
            };
            let comments: String = match rec.comments {
                Some(comments) => comments,
                None => "".to_string(),
            };
            table.add_row(prettytable::row![
                rec.approval_id,
                rec.machine_id,
                rec.approval_type,
                rec.ts,
                pcr_registers,
                comments,
            ]);
        }
        Ok(table.to_string())
    }
}

/// MeasurementApprovedProfileRecordList just implements a newtype
/// pattern for a Vec<MeasurementApprovedProfileRecord> so the ToTable
/// trait can be leveraged (since we don't define Vec).
#[derive(Serialize)]
pub struct MeasurementApprovedProfileRecordList(Vec<MeasurementApprovedProfileRecord>);

impl ToTable for MeasurementApprovedProfileRecordList {
    fn into_table(self) -> eyre::Result<String> {
        let mut table = prettytable::Table::new();
        table.add_row(prettytable::row![
            "approval_id",
            "profile_id",
            "approval_type",
            "ts",
            "comments",
        ]);
        for rec in self.0 {
            let pcr_registers: String = match rec.pcr_registers {
                Some(pcr_registers) => pcr_registers,
                None => "".to_string(),
            };
            let comments: String = match rec.comments {
                Some(comments) => comments,
                None => "".to_string(),
            };
            table.add_row(prettytable::row![
                rec.approval_id,
                rec.profile_id,
                rec.approval_type,
                rec.ts,
                pcr_registers,
                comments,
            ]);
        }
        Ok(table.to_string())
    }
}
