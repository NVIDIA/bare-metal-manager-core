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
//! `measurement report` subcommand dispatcher + backing functions.
//!

use crate::measurement::global;
use crate::measurement::global::cmds::cli_output;
use crate::measurement::report::args::{
    CmdReport, Create, Delete, List, ListMachines, Match, Promote, Revoke, ShowFor, ShowForId,
    ShowForMachine,
};
use ::rpc::forge_tls_client::ForgeClientT;
use ::rpc::protos::measured_boot::list_measurement_report_request;
use ::rpc::protos::measured_boot::{
    CreateMeasurementReportRequest, DeleteMeasurementReportRequest, ListMeasurementReportRequest,
    MatchMeasurementReportRequest, PromoteMeasurementReportRequest, RevokeMeasurementReportRequest,
    ShowMeasurementReportForIdRequest, ShowMeasurementReportsForMachineRequest,
    ShowMeasurementReportsRequest,
};
use carbide::measured_boot::dto::records::MeasurementReportRecord;
use carbide::measured_boot::interface::common::PcrRegisterValue;
use carbide::measured_boot::model::bundle::MeasurementBundle;
use carbide::measured_boot::model::report::MeasurementReport;

///////////////////////////////////////////////////////////////////////////////
/// dispatch matches + dispatches the correct command for
/// the `bundle` subcommand (e.g. create, delete, set-state).
///////////////////////////////////////////////////////////////////////////////

pub async fn dispatch(
    cmd: &CmdReport,
    cli: &mut global::cmds::CliData<'_, '_>,
) -> eyre::Result<()> {
    match cmd {
        CmdReport::Create(local_args) => {
            cli_output(
                create_for_id(cli.grpc_conn, local_args).await?,
                &cli.args.format,
                global::cmds::Destination::Stdout(),
            )?;
        }
        CmdReport::Delete(local_args) => {
            cli_output(
                delete(cli.grpc_conn, local_args).await?,
                &cli.args.format,
                global::cmds::Destination::Stdout(),
            )?;
        }
        CmdReport::Promote(local_args) => {
            cli_output(
                promote(cli.grpc_conn, local_args).await?,
                &cli.args.format,
                global::cmds::Destination::Stdout(),
            )?;
        }
        CmdReport::Revoke(local_args) => {
            cli_output(
                revoke(cli.grpc_conn, local_args).await?,
                &cli.args.format,
                global::cmds::Destination::Stdout(),
            )?;
        }
        CmdReport::Show(selector) => match selector {
            ShowFor::Id(local_args) => {
                cli_output(
                    show_for_id(cli.grpc_conn, local_args).await?,
                    &cli.args.format,
                    global::cmds::Destination::Stdout(),
                )?;
            }
            ShowFor::Machine(local_args) => {
                cli_output(
                    show_for_machine(cli.grpc_conn, local_args).await?,
                    &cli.args.format,
                    global::cmds::Destination::Stdout(),
                )?;
            }
            ShowFor::All => cli_output(
                show_all(cli.grpc_conn).await?,
                &cli.args.format,
                global::cmds::Destination::Stdout(),
            )?,
        },
        CmdReport::List(selector) => match selector {
            List::Machines(local_args) => {
                cli_output(
                    list_machines(cli.grpc_conn, local_args).await?,
                    &cli.args.format,
                    global::cmds::Destination::Stdout(),
                )?;
            }
            List::All(_) => {
                cli_output(
                    list_all(cli.grpc_conn).await?,
                    &cli.args.format,
                    global::cmds::Destination::Stdout(),
                )?;
            }
        },
        CmdReport::Match(local_args) => {
            cli_output(
                match_values(cli.grpc_conn, local_args).await?,
                &cli.args.format,
                global::cmds::Destination::Stdout(),
            )?;
        }
    }
    Ok(())
}

///////////////////////////////////////////////////////////////////////////////
/// create_for_id creates a new measurement report.
///////////////////////////////////////////////////////////////////////////////

pub async fn create_for_id(
    grpc_conn: &mut ForgeClientT,
    create: &Create,
) -> eyre::Result<MeasurementReport> {
    // Request.
    let request = CreateMeasurementReportRequest {
        machine_id: create.machine_id.to_string(),
        pcr_values: PcrRegisterValue::to_pb_vec(&create.values),
    };

    // Response.
    let response = grpc_conn
        .create_measurement_report(request)
        .await
        .map_err(|e| eyre::eyre!(e.to_string()))?;

    MeasurementReport::from_grpc(response.get_ref().report.as_ref())
}

///////////////////////////////////////////////////////////////////////////////
/// delete deletes a measurement report with the provided ID.
///////////////////////////////////////////////////////////////////////////////

pub async fn delete(
    grpc_conn: &mut ForgeClientT,
    delete: &Delete,
) -> eyre::Result<MeasurementReport> {
    // Request.
    let request = DeleteMeasurementReportRequest {
        report_id: Some(delete.report_id.into()),
    };

    // Response.
    let response = grpc_conn
        .delete_measurement_report(request)
        .await
        .map_err(|e| eyre::eyre!(e.to_string()))?;

    MeasurementReport::from_grpc(response.get_ref().report.as_ref())
}

///////////////////////////////////////////////////////////////////////////////
/// promote promotes a report to an active bundle.
///
/// `report promote <report-id> [pcr-selector]`
///////////////////////////////////////////////////////////////////////////////

pub async fn promote(
    grpc_conn: &mut ForgeClientT,
    promote: &Promote,
) -> eyre::Result<MeasurementBundle> {
    // Request.
    let request = PromoteMeasurementReportRequest {
        report_id: Some(promote.report_id.into()),
        pcr_registers: match &promote.pcr_registers {
            None => "".to_string(),
            Some(pcr_set) => pcr_set.to_string(),
        },
    };

    // Response.
    let response = grpc_conn
        .promote_measurement_report(request)
        .await
        .map_err(|e| eyre::eyre!(e.to_string()))?;

    MeasurementBundle::from_grpc(response.get_ref().bundle.as_ref())
}

///////////////////////////////////////////////////////////////////////////////
/// revoke "promotes" a journal entry into a revoked bundle,
/// which is a way of being able to say "any journals that come in
/// matching this should be marked as rejected.
///
/// `journal revoke <journal-id> [pcr-selector]`
///////////////////////////////////////////////////////////////////////////////

pub async fn revoke(
    grpc_conn: &mut ForgeClientT,
    revoke: &Revoke,
) -> eyre::Result<MeasurementBundle> {
    // Request.
    let request = RevokeMeasurementReportRequest {
        report_id: Some(revoke.report_id.into()),
        pcr_registers: match &revoke.pcr_registers {
            None => "".to_string(),
            Some(pcr_set) => pcr_set.to_string(),
        },
    };

    // Response.
    let response = grpc_conn
        .revoke_measurement_report(request)
        .await
        .map_err(|e| eyre::eyre!(e.to_string()))?;

    MeasurementBundle::from_grpc(response.get_ref().bundle.as_ref())
}

///////////////////////////////////////////////////////////////////////////////
/// show_for_id dumps all info about a report for the given ID.
///////////////////////////////////////////////////////////////////////////////

pub async fn show_for_id(
    grpc_conn: &mut ForgeClientT,
    show_for_id: &ShowForId,
) -> eyre::Result<MeasurementReport> {
    // Request.
    let request = ShowMeasurementReportForIdRequest {
        report_id: Some(show_for_id.report_id.into()),
    };

    // Response.
    let response = grpc_conn
        .show_measurement_report_for_id(request)
        .await
        .map_err(|e| eyre::eyre!(e.to_string()))?;

    MeasurementReport::from_grpc(response.get_ref().report.as_ref())
}

///////////////////////////////////////////////////////////////////////////////
/// show_for_machine dumps reports for a given machine.
///////////////////////////////////////////////////////////////////////////////

pub async fn show_for_machine(
    grpc_conn: &mut ForgeClientT,
    show_for_machine: &ShowForMachine,
) -> eyre::Result<Vec<MeasurementReport>> {
    // Request.
    let request = ShowMeasurementReportsForMachineRequest {
        machine_id: show_for_machine.machine_id.to_string(),
    };

    // Response.
    grpc_conn
        .show_measurement_reports_for_machine(request)
        .await
        .map_err(|e| eyre::eyre!(e.to_string()))?
        .get_ref()
        .reports
        .iter()
        .map(|report| {
            MeasurementReport::try_from(report.clone())
                .map_err(|e| eyre::eyre!("conversion failed: {}", e))
        })
        .collect::<eyre::Result<Vec<MeasurementReport>>>()
}

///////////////////////////////////////////////////////////////////////////////
/// show_all dumps all info about all reports.
///////////////////////////////////////////////////////////////////////////////

pub async fn show_all(grpc_conn: &mut ForgeClientT) -> eyre::Result<Vec<MeasurementReport>> {
    // Request.
    let request = ShowMeasurementReportsRequest {};

    // Response.
    grpc_conn
        .show_measurement_reports(request)
        .await
        .map_err(|e| eyre::eyre!(e.to_string()))?
        .get_ref()
        .reports
        .iter()
        .map(|report| {
            MeasurementReport::try_from(report.clone())
                .map_err(|e| eyre::eyre!("conversion failed: {}", e))
        })
        .collect::<eyre::Result<Vec<MeasurementReport>>>()
}

///////////////////////////////////////////////////////////////////////////////
/// list lists all bundle ids.
///////////////////////////////////////////////////////////////////////////////

pub async fn list_all(grpc_conn: &mut ForgeClientT) -> eyre::Result<Vec<MeasurementReportRecord>> {
    // Request.
    let request = ListMeasurementReportRequest { selector: None };

    // Response.
    grpc_conn
        .list_measurement_report(request)
        .await
        .map_err(|e| eyre::eyre!(e.to_string()))?
        .get_ref()
        .reports
        .iter()
        .map(|report| {
            MeasurementReportRecord::try_from(report.clone())
                .map_err(|e| eyre::eyre!("conversion failed: {}", e))
        })
        .collect::<eyre::Result<Vec<MeasurementReportRecord>>>()
}

///////////////////////////////////////////////////////////////////////////////
/// list_machines lists all reports for the given machine ID.
///////////////////////////////////////////////////////////////////////////////

pub async fn list_machines(
    grpc_conn: &mut ForgeClientT,
    list_machines: &ListMachines,
) -> eyre::Result<Vec<MeasurementReportRecord>> {
    // Request.
    let request = ListMeasurementReportRequest {
        selector: Some(list_measurement_report_request::Selector::MachineId(
            list_machines.machine_id.to_string(),
        )),
    };

    // Response.
    grpc_conn
        .list_measurement_report(request)
        .await
        .map_err(|e| eyre::eyre!(e.to_string()))?
        .get_ref()
        .reports
        .iter()
        .map(|report| {
            MeasurementReportRecord::try_from(report.clone())
                .map_err(|e| eyre::eyre!("conversion failed: {}", e))
        })
        .collect::<eyre::Result<Vec<MeasurementReportRecord>>>()
}

///////////////////////////////////////////////////////////////////////////////
/// match_values matches all reports with the provided PCR values.
///
/// `report match <pcr_register:val>,...`
///////////////////////////////////////////////////////////////////////////////`
pub async fn match_values(
    grpc_conn: &mut ForgeClientT,
    match_args: &Match,
) -> eyre::Result<Vec<MeasurementReportRecord>> {
    // Request.
    let request = MatchMeasurementReportRequest {
        pcr_values: PcrRegisterValue::to_pb_vec(&match_args.values),
    };

    // Response.
    grpc_conn
        .match_measurement_report(request)
        .await
        .map_err(|e| eyre::eyre!(e.to_string()))?
        .get_ref()
        .reports
        .iter()
        .map(|report| {
            MeasurementReportRecord::try_from(report.clone())
                .map_err(|e| eyre::eyre!("conversion failed: {}", e))
        })
        .collect::<eyre::Result<Vec<MeasurementReportRecord>>>()
}
