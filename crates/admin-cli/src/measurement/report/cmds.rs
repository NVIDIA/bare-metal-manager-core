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

use ::rpc::admin_cli::{CarbideCliError, CarbideCliResult, ToTable, cli_output};
use ::rpc::protos::measured_boot::{
    CreateMeasurementReportRequest, DeleteMeasurementReportRequest, ListMeasurementReportRequest,
    MatchMeasurementReportRequest, PromoteMeasurementReportRequest, RevokeMeasurementReportRequest,
    ShowMeasurementReportForIdRequest, ShowMeasurementReportsForMachineRequest,
    list_measurement_report_request,
};
use measured_boot::bundle::MeasurementBundle;
use measured_boot::records::MeasurementReportRecord;
use measured_boot::report::MeasurementReport;
use serde::Serialize;

use crate::measurement::global;
use crate::measurement::report::args::{
    CmdReport, Create, Delete, List, ListMachines, Match, Promote, Revoke, ShowFor, ShowForId,
    ShowForMachine,
};
use crate::rpc::ApiClient;

/// dispatch matches + dispatches the correct command for
/// the `bundle` subcommand (e.g. create, delete, set-state).
pub async fn dispatch(
    cmd: CmdReport,
    cli: &mut global::cmds::CliData<'_, '_>,
) -> CarbideCliResult<()> {
    match cmd {
        CmdReport::Create(local_args) => {
            cli_output(
                create_for_id(cli.grpc_conn, local_args).await?,
                &cli.args.format,
                ::rpc::admin_cli::Destination::Stdout(),
            )?;
        }
        CmdReport::Delete(local_args) => {
            cli_output(
                delete(cli.grpc_conn, local_args).await?,
                &cli.args.format,
                ::rpc::admin_cli::Destination::Stdout(),
            )?;
        }
        CmdReport::Promote(local_args) => {
            cli_output(
                promote(cli.grpc_conn, local_args).await?,
                &cli.args.format,
                ::rpc::admin_cli::Destination::Stdout(),
            )?;
        }
        CmdReport::Revoke(local_args) => {
            cli_output(
                revoke(cli.grpc_conn, local_args).await?,
                &cli.args.format,
                ::rpc::admin_cli::Destination::Stdout(),
            )?;
        }
        CmdReport::Show(selector) => match selector {
            ShowFor::Id(local_args) => {
                cli_output(
                    show_for_id(cli.grpc_conn, local_args).await?,
                    &cli.args.format,
                    ::rpc::admin_cli::Destination::Stdout(),
                )?;
            }
            ShowFor::Machine(local_args) => {
                cli_output(
                    show_for_machine(cli.grpc_conn, local_args).await?,
                    &cli.args.format,
                    ::rpc::admin_cli::Destination::Stdout(),
                )?;
            }
            ShowFor::All => cli_output(
                show_all(cli.grpc_conn).await?,
                &cli.args.format,
                ::rpc::admin_cli::Destination::Stdout(),
            )?,
        },
        CmdReport::List(selector) => match selector {
            List::Machines(local_args) => {
                cli_output(
                    list_machines(cli.grpc_conn, local_args).await?,
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
        CmdReport::Match(local_args) => {
            cli_output(
                match_values(cli.grpc_conn, local_args).await?,
                &cli.args.format,
                ::rpc::admin_cli::Destination::Stdout(),
            )?;
        }
    }
    Ok(())
}

/// create_for_id creates a new measurement report.
pub async fn create_for_id(
    grpc_conn: &ApiClient,
    create: Create,
) -> CarbideCliResult<MeasurementReport> {
    // Request.
    let request = CreateMeasurementReportRequest {
        machine_id: create.machine_id.to_string(),
        pcr_values: create.values.into_iter().map(Into::into).collect(),
    };

    // Response.
    let response = grpc_conn.0.create_measurement_report(request).await?;

    MeasurementReport::from_grpc(response.report.as_ref())
        .map_err(|e| crate::CarbideCliError::GenericError(e.to_string()))
}

/// delete deletes a measurement report with the provided ID.
pub async fn delete(grpc_conn: &ApiClient, delete: Delete) -> CarbideCliResult<MeasurementReport> {
    // Request.
    let request = DeleteMeasurementReportRequest {
        report_id: Some(delete.report_id),
    };

    // Response.
    let response = grpc_conn.0.delete_measurement_report(request).await?;

    MeasurementReport::from_grpc(response.report.as_ref())
        .map_err(|e| crate::CarbideCliError::GenericError(e.to_string()))
}

/// promote promotes a report to an active bundle.
///
/// `report promote <report-id> [pcr-selector]`
pub async fn promote(
    grpc_conn: &ApiClient,
    promote: Promote,
) -> CarbideCliResult<MeasurementBundle> {
    // Request.
    let request = PromoteMeasurementReportRequest {
        report_id: Some(promote.report_id),
        pcr_registers: match &promote.pcr_registers {
            None => "".to_string(),
            Some(pcr_set) => pcr_set.to_string(),
        },
    };

    // Response.
    let response = grpc_conn.0.promote_measurement_report(request).await?;

    MeasurementBundle::from_grpc(response.bundle.as_ref())
        .map_err(|e| crate::CarbideCliError::GenericError(e.to_string()))
}

/// revoke "promotes" a journal entry into a revoked bundle,
/// which is a way of being able to say "any journals that come in
/// matching this should be marked as rejected.
///
/// `journal revoke <journal-id> [pcr-selector]`
pub async fn revoke(grpc_conn: &ApiClient, revoke: Revoke) -> CarbideCliResult<MeasurementBundle> {
    // Request.
    let request = RevokeMeasurementReportRequest {
        report_id: Some(revoke.report_id),
        pcr_registers: match &revoke.pcr_registers {
            None => "".to_string(),
            Some(pcr_set) => pcr_set.to_string(),
        },
    };

    // Response.
    let response = grpc_conn.0.revoke_measurement_report(request).await?;

    MeasurementBundle::from_grpc(response.bundle.as_ref())
        .map_err(|e| crate::CarbideCliError::GenericError(e.to_string()))
}

/// show_for_id dumps all info about a report for the given ID.
pub async fn show_for_id(
    grpc_conn: &ApiClient,
    show_for_id: ShowForId,
) -> CarbideCliResult<MeasurementReport> {
    // Request.
    let request = ShowMeasurementReportForIdRequest {
        report_id: Some(show_for_id.report_id),
    };

    // Response.
    let response = grpc_conn.0.show_measurement_report_for_id(request).await?;

    MeasurementReport::from_grpc(response.report.as_ref())
        .map_err(|e| crate::CarbideCliError::GenericError(e.to_string()))
}

/// show_for_machine dumps reports for a given machine.
pub async fn show_for_machine(
    grpc_conn: &ApiClient,
    show_for_machine: ShowForMachine,
) -> CarbideCliResult<MeasurementReportList> {
    // Request.
    let request = ShowMeasurementReportsForMachineRequest {
        machine_id: show_for_machine.machine_id.to_string(),
    };

    // Response.
    Ok(MeasurementReportList(
        grpc_conn
            .0
            .show_measurement_reports_for_machine(request)
            .await?
            .reports
            .into_iter()
            .map(|report| {
                MeasurementReport::try_from(report)
                    .map_err(|e| CarbideCliError::GenericError(format!("conversion failed: {e}")))
            })
            .collect::<CarbideCliResult<Vec<MeasurementReport>>>()?,
    ))
}

/// show_all dumps all info about all reports.
pub async fn show_all(grpc_conn: &ApiClient) -> CarbideCliResult<MeasurementReportList> {
    Ok(MeasurementReportList(
        grpc_conn
            .0
            .show_measurement_reports()
            .await?
            .reports
            .into_iter()
            .map(|report| {
                MeasurementReport::try_from(report)
                    .map_err(|e| CarbideCliError::GenericError(format!("conversion failed: {e}")))
            })
            .collect::<CarbideCliResult<Vec<MeasurementReport>>>()?,
    ))
}

/// list lists all bundle ids.
pub async fn list_all(grpc_conn: &ApiClient) -> CarbideCliResult<MeasurementReportRecordList> {
    // Request.
    let request = ListMeasurementReportRequest { selector: None };

    // Response.
    Ok(MeasurementReportRecordList(
        grpc_conn
            .0
            .list_measurement_report(request)
            .await?
            .reports
            .into_iter()
            .map(|report| {
                MeasurementReportRecord::try_from(report)
                    .map_err(|e| CarbideCliError::GenericError(format!("conversion failed: {e}")))
            })
            .collect::<CarbideCliResult<Vec<MeasurementReportRecord>>>()?,
    ))
}

/// list_machines lists all reports for the given machine ID.
pub async fn list_machines(
    grpc_conn: &ApiClient,
    list_machines: ListMachines,
) -> CarbideCliResult<MeasurementReportRecordList> {
    // Request.
    let request = ListMeasurementReportRequest {
        selector: Some(list_measurement_report_request::Selector::MachineId(
            list_machines.machine_id.to_string(),
        )),
    };

    // Response.
    Ok(MeasurementReportRecordList(
        grpc_conn
            .0
            .list_measurement_report(request)
            .await?
            .reports
            .into_iter()
            .map(|report| {
                MeasurementReportRecord::try_from(report)
                    .map_err(|e| CarbideCliError::GenericError(format!("conversion failed: {e}")))
            })
            .collect::<CarbideCliResult<Vec<MeasurementReportRecord>>>()?,
    ))
}

/// match_values matches all reports with the provided PCR values.
///
/// `report match <pcr_register:val>,...`
pub async fn match_values(
    grpc_conn: &ApiClient,
    match_args: Match,
) -> CarbideCliResult<MeasurementReportRecordList> {
    // Request.
    let request = MatchMeasurementReportRequest {
        pcr_values: match_args.values.into_iter().map(Into::into).collect(),
    };

    // Response.
    Ok(MeasurementReportRecordList(
        grpc_conn
            .0
            .match_measurement_report(request)
            .await?
            .reports
            .into_iter()
            .map(|report| {
                MeasurementReportRecord::try_from(report)
                    .map_err(|e| CarbideCliError::GenericError(format!("conversion failed: {e}")))
            })
            .collect::<CarbideCliResult<Vec<MeasurementReportRecord>>>()?,
    ))
}

/// MeasurementReportRecordList just implements a newtype pattern
/// for a Vec<MeasurementReportRecord> so the ToTable trait can
/// be leveraged (since we don't define Vec).
#[derive(Serialize)]
pub struct MeasurementReportRecordList(Vec<MeasurementReportRecord>);

impl ToTable for MeasurementReportRecordList {
    fn into_table(self) -> eyre::Result<String> {
        let mut table = prettytable::Table::new();
        table.add_row(prettytable::row!["report_id", "machine_id", "created_ts"]);
        for report in self.0.iter() {
            table.add_row(prettytable::row![
                report.report_id,
                report.machine_id,
                report.ts
            ]);
        }
        Ok(table.to_string())
    }
}

/// MeasurementReportList just implements a newtype
/// pattern for a Vec<MeasurementReport> so the ToTable
/// trait can be leveraged (since we don't define Vec).
#[derive(Serialize)]
pub struct MeasurementReportList(Vec<MeasurementReport>);

// When `report show` gets called (for all entries), and the output format
// is the default table view, this gets used to print a pretty table.
impl ToTable for MeasurementReportList {
    fn into_table(self) -> eyre::Result<String> {
        let mut table = prettytable::Table::new();
        table.add_row(prettytable::row!["report_id", "details", "values"]);
        for report in self.0.iter() {
            let mut details_table = prettytable::Table::new();
            details_table.add_row(prettytable::row!["report_id", report.report_id]);
            details_table.add_row(prettytable::row!["machine_id", report.machine_id]);
            details_table.add_row(prettytable::row!["created_ts", report.ts]);
            let mut values_table = prettytable::Table::new();
            values_table.add_row(prettytable::row!["pcr_register", "value"]);
            for value_record in report.values.iter() {
                values_table.add_row(prettytable::row![
                    value_record.pcr_register,
                    value_record.sha_any
                ]);
            }
            table.add_row(prettytable::row![
                report.report_id,
                details_table,
                values_table
            ]);
        }
        Ok(table.to_string())
    }
}
