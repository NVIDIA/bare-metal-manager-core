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
//! `measurement mock-machine` subcommand dispatcher + backing functions.
//!

use crate::measurement::global;
use crate::measurement::global::cmds::cli_output;
use crate::measurement::machine::args::{Attest, CmdMachine, Show};
use ::rpc::forge_tls_client::ForgeClientT;
use ::rpc::protos::measured_boot::{show_candidate_machine_request, ListCandidateMachinesRequest};
use ::rpc::protos::measured_boot::{
    AttestCandidateMachineRequest, ShowCandidateMachineRequest, ShowCandidateMachinesRequest,
};
use carbide::measured_boot::interface::common::{PcrRegisterValue, ToTable};
use carbide::measured_boot::{
    dto::records::CandidateMachineSummary,
    model::{machine::CandidateMachine, report::MeasurementReport},
};
use serde::Serialize;

///////////////////////////////////////////////////////////////////////////////
/// ExecResult exists just to print CLI results out
/// leveraging the same mechanism as everything else.
///////////////////////////////////////////////////////////////////////////////

#[derive(Serialize)]
pub struct ExecResult {
    status: String,
    rows_affected: u64,
}

impl ToTable for ExecResult {
    fn to_table(&self) -> eyre::Result<String> {
        let mut table = prettytable::Table::new();
        table.add_row(prettytable::row!["status", self.status]);
        table.add_row(prettytable::row!["rows_affected", self.rows_affected]);
        Ok(table.to_string())
    }
}

///////////////////////////////////////////////////////////////////////////////
/// dispatch matches + dispatches the correct command
/// for the `mock-machine` subcommand.
///////////////////////////////////////////////////////////////////////////////

pub async fn dispatch(
    cmd: &CmdMachine,
    cli: &mut global::cmds::CliData<'_, '_>,
) -> eyre::Result<()> {
    match cmd {
        CmdMachine::Attest(local_args) => {
            cli_output(
                attest(cli.grpc_conn, local_args).await?,
                &cli.args.format,
                global::cmds::Destination::Stdout(),
            )?;
        }
        CmdMachine::Show(local_args) => {
            if local_args.machine_id.is_some() {
                cli_output(
                    show_by_id(cli.grpc_conn, local_args).await?,
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
        CmdMachine::List(_) => {
            cli_output(
                list(cli.grpc_conn).await?,
                &cli.args.format,
                global::cmds::Destination::Stdout(),
            )?;
        }
    }
    Ok(())
}

///////////////////////////////////////////////////////////////////////////////
/// attest sends attestation data for the given machine ID, as in, PCR
/// register + value pairings, which results in a journal entry being made.
///////////////////////////////////////////////////////////////////////////////

pub async fn attest(
    grpc_conn: &mut ForgeClientT,
    attest: &Attest,
) -> eyre::Result<MeasurementReport> {
    // Request.
    let request = AttestCandidateMachineRequest {
        machine_id: attest.machine_id.to_string(),
        pcr_values: PcrRegisterValue::to_pb_vec(&attest.values),
    };

    // Response.
    let response = grpc_conn
        .attest_candidate_machine(request)
        .await
        .map_err(|e| eyre::eyre!(e.to_string()))?;

    MeasurementReport::from_grpc(response.get_ref().report.as_ref())
}

///////////////////////////////////////////////////////////////////////////////
/// show_by_id shows all info about a given machine ID.
///////////////////////////////////////////////////////////////////////////////

pub async fn show_by_id(
    grpc_conn: &mut ForgeClientT,
    show: &Show,
) -> eyre::Result<CandidateMachine> {
    // Prepare.
    let Some(machine_id) = &show.machine_id else {
        return Err(eyre::eyre!("machine_id must be set to get a machine"));
    };

    // Request.
    let request = ShowCandidateMachineRequest {
        selector: Some(show_candidate_machine_request::Selector::MachineId(
            machine_id.to_string(),
        )),
    };

    // Response.
    let response = grpc_conn
        .show_candidate_machine(request)
        .await
        .map_err(|e| eyre::eyre!(e.to_string()))?;

    CandidateMachine::from_grpc(response.get_ref().machine.as_ref())
}

///////////////////////////////////////////////////////////////////////////////
/// show_all shows all info about all machines.
///////////////////////////////////////////////////////////////////////////////

pub async fn show_all(
    grpc_conn: &mut ForgeClientT,
    _show: &Show,
) -> eyre::Result<Vec<CandidateMachine>> {
    // Request.
    let request = ShowCandidateMachinesRequest {};

    // Response.
    grpc_conn
        .show_candidate_machines(request)
        .await
        .map_err(|e| eyre::eyre!(e.to_string()))?
        .get_ref()
        .machines
        .iter()
        .map(|machine| {
            CandidateMachine::try_from(machine.clone())
                .map_err(|e| eyre::eyre!("conversion failed: {}", e))
        })
        .collect::<eyre::Result<Vec<CandidateMachine>>>()
}

///////////////////////////////////////////////////////////////////////////////
/// list lists all machine IDs.
///////////////////////////////////////////////////////////////////////////////

pub async fn list(grpc_conn: &mut ForgeClientT) -> eyre::Result<Vec<CandidateMachineSummary>> {
    // Request.
    let request = ListCandidateMachinesRequest {};

    // Response.
    grpc_conn
        .list_candidate_machines(request)
        .await
        .map_err(|e| eyre::eyre!(e.to_string()))?
        .get_ref()
        .machines
        .iter()
        .map(|machine| {
            CandidateMachineSummary::try_from(machine.clone())
                .map_err(|e| eyre::eyre!("conversion failed: {}", e))
        })
        .collect::<eyre::Result<Vec<CandidateMachineSummary>>>()
}
