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
use crate::measurement::machine::args::{Attest, CmdMockMachine, Create, Delete, Show};
use ::rpc::forge_tls_client::ForgeClientT;
use ::rpc::protos::measured_boot::{show_mock_machine_request, ListMockMachineRequest};
use ::rpc::protos::measured_boot::{
    AttestMockMachineRequest, CreateMockMachineRequest, DeleteMockMachineRequest,
    ShowMockMachineRequest, ShowMockMachinesRequest,
};
use carbide::measured_boot::interface::common::{PcrRegisterValue, ToTable};
use carbide::measured_boot::{
    dto::records::MockMachineRecord,
    model::{machine::MockMachine, report::MeasurementReport},
};
use serde::Serialize;
use std::collections::HashMap;

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
    cmd: &CmdMockMachine,
    cli: &mut global::cmds::CliData<'_, '_>,
) -> eyre::Result<()> {
    match cmd {
        CmdMockMachine::Create(local_args) => {
            cli_output(
                create(cli.grpc_conn, local_args).await?,
                &cli.args.format,
                global::cmds::Destination::Stdout(),
            )?;
        }
        CmdMockMachine::Delete(local_args) => {
            cli_output(
                delete(cli.grpc_conn, local_args).await?,
                &cli.args.format,
                global::cmds::Destination::Stdout(),
            )?;
        }
        CmdMockMachine::Attest(local_args) => {
            cli_output(
                attest(cli.grpc_conn, local_args).await?,
                &cli.args.format,
                global::cmds::Destination::Stdout(),
            )?;
        }
        CmdMockMachine::Show(local_args) => {
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
        CmdMockMachine::List(_) => {
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
/// create creates a new mock machine.
///////////////////////////////////////////////////////////////////////////////

pub async fn create(grpc_conn: &mut ForgeClientT, create: &Create) -> eyre::Result<MockMachine> {
    // Prepare.
    let mut attrs = HashMap::from([
        (String::from("vendor"), create.vendor.clone()),
        (String::from("product"), create.product.clone()),
    ]);
    for kv_pair in create.extra_attrs.iter() {
        attrs.insert(kv_pair.key.clone(), kv_pair.value.clone());
    }

    // Request.
    let request = CreateMockMachineRequest {
        machine_id: create.machine_id.to_string(),
        attrs,
    };

    // Response.
    let response = grpc_conn
        .create_mock_machine(request)
        .await
        .map_err(|e| eyre::eyre!(e.to_string()))?;

    MockMachine::from_grpc(response.get_ref().machine.as_ref())
}

///////////////////////////////////////////////////////////////////////////////
/// delete deletes a mock machine.
///////////////////////////////////////////////////////////////////////////////

pub async fn delete(grpc_conn: &mut ForgeClientT, delete: &Delete) -> eyre::Result<MockMachine> {
    // Request.
    let request = DeleteMockMachineRequest {
        machine_id: delete.machine_id.to_string(),
    };

    // Response.
    let response = grpc_conn
        .delete_mock_machine(request)
        .await
        .map_err(|e| eyre::eyre!(e.to_string()))?;

    MockMachine::from_grpc(response.get_ref().machine.as_ref())
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
    let request = AttestMockMachineRequest {
        machine_id: attest.machine_id.to_string(),
        pcr_values: PcrRegisterValue::to_pb_vec(&attest.values),
    };

    // Response.
    let response = grpc_conn
        .attest_mock_machine(request)
        .await
        .map_err(|e| eyre::eyre!(e.to_string()))?;

    MeasurementReport::from_grpc(response.get_ref().report.as_ref())
}

///////////////////////////////////////////////////////////////////////////////
/// show_by_id shows all info about a given machine ID.
///////////////////////////////////////////////////////////////////////////////

pub async fn show_by_id(grpc_conn: &mut ForgeClientT, show: &Show) -> eyre::Result<MockMachine> {
    // Prepare.
    let Some(machine_id) = &show.machine_id else {
        return Err(eyre::eyre!("machine_id must be set to get a machine"));
    };

    // Request.
    let request = ShowMockMachineRequest {
        selector: Some(show_mock_machine_request::Selector::MachineId(
            machine_id.to_string(),
        )),
    };

    // Response.
    let response = grpc_conn
        .show_mock_machine(request)
        .await
        .map_err(|e| eyre::eyre!(e.to_string()))?;

    MockMachine::from_grpc(response.get_ref().machine.as_ref())
}

///////////////////////////////////////////////////////////////////////////////
/// show_all shows all info about all machines.
///////////////////////////////////////////////////////////////////////////////

pub async fn show_all(
    grpc_conn: &mut ForgeClientT,
    _show: &Show,
) -> eyre::Result<Vec<MockMachine>> {
    // Request.
    let request = ShowMockMachinesRequest {};

    // Response.
    grpc_conn
        .show_mock_machines(request)
        .await
        .map_err(|e| eyre::eyre!(e.to_string()))?
        .get_ref()
        .machines
        .iter()
        .map(|machine| {
            MockMachine::try_from(machine.clone())
                .map_err(|e| eyre::eyre!("conversion failed: {}", e))
        })
        .collect::<eyre::Result<Vec<MockMachine>>>()
}

///////////////////////////////////////////////////////////////////////////////
/// list lists all machine IDs.
///////////////////////////////////////////////////////////////////////////////

pub async fn list(grpc_conn: &mut ForgeClientT) -> eyre::Result<Vec<MockMachineRecord>> {
    // Request.
    let request = ListMockMachineRequest {};

    // Response.
    grpc_conn
        .list_mock_machine(request)
        .await
        .map_err(|e| eyre::eyre!(e.to_string()))?
        .get_ref()
        .machines
        .iter()
        .map(|machine| {
            MockMachineRecord::try_from(machine.clone())
                .map_err(|e| eyre::eyre!("conversion failed: {}", e))
        })
        .collect::<eyre::Result<Vec<MockMachineRecord>>>()
}
