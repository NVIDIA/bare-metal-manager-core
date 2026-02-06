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

use std::borrow::Cow;

use carbide_uuid::machine::MachineId;
use chrono::{DateTime, Utc};
use clap::Parser;
use prettytable::{Cell, Row, Table};
use rpc::admin_cli::{CarbideCliResult, OutputFormat};

use crate::cfg::dispatch::Dispatch;
use crate::cfg::runtime::RuntimeContext;
use crate::rpc::ApiClient;

#[cfg(test)]
mod tests;

#[derive(Parser, Debug)]
pub enum ScoutStreamAction {
    #[clap(about = "Show all active scout stream connections")]
    Show(ConnectionsShowCommand),
    #[clap(about = "Disconnect a scout stream connection")]
    Disconnect(ConnectionsDisconnectCommand),
    #[clap(about = "Ping test for a scout stream connection")]
    Ping(ConnectionsPingCommand),
}

// ConnectionsShowCommand shows all active scout stream connections.
#[derive(Parser, Debug)]
pub struct ConnectionsShowCommand {}

// ConnectionsDisconnectCommand disconnects a machine based on machine ID.
#[derive(Parser, Debug)]
pub struct ConnectionsDisconnectCommand {
    pub machine_id: MachineId,
}

// ConnectionsPingCommand pings a machine based on machine ID.
#[derive(Parser, Debug)]
pub struct ConnectionsPingCommand {
    pub machine_id: MachineId,
}

pub struct CliContext<'g, 'a> {
    pub grpc_conn: &'g ApiClient,
    pub format: &'a OutputFormat,
}

impl Dispatch for ScoutStreamAction {
    async fn dispatch(self, ctx: RuntimeContext) -> CarbideCliResult<()> {
        let mut ctxt = CliContext {
            grpc_conn: &ctx.api_client,
            format: &ctx.config.format,
        };
        match self {
            ScoutStreamAction::Show(cmd) => handle_show(cmd, &mut ctxt).await?,
            ScoutStreamAction::Disconnect(cmd) => handle_disconnect(cmd, &mut ctxt).await?,
            ScoutStreamAction::Ping(cmd) => handle_ping(cmd, &mut ctxt).await?,
        }
        Ok(())
    }
}

// handle_show shows all active scout stream connections.
async fn handle_show(
    _cmd: ConnectionsShowCommand,
    ctxt: &mut CliContext<'_, '_>,
) -> CarbideCliResult<()> {
    let response = ctxt.grpc_conn.0.scout_stream_show_connections().await?;
    let mut connections = response.scout_stream_connections;
    connections.sort_by(|a, b| a.machine_id.cmp(&b.machine_id));
    match ctxt.format {
        OutputFormat::AsciiTable => {
            print_connections_table(&connections);
        }
        OutputFormat::Json => {
            let json = serde_json::json!({
                "connections": connections.iter().map(|c| {
                    serde_json::json!({
                        "machine_id": c.machine_id,
                        "connect_time": c.connected_at,
                        "uptime_seconds": c.uptime_seconds,
                    })
                }).collect::<Vec<_>>(),
            });
            println!("{}", serde_json::to_string_pretty(&json)?);
        }
        OutputFormat::Yaml => {
            println!("connections:");
            for conn in connections {
                let machine_id = match conn.machine_id.as_ref() {
                    Some(id) => id.to_string(),
                    None => "null".to_string(),
                };
                println!("  - machine_id: {}", machine_id);
                println!("    connect_time: \"{}\"", conn.connected_at);
                println!("    uptime_seconds: {}", conn.uptime_seconds);
            }
        }
        OutputFormat::Csv => {
            for conn in connections {
                let machine_id = match conn.machine_id.as_ref() {
                    Some(id) => id.to_string(),
                    None => "null".to_string(),
                };
                println!(
                    "{},{},{}",
                    machine_id, conn.connected_at, conn.uptime_seconds
                );
            }
        }
    }
    Ok(())
}

// handle_disconnect disconnects an active scout stream connection.
async fn handle_disconnect(
    cmd: ConnectionsDisconnectCommand,
    ctxt: &mut CliContext<'_, '_>,
) -> CarbideCliResult<()> {
    let request: ::rpc::forge::ScoutStreamDisconnectRequest = cmd.into();
    let response = ctxt.grpc_conn.0.scout_stream_disconnect(request).await?;
    let machine_id = match response.machine_id.as_ref() {
        Some(id) => id.to_string(),
        None => "null".to_string(),
    };
    if response.success {
        println!("Successfully disconnected machine_id={}.", machine_id);
    } else {
        println!(
            "Failed to disconnect machine_id={} (already disconnected).",
            machine_id
        );
    }

    Ok(())
}

async fn handle_ping(
    cmd: ConnectionsPingCommand,
    ctxt: &mut CliContext<'_, '_>,
) -> CarbideCliResult<()> {
    let request: ::rpc::forge::ScoutStreamAdminPingRequest = cmd.into();
    let response = ctxt.grpc_conn.0.scout_stream_ping(request).await?;

    println!("{}", response.pong);
    Ok(())
}

// print_connections_table displays connections in an ASCII table format.
fn print_connections_table(connections: &[rpc::forge::ScoutStreamConnectionInfo]) {
    let mut table = Table::new();

    table.add_row(Row::new(vec![
        Cell::new("Machine ID"),
        Cell::new("Connect Time"),
        Cell::new("Uptime Seconds"),
    ]));

    for conn in connections {
        let machine_id = match conn.machine_id.as_ref() {
            Some(id) => id.to_string(),
            None => "null".to_string(),
        };
        let connect_time = if let Ok(dt) = conn.connected_at.parse::<DateTime<Utc>>() {
            Cow::Owned(dt.format("%Y-%m-%d %H:%M:%S").to_string())
        } else {
            Cow::Borrowed(&conn.connected_at)
        };

        table.add_row(Row::new(vec![
            Cell::new(&machine_id),
            Cell::new(&connect_time),
            Cell::new(&conn.uptime_seconds.to_string()),
        ]));
    }

    table.printstd();
}

impl From<ConnectionsDisconnectCommand> for ::rpc::forge::ScoutStreamDisconnectRequest {
    fn from(cmd: ConnectionsDisconnectCommand) -> Self {
        Self {
            machine_id: cmd.machine_id.into(),
        }
    }
}

impl From<ConnectionsPingCommand> for ::rpc::forge::ScoutStreamAdminPingRequest {
    fn from(cmd: ConnectionsPingCommand) -> Self {
        Self {
            machine_id: cmd.machine_id.into(),
        }
    }
}
