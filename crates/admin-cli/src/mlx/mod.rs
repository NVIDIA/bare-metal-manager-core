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

use ::rpc::admin_cli::{CarbideCliResult, OutputFormat};
use clap::Parser;
use libmlx::runner::result_types::{ComparisonResult, SyncResult};
use prettytable::{Cell, Row, Table};

use crate::cfg::dispatch::Dispatch;
use crate::cfg::runtime::RuntimeContext;
use crate::rpc::ApiClient;

mod config;
mod connections;
mod info;
mod lockdown;
mod profile;
mod registry;

#[derive(Parser, Debug)]
pub enum MlxAction {
    #[clap(subcommand, about = "Configuration profile management")]
    Profile(profile::args::ProfileCommand),

    #[clap(subcommand, about = "Device lockdown operations")]
    Lockdown(lockdown::args::LockdownCommand),

    #[clap(subcommand, about = "Device information retrieval")]
    Info(info::args::InfoCommand),

    #[clap(subcommand, about = "scout stream agent connection management")]
    Connections(connections::args::ConnectionsCommand),

    #[clap(subcommand, about = "Variable registry operations")]
    Registry(registry::args::RegistryCommand),

    #[clap(subcommand, about = "Config management operations")]
    Config(config::args::ConfigCommand),
}

pub struct CliContext<'g, 'a> {
    pub grpc_conn: &'g ApiClient,
    pub format: &'a OutputFormat,
}

impl Dispatch for MlxAction {
    async fn dispatch(self, ctx: RuntimeContext) -> CarbideCliResult<()> {
        let mut ctxt = CliContext {
            grpc_conn: &ctx.api_client,
            format: &ctx.config.format,
        };
        match self {
            MlxAction::Profile(cmd) => profile::cmds::dispatch(cmd, &mut ctxt).await?,
            MlxAction::Lockdown(cmd) => lockdown::cmds::dispatch(cmd, &mut ctxt).await?,
            MlxAction::Info(cmd) => info::cmds::dispatch(cmd, &mut ctxt).await?,
            MlxAction::Connections(cmd) => connections::cmds::dispatch(cmd, &mut ctxt).await?,
            MlxAction::Registry(cmd) => registry::cmds::dispatch(cmd, &mut ctxt).await?,
            MlxAction::Config(cmd) => config::cmds::dispatch(cmd, &mut ctxt).await?,
        }
        Ok(())
    }
}

// wrap_text wraps text to a specified width for table display.
fn wrap_text(text: &str, width: usize) -> String {
    if text.len() <= width {
        return text.to_string();
    }

    let mut result = String::new();
    let mut current_line_len = 0;

    for word in text.split_whitespace() {
        if current_line_len + word.len() + 1 > width {
            if !result.is_empty() {
                result.push('\n');
            }
            result.push_str(word);
            current_line_len = word.len();
        } else {
            if !result.is_empty() {
                result.push(' ');
                current_line_len += 1;
            }
            result.push_str(word);
            current_line_len += word.len();
        }
    }

    result
}

// print_sync_result_table prints a SyncResult as an ASCII table.
fn print_sync_result_table(result: &SyncResult) {
    let mut table = Table::new();

    // Check if there are any changes applied.
    if result.changes_applied.is_empty() {
        // Single row indicating no changes.
        table.add_row(Row::new(vec![Cell::new("Device already in sync")]));
    } else {
        // Header row spanning three columns.
        table.add_row(Row::new(vec![Cell::new("Changes Applied").with_hspan(3)]));

        // Column headers.
        table.add_row(Row::new(vec![
            Cell::new("Variable"),
            Cell::new("Old Value"),
            Cell::new("New Value"),
        ]));

        // Add a row for each variable change.
        for change in &result.changes_applied {
            table.add_row(Row::new(vec![
                Cell::new(&change.variable_name),
                Cell::new(&change.old_value.to_string()),
                Cell::new(&change.new_value.to_string()),
            ]));
        }
    }

    table.printstd();
}

// print_sync_result_csv prints a SyncResult in CSV format.
fn print_sync_result_csv(result: &SyncResult) {
    if result.changes_applied.is_empty() {
        println!("Device already in sync");
    } else {
        println!("variable_name,old_value,new_value");
        for change in &result.changes_applied {
            println!(
                "{},{},{}",
                &change.variable_name,
                &change.old_value.to_string(),
                &change.new_value.to_string()
            );
        }
    }
}

// print_comparison_result_table prints a ComparisonResult as an ASCII table.
fn print_comparison_result_table(result: &ComparisonResult) {
    let mut table = Table::new();

    // Check if there are any planned changes.
    if result.planned_changes.is_empty() {
        // Single row indicating device is in sync.
        table.add_row(Row::new(vec![Cell::new(
            "Device is in sync with provided assignments",
        )]));
    } else {
        // Header row spanning three columns.
        table.add_row(Row::new(vec![Cell::new("Comparison Result").with_hspan(3)]));

        // Column headers.
        table.add_row(Row::new(vec![
            Cell::new("Variable"),
            Cell::new("Current Value"),
            Cell::new("Desired Value"),
        ]));

        // Add a row for each planned change.
        for change in &result.planned_changes {
            table.add_row(Row::new(vec![
                Cell::new(&change.variable_name),
                Cell::new(&change.current_value.to_string()),
                Cell::new(&change.desired_value.to_string()),
            ]));
        }
    }

    table.printstd();
}

// print_comparison_result_csv prints a ComparisonResult as a CSV.
fn print_comparison_result_csv(result: &ComparisonResult) {
    if result.planned_changes.is_empty() {
        println!("Device already in sync with given assignments");
    } else {
        println!("variable_name,current_value,desired_value");
        for change in &result.planned_changes {
            println!(
                "{},{},{}",
                &change.variable_name,
                &change.current_value.to_string(),
                &change.desired_value.to_string()
            );
        }
    }
}
