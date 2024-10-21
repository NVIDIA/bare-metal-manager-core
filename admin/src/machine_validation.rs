/* SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use super::rpc;
use crate::cfg::carbide_options::{
    MachineValidationOnDemandOptions, ShowMachineValidationResultsOptions,
    ShowMachineValidationRunsOptions,
};
use ::rpc::forge as forgerpc;
use ::rpc::forge_tls_client::ApiConfig;
use prettytable::{row, Table};
use std::fmt::Write;
use utils::admin_cli::{CarbideCliResult, OutputFormat};

pub async fn external_config_show(
    api_config: &ApiConfig<'_>,
    config_name: String,
) -> CarbideCliResult<()> {
    let response = rpc::get_machine_validation_external_config(config_name, api_config).await?;

    println!("---------------------------");
    if response.config.is_some() {
        let s = String::from_utf8(response.config.unwrap_or_default().config)
            .expect("Found invalid UTF-8");

        println!("{}", s);
    }
    println!("---------------------------");
    Ok(())
}
pub async fn external_config_add_update(
    api_config: &ApiConfig<'_>,
    config_name: String,
    file_name: String,
    description: String,
) -> CarbideCliResult<()> {
    // Read the file data from disk
    let file_data = std::fs::read(&file_name)?;
    rpc::add_update_machine_validation_external_config(
        config_name,
        description,
        file_data,
        api_config,
    )
    .await?;
    Ok(())
}

pub async fn handle_runs_show(
    args: ShowMachineValidationRunsOptions,
    output_format: OutputFormat,
    api_config: &ApiConfig<'_>,
    _page_size: usize,
) -> CarbideCliResult<()> {
    let is_json = output_format == OutputFormat::Json;
    show_runs(is_json, api_config, args).await?;
    Ok(())
}

async fn show_runs(
    json: bool,
    api_config: &ApiConfig<'_>,
    args: ShowMachineValidationRunsOptions,
) -> CarbideCliResult<()> {
    let runs = match rpc::get_machine_validation_runs(api_config, args.machine, args.history).await
    {
        Ok(runs) => runs,
        Err(e) => return Err(e),
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&runs).unwrap());
    } else {
        convert_runs_to_nice_table(runs).printstd();
    }
    Ok(())
}

fn convert_runs_to_nice_table(runs: forgerpc::MachineValidationRunList) -> Box<Table> {
    let mut table = Table::new();

    table.set_titles(row!["Id", "MachineId", "StartTime", "EndTime", "Context"]);

    for run in runs.runs {
        let end_time = if let Some(run_end_time) = run.end_time {
            run_end_time.to_string()
        } else {
            "".to_string()
        };
        table.add_row(row![
            run.validation_id.clone().unwrap_or_default(),
            run.machine_id.unwrap_or_default(),
            run.start_time.unwrap_or_default(),
            end_time,
            run.context.unwrap_or_default(),
        ]);
    }

    table.into()
}

pub async fn handle_results_show(
    args: ShowMachineValidationResultsOptions,
    output_format: OutputFormat,
    api_config: &ApiConfig<'_>,
    _page_size: usize,
    extended: bool,
) -> CarbideCliResult<()> {
    let is_json = output_format == OutputFormat::Json;
    if extended {
        show_results_details(is_json, api_config, args).await?;
    } else {
        show_results(is_json, api_config, args).await?;
    }

    Ok(())
}

async fn show_results(
    json: bool,
    api_config: &ApiConfig<'_>,
    args: ShowMachineValidationResultsOptions,
) -> CarbideCliResult<()> {
    let mut results = match rpc::get_machine_validation_results(
        api_config,
        args.machine,
        args.history,
        args.validation_id,
    )
    .await
    {
        Ok(results) => results,
        Err(e) => return Err(e),
    };

    if args.test_name.is_some() {
        results
            .results
            .retain(|x| x.name == args.test_name.clone().unwrap_or_default())
    }
    if json {
        println!("{}", serde_json::to_string_pretty(&results).unwrap());
    } else {
        convert_results_to_nice_table(results).printstd();
    }
    Ok(())
}

async fn show_results_details(
    json: bool,
    api_config: &ApiConfig<'_>,
    args: ShowMachineValidationResultsOptions,
) -> CarbideCliResult<()> {
    let mut results = match rpc::get_machine_validation_results(
        api_config,
        args.machine,
        args.history,
        args.validation_id,
    )
    .await
    {
        Ok(results) => results,
        Err(e) => return Err(e),
    };
    if args.test_name.is_some() {
        results
            .results
            .retain(|x| x.name == args.test_name.clone().unwrap_or_default())
    }
    if json {
        println!("{}", serde_json::to_string_pretty(&results).unwrap());
    } else {
        println!(
            "{}",
            convert_to_nice_format(results).unwrap_or_else(|x| x.to_string())
        );
    }

    Ok(())
}

fn convert_results_to_nice_table(results: forgerpc::MachineValidationResultList) -> Box<Table> {
    let mut table = Table::new();

    table.set_titles(row![
        "RunID",
        "Name",
        "Context",
        "ExitCode",
        "StartTime",
        "EndTime",
    ]);

    for result in results.results {
        table.add_row(row![
            result.validation_id.clone().unwrap_or_default(),
            result.name,
            result.context,
            result.exit_code,
            result.start_time.unwrap_or_default(),
            result.end_time.unwrap_or_default(),
        ]);
    }

    table.into()
}

fn convert_to_nice_format(
    results: forgerpc::MachineValidationResultList,
) -> CarbideCliResult<String> {
    let width = 14;
    let mut lines = String::new();
    if results.results.is_empty() {
        return Ok(lines);
    }
    let first = results.results.first().unwrap();
    let data = vec![
        (
            "ID",
            first.validation_id.clone().unwrap_or_default().to_string(),
        ),
        ("CONTEXT", first.context.clone()),
    ];
    for (key, value) in data {
        writeln!(&mut lines, "{:<width$}: {}", key, value)?;
    }
    // data.clear();
    for result in results.results {
        writeln!(
            &mut lines,
            "\t------------------------------------------------------------------------"
        )?;
        let details = vec![
            ("Name", result.name.clone()),
            ("Description", result.description.clone()),
            ("Command", result.command.clone()),
            ("Args", result.args.clone()),
            ("StdOut", result.std_out.clone()),
            ("StdErr", result.std_err.clone()),
            ("ExitCode", result.exit_code.to_string()),
            (
                "StartTime",
                result.start_time.unwrap_or_default().to_string(),
            ),
            ("EndTime", result.end_time.unwrap_or_default().to_string()),
        ];

        for (key, value) in details {
            writeln!(&mut lines, "{:<width$}: {}", key, value)?;
        }
        writeln!(
            &mut lines,
            "\t------------------------------------------------------------------------"
        )?;
    }
    Ok(lines)
}

pub async fn on_demand_machine_validation(
    api_config: &ApiConfig<'_>,
    args: MachineValidationOnDemandOptions,
) -> CarbideCliResult<()> {
    rpc::on_demand_machine_validation(args.machine, args.tags, args.allowed_tests, api_config)
        .await?;
    Ok(())
}
pub async fn remove_external_config(
    api_config: &ApiConfig<'_>,
    name: String,
) -> CarbideCliResult<()> {
    // Read the file data from disk
    rpc::remove_machine_validation_external_config(api_config, name).await?;
    Ok(())
}
