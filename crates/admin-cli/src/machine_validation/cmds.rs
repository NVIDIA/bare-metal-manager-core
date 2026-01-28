/* SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use std::borrow::Cow;
use std::fmt::Write;

use ::rpc::admin_cli::{CarbideCliError, CarbideCliResult, OutputFormat};
use ::rpc::forge::{
    self as forgerpc, MachineValidationTestEnableDisableTestRequest,
    MachineValidationTestUpdateRequest, MachineValidationTestVerfiedRequest,
};
use prettytable::{Table, row};

use super::args::{
    AddTestOptions, EnableDisableTestOptions, OnDemandOptions, ShowResultsOptions, ShowRunsOptions,
    ShowTestOptions, UpdateTestOptions, VerifyTestOptions,
};
use crate::rpc::ApiClient;

pub async fn external_config_show(
    api_client: &ApiClient,
    config_names: Vec<String>,
    extended: bool,
    output_format: OutputFormat,
) -> CarbideCliResult<()> {
    let is_json = output_format == OutputFormat::Json;
    let ret = api_client
        .0
        .get_machine_validation_external_configs(config_names)
        .await?;

    if extended {
        show_external_config_show_details(ret.configs, is_json)?;
    } else {
        show_external_config_show(ret.configs, is_json)?;
    }
    Ok(())
}

pub fn show_external_config_show_details(
    configs: Vec<forgerpc::MachineValidationExternalConfig>,
    json: bool,
) -> CarbideCliResult<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(&configs)?);
    } else {
        println!("{}", convert_external_config_to_nice_format(configs)?);
    }
    Ok(())
}

pub fn show_external_config_show(
    configs: Vec<forgerpc::MachineValidationExternalConfig>,
    json: bool,
) -> CarbideCliResult<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(&configs)?);
    } else {
        convert_external_config_to_nice_table(configs).printstd();
    }
    Ok(())
}

fn convert_external_config_to_nice_format(
    configs: Vec<forgerpc::MachineValidationExternalConfig>,
) -> CarbideCliResult<String> {
    let width = 14;
    let mut lines = String::new();
    if configs.is_empty() {
        return Ok(lines);
    }
    for config in configs {
        writeln!(
            &mut lines,
            "\t------------------------------------------------------------------------"
        )?;
        let timestamp = if config.timestamp.is_some() {
            "".to_string()
        } else {
            config.timestamp.unwrap_or_default().to_string()
        };
        let config_string = String::from_utf8(config.config)
            .map_err(|e| CarbideCliError::GenericError(e.to_string()))?;

        let details = vec![
            ("Name", config.name),
            ("Description", config.description.unwrap_or_default()),
            ("Version", config.version),
            ("TimeStamp", timestamp),
            ("Config", config_string),
        ];

        for (key, value) in details {
            writeln!(&mut lines, "{key:<width$}: {value}")?;
        }
        writeln!(
            &mut lines,
            "\t------------------------------------------------------------------------"
        )?;
    }
    Ok(lines)
}

fn convert_external_config_to_nice_table(
    configs: Vec<forgerpc::MachineValidationExternalConfig>,
) -> Box<Table> {
    let mut table = Table::new();

    table.set_titles(row!["Name", "Description", "Version", "Timestamp"]);

    for config in configs {
        table.add_row(row![
            config.name,
            config.description.unwrap_or_default(),
            config.version,
            config.timestamp.unwrap_or_default(),
        ]);
    }

    table.into()
}

pub async fn external_config_add_update(
    api_client: &ApiClient,
    config_name: String,
    file_name: String,
    description: String,
) -> CarbideCliResult<()> {
    // Read the file data from disk
    let file_data = std::fs::read(&file_name)?;
    api_client
        .add_update_machine_validation_external_config(config_name, description, file_data)
        .await?;
    Ok(())
}

pub async fn handle_runs_show(
    args: ShowRunsOptions,
    output_format: OutputFormat,
    api_client: &ApiClient,
    _page_size: usize,
) -> CarbideCliResult<()> {
    let is_json = output_format == OutputFormat::Json;
    show_runs(is_json, api_client, args).await?;
    Ok(())
}

async fn show_runs(
    json: bool,
    api_client: &ApiClient,
    args: ShowRunsOptions,
) -> CarbideCliResult<()> {
    let runs = match api_client
        .get_machine_validation_runs(args.machine, args.history)
        .await
    {
        Ok(runs) => runs,
        Err(e) => return Err(e),
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&runs)?);
    } else {
        convert_runs_to_nice_table(runs).printstd();
    }
    Ok(())
}

fn convert_runs_to_nice_table(runs: forgerpc::MachineValidationRunList) -> Box<Table> {
    let mut table = Table::new();

    table.set_titles(row![
        "Id",
        "MachineId",
        "StartTime",
        "EndTime",
        "Context",
        "State"
    ]);

    for run in runs.runs {
        let end_time = if let Some(run_end_time) = run.end_time {
            run_end_time.to_string()
        } else {
            "".to_string()
        };
        let status_state = run
            .status
            .unwrap_or_default()
            .machine_validation_state
            .unwrap_or(
                forgerpc::machine_validation_status::MachineValidationState::Completed(
                    forgerpc::machine_validation_status::MachineValidationCompleted::Success.into(),
                ),
            );
        table.add_row(row![
            run.validation_id.unwrap_or_default(),
            run.machine_id.unwrap_or_default(),
            run.start_time.unwrap_or_default(),
            end_time,
            run.context.unwrap_or_default(),
            format!("{:?}", status_state),
        ]);
    }

    table.into()
}

pub async fn handle_results_show(
    args: ShowResultsOptions,
    output_format: OutputFormat,
    api_client: &ApiClient,
    _page_size: usize,
    extended: bool,
) -> CarbideCliResult<()> {
    let is_json = output_format == OutputFormat::Json;
    if extended {
        show_results_details(is_json, api_client, args).await?;
    } else {
        show_results(is_json, api_client, args).await?;
    }

    Ok(())
}

async fn show_results(
    json: bool,
    api_client: &ApiClient,
    args: ShowResultsOptions,
) -> CarbideCliResult<()> {
    let mut results = match api_client
        .get_machine_validation_results(args.machine, args.history, args.validation_id)
        .await
    {
        Ok(results) => results,
        Err(e) => return Err(e),
    };

    if let Some(test_name) = args.test_name {
        results.results.retain(|x| x.name == test_name)
    }
    if json {
        println!("{}", serde_json::to_string_pretty(&results)?);
    } else {
        convert_results_to_nice_table(results).printstd();
    }
    Ok(())
}

async fn show_results_details(
    json: bool,
    api_client: &ApiClient,
    args: ShowResultsOptions,
) -> CarbideCliResult<()> {
    let mut results = match api_client
        .get_machine_validation_results(args.machine, args.history, args.validation_id)
        .await
    {
        Ok(results) => results,
        Err(e) => return Err(e),
    };
    if let Some(test_name) = args.test_name {
        results.results.retain(|x| x.name == test_name)
    }
    if json {
        println!("{}", serde_json::to_string_pretty(&results)?);
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
            result.validation_id.unwrap_or_default(),
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
            Cow::Owned(
                first
                    .validation_id
                    .as_ref()
                    .map(|id| id.to_string())
                    .unwrap_or_default(),
            ),
        ),
        ("CONTEXT", Cow::Borrowed(first.context.as_str())),
    ];
    for (key, value) in data {
        writeln!(&mut lines, "{key:<width$}: {value}")?;
    }
    // data.clear();
    for result in results.results {
        writeln!(
            &mut lines,
            "\t------------------------------------------------------------------------"
        )?;
        let details = vec![
            ("Name", result.name),
            ("Description", result.description),
            ("Command", result.command),
            ("Args", result.args),
            ("StdOut", result.std_out),
            ("StdErr", result.std_err),
            ("ExitCode", result.exit_code.to_string()),
            (
                "StartTime",
                result.start_time.unwrap_or_default().to_string(),
            ),
            ("EndTime", result.end_time.unwrap_or_default().to_string()),
        ];

        for (key, value) in details {
            writeln!(&mut lines, "{key:<width$}: {value}")?;
        }
        writeln!(
            &mut lines,
            "\t------------------------------------------------------------------------"
        )?;
    }
    Ok(lines)
}

pub async fn on_demand_machine_validation(
    api_client: &ApiClient,
    args: OnDemandOptions,
) -> CarbideCliResult<()> {
    api_client
        .on_demand_machine_validation(
            args.machine,
            args.tags,
            args.allowed_tests,
            args.run_unverfied_tests,
            args.contexts,
        )
        .await?;
    Ok(())
}

pub async fn remove_external_config(api_client: &ApiClient, name: String) -> CarbideCliResult<()> {
    api_client
        .0
        .remove_machine_validation_external_config(name)
        .await?;
    Ok(())
}

pub async fn show_tests(
    api_client: &ApiClient,
    args: ShowTestOptions,
    output_format: OutputFormat,
    extended: bool,
) -> CarbideCliResult<()> {
    let tests = api_client
        .get_machine_validation_tests(
            args.test_id,
            args.platforms,
            args.contexts,
            args.show_un_verfied,
        )
        .await?;
    if extended {
        let _ = show_tests_details(output_format == OutputFormat::Json, tests);
    } else {
        convert_tests_to_nice_table(tests.tests).printstd();
    }

    Ok(())
}

fn show_tests_details(
    is_json: bool,
    test: forgerpc::MachineValidationTestsGetResponse,
) -> CarbideCliResult<()> {
    if is_json {
        for test in test.tests {
            println!("{}", serde_json::to_string_pretty(&test)?);
        }
    } else {
        println!(
            "{}",
            convert_tests_to_nice_format(test.tests).unwrap_or_else(|x| x.to_string())
        );
    }
    Ok(())
}

fn convert_tests_to_nice_table(tests: Vec<forgerpc::MachineValidationTest>) -> Box<Table> {
    let mut table = Table::new();

    table.set_titles(row![
        "TestId",
        "Name",
        "Command",
        "Timeout",
        "IsVerified",
        "Version",
        "IsEnabled",
    ]);

    for test in tests {
        table.add_row(row![
            test.test_id,
            test.name,
            test.command,
            test.timeout.unwrap_or_default().to_string(),
            test.verified,
            test.version,
            test.is_enabled,
        ]);
    }

    table.into()
}

fn convert_tests_to_nice_format(
    tests: Vec<forgerpc::MachineValidationTest>,
) -> CarbideCliResult<String> {
    let width = 14;
    let mut lines = String::new();
    if tests.is_empty() {
        return Ok(lines);
    }
    // data.clear();
    for test in tests {
        writeln!(
            &mut lines,
            "\t------------------------------------------------------------------------"
        )?;
        let contexts = match serde_json::to_string(&test.contexts) {
            Ok(msg) => msg,
            Err(_) => "[]".to_string(),
        };
        let platforms = match serde_json::to_string(&test.supported_platforms) {
            Ok(msg) => msg,
            Err(_) => "[]".to_string(),
        };
        let custom_tags = match serde_json::to_string(&test.custom_tags) {
            Ok(msg) => msg,
            Err(_) => "[]".to_string(),
        };
        let components = match serde_json::to_string(&test.components) {
            Ok(msg) => msg,
            Err(_) => "[]".to_string(),
        };

        let details = vec![
            ("TestId", test.test_id),
            ("Name", test.name),
            ("Description", test.description.unwrap_or_default()),
            ("Command", test.command),
            ("Args", test.args),
            ("Contexts", contexts),
            ("PreCondition", test.pre_condition.unwrap_or_default()),
            ("TimeOut", test.timeout.unwrap().to_string()),
            ("CustomTags", custom_tags),
            ("Components", components),
            ("SupportedPlatforms", platforms),
            ("ImageName", test.img_name.unwrap_or_default()),
            ("ContainerArgs", test.container_arg.unwrap_or_default()),
            (
                "ExecuteInHost",
                test.execute_in_host.unwrap_or_default().to_string(),
            ),
            ("ExtraErrorFile", test.extra_err_file.unwrap_or_default()),
            (
                "ExtraOutPutFile",
                test.extra_output_file.unwrap_or_default(),
            ),
            (
                "ExternalConfigFile",
                test.external_config_file.unwrap_or_default(),
            ),
            ("Version", test.version.to_string()),
            ("LastModifiedAt", test.last_modified_at),
            ("LastModifiedBy", test.modified_by),
            ("IsVerified", test.verified.to_string()),
            ("IsReadOnly", test.read_only.to_string()),
            ("IsEnabled", test.is_enabled.to_string()),
        ];

        for (key, value) in details {
            writeln!(&mut lines, "{key:<width$}: {value}")?;
        }
        writeln!(
            &mut lines,
            "\t------------------------------------------------------------------------"
        )?;
    }
    Ok(lines)
}

pub async fn machine_validation_test_verfied(
    api_client: &ApiClient,
    options: VerifyTestOptions,
) -> CarbideCliResult<()> {
    api_client
        .0
        .machine_validation_test_verfied(MachineValidationTestVerfiedRequest {
            test_id: options.test_id,
            version: options.version,
        })
        .await?;
    Ok(())
}

pub async fn machine_validation_test_enable(
    api_client: &ApiClient,
    options: EnableDisableTestOptions,
) -> CarbideCliResult<()> {
    api_client
        .0
        .machine_validation_test_enable_disable_test(
            MachineValidationTestEnableDisableTestRequest {
                test_id: options.test_id,
                version: options.version,
                is_enabled: true,
            },
        )
        .await?;
    Ok(())
}

pub async fn machine_validation_test_disable(
    api_client: &ApiClient,
    options: EnableDisableTestOptions,
) -> CarbideCliResult<()> {
    api_client
        .0
        .machine_validation_test_enable_disable_test(
            MachineValidationTestEnableDisableTestRequest {
                test_id: options.test_id,
                version: options.version,
                is_enabled: false,
            },
        )
        .await?;
    Ok(())
}

pub async fn machine_validation_test_update(
    api_client: &ApiClient,
    options: UpdateTestOptions,
) -> CarbideCliResult<()> {
    let payload = forgerpc::machine_validation_test_update_request::Payload {
        contexts: options.contexts,
        img_name: options.img_name,
        execute_in_host: options.execute_in_host,
        container_arg: options.container_arg,
        command: options.command,
        args: options.args,
        extra_err_file: options.extra_err_file,
        external_config_file: options.external_config_file,
        pre_condition: options.pre_condition,
        timeout: options.timeout,
        extra_output_file: options.extra_output_file,
        supported_platforms: options.supported_platforms,
        custom_tags: options.custom_tags,
        components: options.components,
        is_enabled: options.is_enabled,
        description: options.description,
        verified: None,
        name: None,
    };
    api_client
        .0
        .update_machine_validation_test(MachineValidationTestUpdateRequest {
            test_id: options.test_id,
            version: options.version,
            payload: Some(payload),
        })
        .await?;
    Ok(())
}

pub async fn machine_validation_test_add(
    api_client: &ApiClient,
    options: AddTestOptions,
) -> CarbideCliResult<()> {
    let mut contexts = vec!["OnDemand".to_string()];
    if !options.contexts.is_empty() {
        contexts = options.contexts;
    }

    let mut supported_platforms = vec!["New_Sku".to_string()];
    if !options.supported_platforms.is_empty() {
        supported_platforms = options.supported_platforms;
    }
    let mut description = Some("new test case".to_string());
    if options.description.is_some() {
        description = options.description;
    }
    let request = forgerpc::MachineValidationTestAddRequest {
        name: options.name,
        description,
        contexts,
        img_name: options.img_name,
        execute_in_host: options.execute_in_host,
        container_arg: options.container_arg,
        command: options.command,
        args: options.args,
        extra_err_file: options.extra_err_file,
        external_config_file: options.external_config_file,
        pre_condition: options.pre_condition,
        timeout: options.timeout,
        extra_output_file: options.extra_output_file,
        supported_platforms,
        read_only: options.read_only,
        custom_tags: options.custom_tags,
        components: options.components,
        is_enabled: options.is_enabled,
    };
    api_client.0.add_machine_validation_test(request).await?;
    Ok(())
}
