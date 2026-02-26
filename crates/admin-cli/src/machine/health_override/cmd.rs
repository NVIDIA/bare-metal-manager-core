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

use std::str::FromStr;

use ::rpc::admin_cli::{CarbideCliError, CarbideCliResult, OutputFormat};
use ::rpc::forge::{self as forgerpc, RemoveHealthReportOverrideRequest};
use chrono::Utc;
use health_report::{
    HealthAlertClassification, HealthProbeAlert, HealthProbeId, HealthProbeSuccess, HealthReport,
};
use prettytable::{Table, row};

use super::args::{Args, HealthOverrideTemplates};
use crate::rpc::ApiClient;

fn get_empty_template() -> HealthReport {
    HealthReport {
        source: "".to_string(),
        observed_at: Some(Utc::now()),
        successes: vec![HealthProbeSuccess {
            id: HealthProbeId::from_str("test").unwrap(),
            target: Some("".to_string()),
        }],
        alerts: vec![HealthProbeAlert {
            id: HealthProbeId::from_str("test").unwrap(),
            target: None,
            in_alert_since: None,
            message: "".to_string(),
            tenant_message: None,
            classifications: vec![
                HealthAlertClassification::prevent_allocations(),
                HealthAlertClassification::prevent_host_state_changes(),
                HealthAlertClassification::suppress_external_alerting(),
            ],
        }],
    }
}

pub fn get_health_report(
    template: HealthOverrideTemplates,
    message: Option<String>,
) -> HealthReport {
    let mut report = HealthReport {
        source: "admin-cli".to_string(),
        observed_at: Some(Utc::now()),
        successes: vec![],
        alerts: vec![HealthProbeAlert {
            id: HealthProbeId::from_str("Maintenance").unwrap(),
            target: None,
            in_alert_since: None,
            message: message.unwrap_or_default(),
            tenant_message: None,
            classifications: vec![
                HealthAlertClassification::prevent_allocations(),
                HealthAlertClassification::suppress_external_alerting(),
            ],
        }],
    };

    match template {
        HealthOverrideTemplates::HostUpdate => {
            report.source = "host-update".to_string();
            report.alerts[0].id = HealthProbeId::from_str("HostUpdateInProgress").unwrap();
            report.alerts[0].target = Some("admin-cli".to_string());
        }
        HealthOverrideTemplates::InternalMaintenance => {
            report.source = "maintenance".to_string();
        }
        HealthOverrideTemplates::StopRebootForAutomaticRecoveryFromStateMachine => {
            report.source = "manual-maintenance".to_string();
            report.alerts[0].target = Some("admin-cli".to_string());
            report.alerts[0].classifications = vec![
                HealthAlertClassification::stop_reboot_for_automatic_recovery_from_state_machine(),
            ];
        }
        HealthOverrideTemplates::OutForRepair => {
            report.source = "manual-maintenance".to_string();
            report.alerts[0].target = Some("OutForRepair".to_string());
        }
        HealthOverrideTemplates::Degraded => {
            report.source = "manual-maintenance".to_string();
            report.alerts[0].target = Some("Degraded".to_string());
        }
        HealthOverrideTemplates::Validation => {
            report.source = "manual-maintenance".to_string();
            report.alerts[0].target = Some("Validation".to_string());
            report.alerts[0].classifications =
                vec![HealthAlertClassification::suppress_external_alerting()];
        }
        HealthOverrideTemplates::SuppressExternalAlerting => {
            report.source = "suppress-paging".to_string();
            report.alerts[0].target = Some("SuppressExternalAlerting".to_string());
            report.alerts[0].classifications =
                vec![HealthAlertClassification::suppress_external_alerting()];
        }
        HealthOverrideTemplates::MarkHealthy => {
            report.source = "admin-cli".to_string();
            report.alerts.clear();
        }
        // Template to indicate that the instance is identified as unhealthy by the tenant and
        // should be fixed before returning to the tenant.
        HealthOverrideTemplates::TenantReportedIssue => {
            report.source = "tenant-reported-issue".to_string();
            report.alerts[0].id = HealthProbeId::from_str("TenantReportedIssue")
                .expect("TenantReportedIssue is a valid non-empty HealthProbeId");
            report.alerts[0].target = Some("tenant-reported".to_string());
            report.alerts[0].classifications = vec![
                HealthAlertClassification::prevent_allocations(),
                HealthAlertClassification::suppress_external_alerting(),
            ];
        }
        // Template to indicate that the instance is identified as unhealthy and
        // is ready to be picked by Repair System for diagnosis and fix.
        HealthOverrideTemplates::RequestRepair => {
            report.source = "repair-request".to_string();
            report.alerts[0].id = HealthProbeId::from_str("RequestRepair")
                .expect("RequestRepair is a valid non-empty HealthProbeId");
            report.alerts[0].target = Some("repair-requested".to_string());
            report.alerts[0].classifications = vec![
                HealthAlertClassification::prevent_allocations(),
                HealthAlertClassification::suppress_external_alerting(),
            ];
        }
    }

    report
}

pub async fn handle_override(
    command: Args,
    output_format: OutputFormat,
    api_client: &ApiClient,
) -> CarbideCliResult<()> {
    match command {
        Args::Show { machine_id } => {
            let response = api_client
                .0
                .list_health_report_overrides(machine_id)
                .await?;
            let mut rows = vec![];
            for r#override in response.overrides {
                let report = r#override.report.ok_or(CarbideCliError::GenericError(
                    "missing response".to_string(),
                ))?;
                let mode = match ::rpc::forge::OverrideMode::try_from(r#override.mode)
                    .map_err(|_| CarbideCliError::GenericError("invalide response".to_string()))?
                {
                    forgerpc::OverrideMode::Merge => "Merge",
                    forgerpc::OverrideMode::Replace => "Replace",
                };
                rows.push((report, mode));
            }
            match output_format {
                OutputFormat::Json => println!(
                    "{}",
                    serde_json::to_string_pretty(
                        &rows
                            .into_iter()
                            .map(|r| {
                                serde_json::json!({
                                    "report": r.0,
                                    "mode": r.1,
                                })
                            })
                            .collect::<Vec<_>>(),
                    )?
                ),
                _ => {
                    let mut table = Table::new();
                    table.set_titles(row!["Report", "Mode"]);
                    for row in rows {
                        table.add_row(row![serde_json::to_string(&row.0)?, row.1]);
                    }
                    table.printstd();
                }
            }
        }
        Args::Add(options) => {
            let report = if let Some(template) = options.template {
                get_health_report(template, options.message)
            } else if let Some(health_report) = options.health_report {
                serde_json::from_str::<health_report::HealthReport>(&health_report)
                    .map_err(CarbideCliError::JsonError)?
            } else {
                return Err(CarbideCliError::GenericError(
                    "Either health_report or template name must be provided.".to_string(),
                ));
            };

            if options.print_only {
                println!("{}", serde_json::to_string_pretty(&report).unwrap());
                return Ok(());
            }

            api_client
                .machine_insert_health_report_override(
                    options.machine_id,
                    report.into(),
                    options.replace,
                )
                .await?;
        }
        Args::Remove {
            machine_id,
            report_source,
        } => {
            api_client
                .0
                .remove_health_report_override(RemoveHealthReportOverrideRequest {
                    machine_id: Some(machine_id),
                    source: report_source,
                })
                .await?;
        }
        Args::PrintEmptyTemplate => {
            println!(
                "{}",
                serde_json::to_string_pretty(&get_empty_template()).unwrap()
            );
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use health_report::{HealthAlertClassification, HealthProbeId};

    use super::*;

    #[test]
    fn test_tenant_reported_issue_template() {
        let report = get_health_report(
            HealthOverrideTemplates::TenantReportedIssue,
            Some("Customer reported network connectivity issues".to_string()),
        );

        assert_eq!(report.source, "tenant-reported-issue");
        assert_eq!(report.alerts.len(), 1);

        let alert = &report.alerts[0];
        assert_eq!(
            alert.id,
            HealthProbeId::from_str("TenantReportedIssue").unwrap()
        );
        assert_eq!(alert.target, Some("tenant-reported".to_string()));
        assert_eq!(
            alert.message,
            "Customer reported network connectivity issues"
        );
        assert!(alert.tenant_message.is_none());

        // Check classifications
        assert_eq!(alert.classifications.len(), 2);
        assert!(
            alert
                .classifications
                .contains(&HealthAlertClassification::prevent_allocations())
        );
        assert!(
            alert
                .classifications
                .contains(&HealthAlertClassification::suppress_external_alerting())
        );
    }

    #[test]
    fn test_request_repair_template() {
        let report = get_health_report(
            HealthOverrideTemplates::RequestRepair,
            Some("Hardware diagnostics indicate memory failure".to_string()),
        );

        assert_eq!(report.source, "repair-request");
        assert_eq!(report.alerts.len(), 1);

        let alert = &report.alerts[0];
        assert_eq!(alert.id, HealthProbeId::from_str("RequestRepair").unwrap());
        assert_eq!(alert.target, Some("repair-requested".to_string()));
        assert_eq!(
            alert.message,
            "Hardware diagnostics indicate memory failure"
        );
        assert!(alert.tenant_message.is_none());

        // Check classifications
        assert_eq!(alert.classifications.len(), 2);
        assert!(
            alert
                .classifications
                .contains(&HealthAlertClassification::prevent_allocations())
        );
        assert!(
            alert
                .classifications
                .contains(&HealthAlertClassification::suppress_external_alerting())
        );
    }

    #[test]
    fn test_tenant_reported_issue_template_with_empty_message() {
        let report = get_health_report(HealthOverrideTemplates::TenantReportedIssue, None);

        assert_eq!(report.source, "tenant-reported-issue");
        assert_eq!(report.alerts[0].message, "");
    }

    #[test]
    fn test_request_repair_template_with_empty_message() {
        let report = get_health_report(HealthOverrideTemplates::RequestRepair, None);

        assert_eq!(report.source, "repair-request");
        assert_eq!(report.alerts[0].message, "");
    }

    #[test]
    fn test_new_templates_have_suppress_external_alerting() {
        // Verify both new templates include SuppressExternalAlerting classification
        let tenant_report = get_health_report(
            HealthOverrideTemplates::TenantReportedIssue,
            Some("test".to_string()),
        );
        let repair_report = get_health_report(
            HealthOverrideTemplates::RequestRepair,
            Some("test".to_string()),
        );

        // Both should suppress external alerting
        assert!(
            tenant_report.alerts[0]
                .classifications
                .contains(&HealthAlertClassification::suppress_external_alerting())
        );
        assert!(
            repair_report.alerts[0]
                .classifications
                .contains(&HealthAlertClassification::suppress_external_alerting())
        );
    }
}
