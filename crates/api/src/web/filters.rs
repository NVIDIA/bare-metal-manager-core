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

/*
 * This module has to be called 'filters'.
 * Askama makes all these functions accessible as template filters.
 */

use std::collections::BTreeSet;
use std::fmt::{Display, Write};
use std::str::FromStr;

use askama_escape::Escaper;
use carbide_uuid::machine::MachineId;

/// Generates HTML links for Machine IDs
pub fn machine_id_link(id: impl Display) -> ::askama::Result<String> {
    machine_link(id, "machine")
}

/// Generates a formatted link for Machine IDs to a predefined path
fn machine_link(id: impl Display, path: impl Display) -> ::askama::Result<String> {
    let id = id.to_string();
    let short_id = if MachineId::from_str(&id).is_err() {
        // Not a Machine ID. Escape HTML to make it safe for post processing with safe filter
        let mut output = String::new();
        askama_escape::Html.write_escaped(&mut output, &id)?;
        return Ok(output);
    } else {
        // "fm100dsbiu5ckus880v8407u0mkcensa39cule26im5gnpvmuufckacguc0" -> "acguc0"
        &id[id.len() - 6..]
    };

    let formatted = format!(
        r#"
    <a href="/admin/{path}/{id}">
        <div class="machine_id">
            <div>{id}</div><div>{short_id}</div>
        </div>
    </a>"#
    );

    Ok(formatted)
}

/// Formats labels into HTML
pub fn label_list_fmt(labels: &[rpc::forge::Label], truncate: bool) -> ::askama::Result<String> {
    const MAX_LABEL_LENGTH: usize = 32;

    // Format labels by key to get a consistent order
    let mut labels = labels.to_vec();
    labels.sort_by(|l1, l2| l1.key.cmp(&l2.key));

    let mut result = String::new();
    for label in labels.iter() {
        if !result.is_empty() {
            result += "<br>";
        }
        result += "<b>";
        let truncated_key = if truncate && label.key.len() > MAX_LABEL_LENGTH {
            &format!(
                "{}...",
                &label.key.chars().take(MAX_LABEL_LENGTH).collect::<String>()
            )
        } else {
            &label.key
        };
        askama_escape::Html.write_escaped(&mut result, truncated_key)?;
        result += "</b>";

        if let Some(value) = label.value.as_ref() {
            result += ": ";
            let truncated_value = if truncate && value.len() > MAX_LABEL_LENGTH {
                &format!(
                    "{}...",
                    &value.chars().take(MAX_LABEL_LENGTH).collect::<String>()
                )
            } else {
                value
            };
            askama_escape::Html.write_escaped(&mut result, truncated_value)?;
        }
    }
    Ok(result)
}

/// Formats a list of Health Probe Alerts
/// If there is no alert, generates a green "None" bubble
/// Generates HTML using the unified bubble system
pub fn health_alerts_fmt(
    alerts: &[health_report::HealthProbeAlert],
    include_message: bool,
    include_target: bool,
) -> ::askama::Result<String> {
    if alerts.is_empty() {
        return Ok(r#"<span class="bubble success">None</span>"#.to_string());
    }

    let mut result = String::new();
    for alert in alerts.iter() {
        if !result.is_empty() {
            result += " ";
        }

        result += r#"<span class="bubble error">"#;
        askama_escape::Html.write_escaped(&mut result, &alert.id.to_string())?;
        if include_target && let Some(target) = alert.target.as_ref() {
            result += " [Target: ";
            askama_escape::Html.write_escaped(&mut result, target)?;
            result.push(']');
        }

        if include_message {
            result += ": ";
            askama_escape::Html.write_escaped(&mut result, &alert.message)?;
        }
        result += r#"</span>"#;
    }
    Ok(result)
}

/// Formats a list of Health Alert Classifications
/// If there is no alert, the generated String will be empty
pub fn health_alert_classifications_fmt<'a, T, AlertRef>(alerts: T) -> ::askama::Result<String>
where
    T: IntoIterator<Item = AlertRef>,
    AlertRef: std::borrow::Borrow<&'a health_report::HealthProbeAlert> + 'a,
{
    let mut result = String::new();
    let mut classifications = BTreeSet::<health_report::HealthAlertClassification>::new();

    for alert_ref in alerts.into_iter() {
        let alert: &health_report::HealthProbeAlert = alert_ref.borrow();
        classifications.extend(alert.classifications.iter().cloned());
    }

    for classification in classifications.iter() {
        if !result.is_empty() {
            result += "<br>";
        }
        result += r#"<div class="health_alert_classification">"#;
        askama_escape::Html.write_escaped(&mut result, &classification.to_string())?;
        result += r#"</div>"#;
    }

    Ok(result)
}

/// Renders version strings including timestamps
/// Also shows the localized timestamp on Mouseover
pub fn config_version(version: impl Display) -> ::askama::Result<String> {
    let string_version = version.to_string();
    let version = match string_version.parse::<config_version::ConfigVersion>() {
        Ok(version) => version,
        Err(_) => return Ok(string_version),
    };

    let utc_time = version.timestamp();
    let formatted_utc_time = utc_time.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true);
    Ok(format!(
        "{string_version}<br><small>[<span title=\"{formatted_utc_time}\" onmouseover=\"setTitleToLocalizedTime(this)\">{formatted_utc_time}</span>]</small>"
    ))
}

/// Prints the value of the `Option` in case it's `Some(x)`, and otherwise an empty string
pub fn option_fmt(value: &Option<impl Display>) -> askama::Result<String> {
    Ok(match value {
        Some(value) => value.to_string(),
        None => String::new(),
    })
}

/// Formats the boot order list
pub fn boot_order_fmt(
    boot_order: &Option<rpc::site_explorer::BootOrder>,
) -> ::askama::Result<String> {
    let json_result = boot_order
        .as_ref()
        .and_then(|order| serde_json::to_string_pretty(order).ok())
        .unwrap_or_default();

    Ok(json_result
        .trim_matches(|c| c == '{' || c == '}')
        .trim()
        .to_string())
}

pub fn colorize_output(ansi_text: &str) -> ::askama::Result<String> {
    let html = ansi_to_html::Converter::new()
        .convert(ansi_text)
        .unwrap_or_default();
    Ok(html)
}

/// Formats a state handler outcome
pub fn controller_state_reason_fmt(
    reason: &Option<::rpc::forge::ControllerStateReason>,
) -> ::askama::Result<String> {
    let Some(reason) = reason else {
        return Ok(String::new());
    };

    let mut result = String::new();
    let classes = match reason.outcome() {
        rpc::forge::ControllerStateOutcome::Wait => "bubble warning".to_string(),
        rpc::forge::ControllerStateOutcome::Error => "bubble error".to_string(),
        _ => "bubble".to_string(),
    };

    write!(
        &mut result,
        "<b>Outcome:</b> <span class=\"{classes}\">{:?}</span>",
        reason.outcome()
    )
    .unwrap();
    if let Some(message) = &reason.outcome_msg {
        write!(&mut result, "<br><b>Message:</b> ").unwrap();
        askama_escape::Html.write_escaped(&mut result, message)?;
    }

    if let Some(source_ref) = reason.source_ref.as_ref() {
        const GITLAB_REPO: &str = "https://gitlab-master.nvidia.com/nvmetal/carbide";

        // TODO: carbide_version::v!(git_sha) should work here - however it returns an
        // outdated commit ID.
        let build_version = carbide_version::v!(build_version);
        let commit_hash = match build_version.rfind('g') {
            Some(idx) if idx != build_version.len() - 1 => &build_version[idx + 1..],
            _ => "trunk",
        };

        write!(
            &mut result,
            "<br><b>Source:</b> <a href=\"{}/-/blob/{}/{}#L{}\">{}:{}</a>",
            GITLAB_REPO,
            commit_hash,
            source_ref.file,
            source_ref.line,
            source_ref.file,
            source_ref.line
        )
        .unwrap();
    }

    Ok(result)
}
