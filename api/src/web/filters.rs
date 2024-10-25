/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

/*
 * This module has to be called 'filters'.
 * Askama makes all these functions accessible as template filters.
 */

use std::collections::BTreeSet;

use askama_escape::Escaper;

/// Generates HTML links for Machine IDs
pub fn machine_id_link<T: std::fmt::Display>(id: T) -> ::askama::Result<String> {
    machine_link(id.to_string(), "machine")
}

/// Generates HTML links to the Managed Host page for Machine IDs
pub fn managed_host_id_link<T: std::fmt::Display>(id: T) -> ::askama::Result<String> {
    machine_link(id.to_string(), "managed-host")
}

/// Generates a formatted link for Machine IDs to a predefined path
fn machine_link(id: String, path: &str) -> ::askama::Result<String> {
    let short_id = if id.len() < 25
        || !id.starts_with("fm100")
        || id.chars().any(|c| !c.is_ascii_alphanumeric())
    {
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
/// If there is no alert, the generated String will be "None"
pub fn health_alerts_fmt(
    alerts: &[health_report::HealthProbeAlert],
    include_message: bool,
) -> ::askama::Result<String> {
    if alerts.is_empty() {
        return Ok("None".to_string());
    }

    let mut result = String::new();
    for alert in alerts.iter() {
        if !result.is_empty() {
            result += "<br>";
        }
        askama_escape::Html.write_escaped(&mut result, &alert.id.to_string())?;
        if let Some(target) = alert.target.as_ref() {
            result += " [Target: ";
            askama_escape::Html.write_escaped(&mut result, target)?;
            result.push(']');
        }

        if include_message {
            result += ": ";
            askama_escape::Html.write_escaped(&mut result, &alert.message)?;
        }
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
pub fn config_version<T: std::fmt::Display>(version: T) -> ::askama::Result<String> {
    let string_version = version.to_string();
    let version = match string_version.parse::<config_version::ConfigVersion>() {
        Ok(version) => version,
        Err(_) => return Ok(string_version),
    };

    let utc_time = version.timestamp();
    let formatted_utc_time = utc_time.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true);
    Ok(format!("{string_version}<br><small>[<span title=\"{}\" onmouseover=\"setTitleToLocalizedTime(this)\">{}</span>]</small>", formatted_utc_time, formatted_utc_time))
}

/// Prints the value of the `Option` in case it's `Some(x)`, and otherwise an empty string
pub fn option_fmt<T>(value: &Option<T>) -> askama::Result<String>
where
    T: std::fmt::Display,
{
    Ok(match value {
        Some(value) => value.to_string(),
        None => String::new(),
    })
}
