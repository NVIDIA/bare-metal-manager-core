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
pub fn label_list_fmt(labels: &[rpc::forge::Label]) -> ::askama::Result<String> {
    let mut result = String::new();
    for label in labels.iter() {
        if !result.is_empty() {
            result += "<br>";
        }
        result += "<b>";
        askama_escape::Html.write_escaped(&mut result, &label.key)?;
        result += "</b>";
        if let Some(value) = label.value.as_ref() {
            result += ": ";
            askama_escape::Html.write_escaped(&mut result, value)?;
        }
    }
    Ok(result)
}
