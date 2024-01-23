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
    let full_id = id.to_string();
    let short_id = if full_id.len() < 25
        || !full_id.starts_with("fm100")
        || full_id.as_bytes()[5] == b'p' // Predicted Hosts are not linked
        || full_id.chars().any(|c| !c.is_ascii_alphanumeric())
    {
        // Not a Machine ID. Escape HTML to make it safe for post processing with safe filter
        let mut output = String::new();
        askama_escape::Html.write_escaped(&mut output, &full_id)?;
        return Ok(output);
    } else {
        // "fm100dsbiu5ckus880v8407u0mkcensa39cule26im5gnpvmuufckacguc0" -> "acguc0"
        &full_id[full_id.len() - 6..]
    };

    let formatted = format!(
        r#"
    <a href="/admin/machine/{full_id}">
        <div class="machine_id">
            <div>{full_id}</div><div>{short_id}</div>
        </div>
    </a>"#
    );

    Ok(formatted)
}
