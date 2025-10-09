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

use colored::*;
use similar::{ChangeTag, TextDiff};

use crate::duppet::SyncOptions;

/// logln is a macro used for conditional logging based
/// around the --dry-run and --quiet sync options.
#[macro_export]
macro_rules! logln {
    ($options:expr, $($arg:tt)*) => {{
        if !$options.quiet {
            let prefix = if $options.dry_run { "[dry-run] " } else { "" };
            tracing::info!("{}{}", prefix, format!($($arg)*));
        }
    }};
}

/// maybe_colorize colorizes log line prefixes with fancy
/// pretty colors. Can be disabled with the --no-color sync
/// option, but why would you?
pub fn maybe_colorize<'a>(
    text: &'a str,
    style: fn(&'a str) -> ColoredString,
    options: &SyncOptions,
) -> String {
    if options.no_color {
        text.to_string()
    } else {
        style(text).to_string()
    }
}

/// build_diff builds a diff between the source (expected) and
/// destination (existing) files, in the case where the destination
/// file already exists.
pub fn build_diff(src: &str, dst: &str) -> String {
    let diff = TextDiff::from_lines(dst, src);
    let mut diff_output = String::new();

    for change in diff.iter_all_changes() {
        let sign = match change.tag() {
            ChangeTag::Delete => "-",
            ChangeTag::Insert => "+",
            ChangeTag::Equal => " ",
        };
        diff_output.push_str(&format!("{sign}{change}"));
    }
    diff_output.trim_end().to_string()
}
