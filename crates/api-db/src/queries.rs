/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

// Queries in this module are large enough that it makes sense to have them as separate files rather
// than huge inline rust strings.

use lazy_static::lazy_static;

static MANAGED_HOSTS_TEMPLATE: &str = include_str!("sql/managed_hosts.sql.template");
static MACHINE_SNAPSHOTS_TEMPLATE: &str = include_str!("sql/machine_snapshots.sql.template");
static MANAGED_HOST_HISTORY_JOIN_SNIPPET: &str =
    include_str!("sql/managed_host_history_join.snippet");
static MACHINE_SNAPSHOT_HISTORY_JOIN_SNIPPET: &str =
    include_str!("sql/machine_snapshot_history_join.snippet");
static HISTORY_SELECT_SNIPPET: &str = include_str!("sql/history_select.snippet");

fn replace_sql<F: Fn(&str) -> Option<&str>>(input: &str, f: F) -> String {
    input
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with("--") {
                return None;
            }
            f(trimmed)
        })
        .collect::<Vec<_>>()
        .join(" ")
}

lazy_static! {
    pub static ref MANAGED_HOSTS_WITH_HISTORY: String =
        replace_sql(MANAGED_HOSTS_TEMPLATE, |line| {
            match line {
                "__HISTORY_SELECT__" => Some(HISTORY_SELECT_SNIPPET),
                "__HISTORY_JOIN__" => Some(MANAGED_HOST_HISTORY_JOIN_SNIPPET),
                default => Some(default),
            }
        });
    pub static ref MANAGED_HOSTS_NO_HISTORY: String = replace_sql(MANAGED_HOSTS_TEMPLATE, |line| {
        match line {
            "__HISTORY_SELECT__" => None,
            "__HISTORY_JOIN__" => None,
            default => Some(default),
        }
    });
    pub static ref MACHINE_SNAPSHOTS_WITH_HISTORY: String =
        replace_sql(MACHINE_SNAPSHOTS_TEMPLATE, |line| {
            match line {
                "__HISTORY_SELECT__" => Some(HISTORY_SELECT_SNIPPET),
                "__HISTORY_JOIN__" => Some(MACHINE_SNAPSHOT_HISTORY_JOIN_SNIPPET),
                default => Some(default),
            }
        });
    pub static ref MACHINE_SNAPSHOTS_NO_HISTORY: String =
        replace_sql(MACHINE_SNAPSHOTS_TEMPLATE, |line| {
            match line {
                "__HISTORY_SELECT__" => None,
                "__HISTORY_JOIN__" => None,
                default => Some(default),
            }
        });
}
