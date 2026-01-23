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

pub mod ipmi;
pub mod ssh;

use chrono::{DateTime, SecondsFormat, Utc};
use tokio::sync::oneshot;

use crate::bmc::pending_output_line::PendingOutputLine;

fn echo_connected_message(
    tx: oneshot::Sender<Vec<u8>>,
    pending_line: &PendingOutputLine,
    total_bytes: usize,
    last_output_received: Option<DateTime<Utc>>,
    connected_since: DateTime<Utc>,
) {
    let mut lines = Vec::with_capacity(6);

    lines.push(b"---\r\n".to_vec());
    lines.push(
        format!(
            "Console connected for {} (since {})\r\n",
            format_duration_since(connected_since),
            connected_since.to_rfc3339_opts(SecondsFormat::Secs, true),
        )
        .into_bytes(),
    );

    if let Some(last_output_received) = last_output_received {
        lines.push(
            format!(
                "Output seen from console: {} KB\r\n",
                total_bytes.div_ceil(1024)
            )
            .into_bytes(),
        );
        lines.push(
            format!(
                "Last output received {} ago at {}\r\n",
                format_duration_since(last_output_received),
                last_output_received.to_rfc3339_opts(SecondsFormat::Secs, true),
            )
            .into_bytes(),
        );
    } else {
        lines.push(b"No output received from console yet.\r\n".to_vec());
    }

    lines.push(b"---\r\n".to_vec());
    lines.push(pending_line.get().to_vec());

    tx.send(lines.concat()).ok();
}

fn format_duration_since(ts: DateTime<Utc>) -> String {
    let mut secs = Utc::now().signed_duration_since(ts).as_seconds_f64().ceil() as usize;
    let days = secs / 86_400;
    secs %= 86_400;
    let hours = secs / 3600;
    secs %= 3600;
    let minutes = secs / 60;
    let seconds = secs % 60;

    let mut s = String::with_capacity(8);
    if days > 0 {
        s.push_str(&format!("{days}d"));
    }
    if hours > 0 || !s.is_empty() {
        s.push_str(&format!("{hours}h"));
    }
    if minutes > 0 || !s.is_empty() {
        s.push_str(&format!("{minutes}m"));
    }
    s.push_str(&format!("{seconds}s"));
    s
}
