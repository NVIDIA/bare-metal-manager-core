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

use std::fmt::Display;

use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

/// Start a task that will wait for SIGINT or SIGTERM, and will cancel the given CancellationToken
/// when either of them occur.
pub(super) fn start(join_set: &mut JoinSet<()>, cancel_token: CancellationToken) {
    // Register the signals before returning
    let signal_future = shutdown_signal();

    join_set
        .build_task()
        .name("shutdown signal handler")
        .spawn(async move {
            tokio::select! {
                _ = cancel_token.cancelled() => {}
                signal = signal_future => {
                    tracing::info!(%signal, "Shutdown signal received");
                    cancel_token.cancel();
                }
            }
        })
        // Safety: tokio::task::Builder::spawn always returns Ok, runtime issues cause panics
        // instead of Err.
        .expect("signal handler should spawn successfully");
}

enum ShutdownCause {
    Int,
    Term,
}

impl Display for ShutdownCause {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ShutdownCause::Int => write!(f, "SIGINT"),
            ShutdownCause::Term => write!(f, "SIGTERM"),
        }
    }
}

fn shutdown_signal() -> impl Future<Output = ShutdownCause> {
    use tokio::signal::unix::{SignalKind, signal};

    // Register the signals before returning
    let mut terminate =
        signal(SignalKind::terminate()).expect("Failed to register SIGTERM handler");
    let mut interrupt = signal(SignalKind::interrupt()).expect("Failed to register SIGINT handler");

    async move {
        tokio::select! {
            _ = interrupt.recv() => ShutdownCause::Int,
            _ = terminate.recv() => ShutdownCause::Term,
        }
    }
}
