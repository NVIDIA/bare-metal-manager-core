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

//!
//! The Carbide API server implementation.
//!
//! This crate holds the [`Api`] service (the gRPC `Forge` implementation and all
//! the business logic behind it), plus the server bootstrap ([`run`]) and the
//! request listener. The admin web UI lives in the separate `carbide-api-web`
//! crate, which depends on this one; the thin `carbide-api` binary crate wires
//! the two together.

// It's too cumbersome for tests to adhere to these, which are less important in testing anyway.
// Gated on `any(test, feature = "test-support")` to match the `tests` module below: the fixtures
// also compile (without `cfg(test)`) when a dependent enables `test-support`, so the allow must
// cover that build too — otherwise the custom txn lints fire on the fixtures under `--all-features`.
#![cfg_attr(any(test, feature = "test-support"), allow(txn_held_across_await))]
#![cfg_attr(any(test, feature = "test-support"), allow(txn_without_commit))]

// NOTE on pub vs non-pub mods:
//
// Most of this crate is private ("mod", not "pub mod"), so that we get working dead-code detection:
// If modules here are public, rust will not find dead code for anything marked `pub` within the
// module. We make public only the minimum surface needed by our two dependents:
//   - the `carbide-api` binary crate, which needs `run`, `init_tools`, and the listener wiring; and
//   - the `carbide-api-web` crate, which needs the `Api` service type and a few shared types
//     (`AuthContext`, `CarbideError`, `LogStream`/`LogLine`, `NUM_REQUIRED_APPROVALS`, and the
//     `cfg::file` config types).
// Anything that doesn't need to cross a crate boundary should stay private.

mod api;
mod attestation;
mod auth;
pub mod cfg;
mod compat;
mod credentials;
mod db_init;
mod dhcp;
mod dpa;
mod dpf_services;
mod dynamic_settings;
mod errors;
mod ethernet_virtualization;
mod handlers;
mod instance;
mod ipxe;
pub mod listener;
mod logging;
mod machine_identity;
mod machine_update_manager;
mod machine_validation;
mod measured_boot;
mod mqtt_state_change_hook;
mod network_segment;
mod run;
mod scout_stream;
pub mod setup;
mod storage;

#[cfg(any(test, feature = "test-support"))]
pub mod test_support;

// Compiled for our own tests, and also when the `test-support` feature is enabled so that
// dependents (notably `carbide-api-web`) can reuse the `tests::common` fixtures to build a real
// `Api`. Only `tests::common` is exposed under `test-support`; the actual test cases stay
// `#[cfg(test)]` (see `tests/mod.rs`).
#[cfg(any(test, feature = "test-support"))]
pub mod tests;

use std::sync::OnceLock;

// Allow carbide_macros::sqlx_test to be referred as #[crate::sqlx_test]
#[cfg(test)]
pub(crate) use carbide_macros::sqlx_test;
// TODO: temporary while migrating db to its own crate
pub use db::{DatabaseError, DatabaseResult};
// Save typing
pub(crate) use errors::CarbideResult;

pub use crate::api::Api;
pub use crate::auth::AuthContext;
pub use crate::cfg::command_line::{Command, Options};
use crate::cfg::file::ToolLink;
pub use crate::errors::CarbideError;
pub use crate::handlers::redfish::NUM_REQUIRED_APPROVALS;
pub use crate::listener::{AdminUiRoutesBuilder, ApiListenMode, ApiTlsConfig};
pub use crate::logging::stream::{LogLine, LogStream};
pub use crate::run::run;

/// Process-global tool list rendered in the admin web UI's "Tools" sidebar.
///
/// This lives here (rather than in `carbide-api-web`) because it is derived from
/// the parsed [`cfg::file::CarbideConfig`] during server startup, before the web
/// layer exists. The web layer reads it back via [`configured_tools`]. It is a
/// write-once `OnceLock` because `base.html` is rendered by more than 70 page
/// structs, and threading the list through all of them (and every test fixture)
/// is far more invasive than a global read.
static TOOLS: OnceLock<Vec<ToolLink>> = OnceLock::new();

/// Initialize the global tool list. Call once during startup before serving any
/// web requests. Subsequent calls are ignored.
pub fn init_tools(tools: Vec<ToolLink>) {
    let _ = TOOLS.set(tools);
}

/// The configured external tool links, for the admin UI's "Tools" sidebar.
///
/// Empty when no tools are configured or when [`init_tools`] has not been called
/// (e.g. unit tests).
pub fn configured_tools() -> &'static [ToolLink] {
    TOOLS.get().map(Vec::as_slice).unwrap_or(&[])
}
