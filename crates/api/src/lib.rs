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
//! The Carbide API server library.
//!

// It's too cumbersome for tests to adhere to these, which are less important in testing anyway.
#![cfg_attr(test, allow(txn_held_across_await))]
#![cfg_attr(test, allow(txn_without_commit))]
#![allow(unknown_lints)]

// NOTE on pub vs non-pub mods:
//
// carbide-api is a CLI crate, not a lib. The only reason we have lib.rs is to export things so that
// the `api-test` crate can do integration tests against carbide-api. And even that is a compromise:
// `api-test` should be as "black box" as possible, and we should only be exporting things like the
// main `run()` function and some [`cfg`] types, so that api-test can run a full carbide server.
// Otherwise, lib.rs should be mostly private ("mod", not "pub mod" in these lines), so that we get
// working dead-code detection: If modules here are public, rust will not find dead code for
// anything marked `pub` within the module.

mod api;
mod attestation;
mod auth;
mod cfg;
mod credentials;
mod db_init;
mod dhcp;
mod dpa;
mod dynamic_settings;
mod errors;
mod ethernet_virtualization;
mod firmware_downloader;
mod handlers;
mod ib;
mod ib_fabric_monitor;
mod instance;
mod ipmitool;
mod ipxe;
mod listener;
mod logging;
mod machine_update_manager;
mod machine_validation;
mod measured_boot;
mod mqtt_state_change_hook;
mod network_segment;
mod nvl_partition_monitor;
mod nvlink;
mod preingestion_manager;
mod rack;
mod redfish;
mod run;
mod scout_stream;
mod setup;
mod site_explorer;
mod state_controller;
mod storage;
#[cfg(test)]
mod tests;
mod web;

// Allow carbide_macros::sqlx_test to be referred as #[crate::sqlx_test]
#[cfg(test)]
pub(crate) use carbide_macros::sqlx_test;
// TODO: temporary while migrating db to its own crate
pub use db::{DatabaseError, DatabaseResult};
// Save typing
pub(crate) use errors::{CarbideError, CarbideResult};

// Stuff needed by main.rs and api-test
pub use crate::{cfg::command_line::Command, cfg::command_line::Options, run::run};
