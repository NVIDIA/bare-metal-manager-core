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

//!
//! The Carbide API server library.
//!

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
mod db;
mod db_init;
mod dhcp;
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
mod measured_boot;
mod model;
mod network_segment;
mod preingestion_manager;
mod redfish;
mod resource_pool;
mod run;
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

// Save typing
pub(crate) use errors::{CarbideError, CarbideResult};

// Stuff needed by main.rs and api-test
pub use crate::{
    cfg::command_line::Command, cfg::command_line::Options, db::migrations::migrate, run::run,
};
