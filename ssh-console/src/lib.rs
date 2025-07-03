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

//! ssh-console - BMC Serial Console Proxy
//!
//! This crate provides an SSH server that acts as a proxy to BMC (Baseboard Management Controller)
//! serial consoles. It supports multiple BMC vendors (Dell, Lenovo, HPE) and handles authentication
//! through either OpenSSH certificates or public key validation via a carbide-api.
//!
//! ## Architecture
//!
//! - [`ssh_server::server`]: Responsible for running the service itself
//! - [`ssh_server::frontend`]: Handles SSH client connections and authentication
//! - [`ssh_server::backend`]: Manages connections to BMC devices and serial console activation
//! - [`config`]: Configuration management with TOML file support
//! - [`bmc_vendor`]: Vendor-specific BMC interaction logic

pub mod bmc_vendor;
mod ssh_server;

// pub mods are only ones used by main.rs and integration tests
pub mod config;

pub use ssh_server::{SpawnHandle, spawn};
