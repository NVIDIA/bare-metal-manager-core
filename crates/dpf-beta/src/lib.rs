/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

//! # Carbide DPF SDK
//!
//! This crate provides a high-level SDK for interacting with the NVIDIA DPF
//! (DOCA Platform Framework) operator via Kubernetes CRDs.
//!
//! ## Overview
//!
//! The DPF SDK abstracts away the complexity of managing DPF CRDs, providing
//! a clean interface for:
//!
//! - Initializing DPF resources (BFB, DPUFlavor, DPUDeployment with services)
//! - Registering and managing DPU devices
//! - Registering and managing DPU nodes (hosts with DPUs)
//! - Watching for DPF events via callbacks
//!
//! ## Example
//!
//! ```rust,ignore
//! use dpf::{DpfSdk, KubeRepository, DpfInitConfig, DpuWatcherBuilder};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create SDK with Kubernetes backend
//!     let repo = KubeRepository::new().await?;
//!     let sdk = DpfSdk::new(repo, "dpf-operator-system");
//!
//!     // Initialize DPF resources
//!     let config = DpfInitConfig {
//!         bfb_url: "http://example.com/forge.bfb".to_string(),
//!         bmc_password: "secret".to_string(),
//!         ..Default::default()
//!     };
//!     sdk.create_initialization_objects(&config).await?;
//!
//!     // Start watching for events (stopped on drop)
//!     let _watcher = DpuWatcherBuilder::new(sdk.repo(), sdk.namespace())
//!         .on_reboot_required(|event| async move {
//!             println!("Reboot required for: {}", event.host_bmc_ip);
//!             Ok(())
//!         })
//!         .on_dpu_ready(|event| {
//!             println!("DPU ready: {}", event.dpu_name);
//!         })
//!         .start();
//!
//!     // ... do work ...
//!     // watcher is stopped when dropped
//!     Ok(())
//! }
//! ```
#![warn(clippy::all)]
#![deny(warnings, unsafe_code)]

pub mod crds;
pub mod error;
pub mod flavor;
pub mod repository;
pub mod sdk;
pub mod services;
pub mod types;
pub mod watcher;

#[cfg(test)]
mod test;

// Re-exports for convenience
pub use error::DpfError;
pub use repository::{DpfRepository, KubeRepository};
pub use sdk::{DpfSdk, NoLabels, ResourceLabeler, dpu_name, dpu_node_name, node_id_from_node_name};
pub use services::ServiceRegistryConfig;
pub use types::{
    ConfigPortsServiceType, DpfInitConfig, DpuDeviceInfo, DpuErrorEvent, DpuEvent, DpuNodeInfo,
    DpuPhase, DpuReadyEvent, MaintenanceEvent, RebootRequiredEvent, ServiceChainSwitch,
    ServiceConfigPort, ServiceConfigPortProtocol, ServiceDefinition, ServiceInterface,
};
pub use watcher::{DpuWatcher, DpuWatcherBuilder};

/// Default namespace for DPF operator resources.
pub const NAMESPACE: &str = "dpf-operator-system";
