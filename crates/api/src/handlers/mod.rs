/*
 * SPDX-FileCopyrightText: Copyright (c) 2024-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

pub mod api;
pub mod attestation;
pub mod bmc_endpoint_explorer;
pub mod bmc_metadata;
pub mod boot_override;
pub mod credential;
pub mod db;
pub mod dns;
pub mod domain;
pub mod dpa;
pub mod dpf;
pub mod dpu;
pub mod dpu_remediation;
pub mod expected_machine;
pub mod expected_power_shelf;
pub mod expected_switch;
pub mod extension_service;
pub mod finder;
pub mod firmware;
pub mod health;
pub mod host_reprovisioning;
pub mod ib_fabric;
pub mod ib_partition;
pub mod instance;
pub mod instance_type;
pub mod logical_partition;
pub mod machine;
pub mod machine_discovery;
pub mod machine_hardware_info;
pub mod machine_interface;
pub mod machine_quarantine;
pub mod machine_scout;
pub mod machine_validation;
pub mod managed_host;
#[cfg(feature = "linux-build")]
pub mod measured_boot;
pub mod mlx_admin;
pub mod network_devices;
pub mod network_security_group;
pub mod network_segment;
pub mod nvl_partition;
pub mod power_options;
pub mod power_shelf;
pub mod pxe;
pub mod rack;
pub mod rack_firmware;
pub mod redfish;
pub mod resource_pool;
pub mod route_server;
pub mod scout_stream;
pub mod site_explorer;
pub mod sku;
pub mod switch;
pub mod tenant;
pub mod tenant_keyset;
pub mod tpm_ca;
pub mod uefi;
pub mod utils;
pub mod vpc;
pub mod vpc_peering;
pub mod vpc_prefix;
