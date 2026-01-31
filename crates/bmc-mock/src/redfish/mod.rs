/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

pub mod account_service;
pub mod bios;
pub mod boot_options;
pub mod chassis;
pub mod collection;
pub mod computer_system;
pub mod ethernet_interface;
pub mod log_services;
pub mod manager;
pub mod manager_network_protocol;
pub mod network_adapter;
pub mod network_device_function;
pub mod oem;
pub mod pcie_device;
pub mod resource;
pub mod secure_boot;
pub mod service_root;
pub mod software_inventory;
pub mod task_service;
pub mod update_service;

pub use collection::Collection;
pub use resource::Resource;
