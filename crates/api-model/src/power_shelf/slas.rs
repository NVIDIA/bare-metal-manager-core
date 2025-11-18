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

/// SLA for PowerShelf initialization in seconds
pub const INITIALIZING: u64 = 300; // 5 minutes

/// SLA for PowerShelf fetching data in seconds
pub const FETCHING_DATA: u64 = 300; // 5 minutes

/// SLA for PowerShelf configuring in seconds
pub const CONFIGURING: u64 = 300; // 5 minutes

// /// SLA for PowerShelf ready in seconds
// pub const READY: u64 = 0; // 0 minutes

// /// SLA for PowerShelf error in seconds
// pub const ERROR: u64 = 300; // 5 minutes

/// SLA for PowerShelf deleting in seconds
pub const DELETING: u64 = 300; // 5 minutes
