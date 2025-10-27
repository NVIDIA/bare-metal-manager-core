/*
 * SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

//! SLAs for Dpa Interface State Machine Controller
//! These SLAs are in seconds

pub const PROVISIONING: u64 = 15 * 60;

pub const WAITINGFORSETVNI: u64 = 15 * 60;

pub const WAITINGFORRESETVNI: u64 = 15 * 60;
