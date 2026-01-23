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

use std::time::Duration;

pub const LOCKING: Duration = Duration::from_secs(15 * 60);
pub const APPLY_PROFILE: Duration = Duration::from_secs(15 * 60);
pub const UNLOCKING: Duration = Duration::from_secs(15 * 60);
pub const WAITINGFORSETVNI: Duration = Duration::from_secs(15 * 60);
pub const WAITINGFORRESETVNI: Duration = Duration::from_secs(15 * 60);
