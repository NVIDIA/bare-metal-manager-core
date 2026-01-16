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

//! MQTT state change hook for publishing ManagedHostState transitions.
//!
//! This module implements the AsyncAPI specification defined in `carbide.yaml`,
//! publishing state changes to `carbide/v1/machine/{machineId}/state` over MQTT 3.1.1.

pub mod hook;
pub mod message;
pub mod metrics;
