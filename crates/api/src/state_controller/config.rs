/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::time::Duration;

/// General settings for state controller iterations
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct IterationConfig {
    /// Configures the desired duration for one state controller iteration
    ///
    /// Lower iteration times will make the controller react faster to state changes.
    /// However they will also increase the load on the system
    pub iteration_time: Duration,

    /// Configures the maximum time that the state handler will spend on evaluating
    /// and advancing the state of a single object. If more time elapses during
    /// state handling than this timeout allows for, state handling will fail with
    /// a `TimeoutError`.
    pub max_object_handling_time: Duration,

    /// Configures the maximum amount of concurrency for the object state controller
    ///
    /// The controller will attempt to advance the state of this amount of instances
    /// in parallel.
    pub max_concurrency: usize,
}

impl Default for IterationConfig {
    fn default() -> Self {
        Self {
            iteration_time: Duration::from_secs(30),
            // This is by default set rather high to make sure we usually run the operations
            // in the state handlers to completion. The purpose of the timeout is just to
            // prevent an indefinitely stuck state handler - e.g. to due to networking issues
            // and missing sqlx timeouts
            max_object_handling_time: Duration::from_secs(3 * 60),
            max_concurrency: 10,
        }
    }
}
