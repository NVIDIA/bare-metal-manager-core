/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! Implementation interface for the top-level `carbide-api` composition crate.
//!
//! This is not a general-purpose library API. It groups the process-bootstrap
//! types that must cross the crate boundary while service implementation stays
//! in `carbide-api-core`.

pub use crate::api::metrics::ApiMetricsEmitter;
pub use crate::logging::level_filter::{ActiveLevel, ReloadableFilter};
pub use crate::logging::setup::{Logging, dep_log_filter};
pub use crate::logging::stream::LogStreamLayer;
pub use crate::run::{CoreRunInputs, run_core};
