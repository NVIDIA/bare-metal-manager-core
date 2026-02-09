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
