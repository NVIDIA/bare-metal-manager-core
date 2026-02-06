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
// cmd module contains command-line interface logic and command handlers.
pub mod cmd;
// discovery module handles device discovery and enumeration using mlxfwmanager.
pub mod discovery;
// filters module provides filtering capabilities for device queries.
pub mod filters;
// info module defines the core device information structures.
pub mod info;
// proto module contains code for translating to/from protobuf
pub mod proto;
// report module contains the MlxDeviceReport and helpers.
pub mod report;
