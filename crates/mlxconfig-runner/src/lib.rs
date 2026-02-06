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

// src/lib.rs
// Library for the mlxconfig-runner crate.
pub mod command_builder;
pub mod error;
pub mod exec_options;
pub mod executor;
pub mod json_parser;
pub mod result_types;
pub mod runner;
pub mod traits;

// Re-export main types for convenience
pub use error::MlxRunnerError;
pub use exec_options::ExecOptions;
// Re-export from dependencies for convenience
pub use mlxconfig_variables::{MlxConfigValue, MlxConfigVariable, MlxVariableRegistry};
pub use result_types::*;
pub use runner::MlxConfigRunner;
pub use traits::{MlxConfigQueryable, MlxConfigSettable};
