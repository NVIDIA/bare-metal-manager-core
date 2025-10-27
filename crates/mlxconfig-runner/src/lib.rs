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
