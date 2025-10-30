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
#[derive(thiserror::Error, Debug)]
pub enum MachineValidationError {
    #[error("Machine Validation: {0}")]
    Generic(String),
    #[error("Unable to config read: {0}")]
    ConfigFileRead(String),
    #[error("Yaml parse error: {0}")]
    Parse(String),
    #[error("{0}: {1}")]
    File(String, String),
    #[error("Failed {0}: {1}")]
    ApiClient(String, String),
}
