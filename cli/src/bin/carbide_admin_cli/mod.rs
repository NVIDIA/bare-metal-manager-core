/*
 * SPDX-FileCopyrightText: Copyright (c) 2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
pub mod cfg;
pub mod machine;
mod rpc;

use ::rpc::forge as forgerpc;

#[derive(thiserror::Error, Debug)]
pub enum CarbideCliError {
    #[error("Unable to connect to carbide API: {0}")]
    CarbideApiConnectFailed(String),

    #[error("Error while writing into string: {0}")]
    CarbideCliStringWriteError(#[from] std::fmt::Error),
}

pub type CarbideCliResult<T> = Result<T, CarbideCliError>;

pub fn default_uuid() -> forgerpc::Uuid {
    forgerpc::Uuid {
        value: "00000000-0000-0000-0000-000000000000".to_string(),
    }
}
