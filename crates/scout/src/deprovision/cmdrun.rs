/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use std::ffi::OsStr;

use scout::CarbideClientError;
use utils::cmd::TokioCmd;

pub async fn run_prog<I, S>(command: S, args: I) -> Result<String, CarbideClientError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let command = TokioCmd::new(command);
    command
        .args(args)
        .output()
        .await
        .map_err(CarbideClientError::from)
}
