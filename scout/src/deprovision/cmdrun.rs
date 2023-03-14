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
use std::process::Command;

use scout::CarbideClientError;

pub fn run_prog(cmd: String) -> Result<String, CarbideClientError> {
    let mut cmdpar = cmd.split(' ');
    let mut command = Command::new(cmdpar.next().unwrap());
    for par in cmdpar {
        command.arg(par);
    }

    let output = command.output().map_err(|e| {
        CarbideClientError::SubprocessError(
            command.get_program().to_string_lossy().to_string(),
            command
                .get_args()
                .map(|arg| arg.to_string_lossy().to_string())
                .collect::<Vec<String>>(),
            format!("Failed to spawn process: {}", e),
        )
    })?;

    if !output.status.success() {
        return Err(CarbideClientError::subprocess_error(&command, &output));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}
