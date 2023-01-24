/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

pub fn run_prog(cmd: String) -> Result<String, String> {
    let mut cmdpar = cmd.split(' ');
    let mut runcmd = Command::new(cmdpar.next().unwrap());
    for par in cmdpar {
        runcmd.arg(par);
    }
    let stdout = match runcmd.output() {
        Ok(output) => {
            if output.status.success() {
                output.stdout
            } else {
                return Err(format!(
                    "Bad exit code: CMD=\"{}\" ERROR=\"{}\"",
                    cmd, output.status
                ));
            }
        }
        Err(errmsg) => {
            return Err(format!("Cant run: CMD=\"{}\" ERROR=\"{}\"", cmd, errmsg));
        }
    };
    Ok(String::from_utf8_lossy(&stdout).to_string())
}
