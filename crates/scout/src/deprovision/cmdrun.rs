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
use scout::CarbideClientError;
use utils::cmd::Cmd;

pub fn run_prog(cmd: String) -> Result<String, CarbideClientError> {
    let mut cmdpar = cmd.split(' ');
    let command = Cmd::new(cmdpar.next().unwrap());
    command
        .args(cmdpar)
        .output()
        .map_err(CarbideClientError::from)
}
