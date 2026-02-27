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

use clap::Parser;

#[derive(Parser, Debug, Clone)]
pub struct Args {
    #[clap(
        short = 'i',
        long,
        help = "Optional, unique ID to use when creating the instance type"
    )]
    pub id: Option<String>,

    #[clap(short = 'n', long, help = "Name of the instance type")]
    pub name: Option<String>,

    #[clap(short = 'd', long, help = "Description of the instance type")]
    pub description: Option<String>,

    #[clap(
        short = 'l',
        long,
        help = "JSON map of simple key:value pairs to be applied as labels to the instance type"
    )]
    pub labels: Option<String>,

    #[clap(
        short = 'f',
        long,
        help = "Optional, JSON array containing a set of instance type capability filters"
    )]
    pub desired_capabilities: Option<String>,
}
