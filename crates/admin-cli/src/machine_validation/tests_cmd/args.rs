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

#[derive(Parser, Debug)]
pub enum Args {
    #[clap(about = "Show tests")]
    Show(ShowTestOptions),
    #[clap(about = "Verify a given test")]
    Verify(VerifyTestOptions),
    #[clap(about = "Add new test case")]
    Add(AddTestOptions),
    #[clap(about = "Update existing test case")]
    Update(UpdateTestOptions),
    #[clap(about = "Enabled a test")]
    Enable(EnableDisableTestOptions),
    #[clap(about = "Disable a test")]
    Disable(EnableDisableTestOptions),
}

#[derive(Parser, Debug)]
pub struct ShowTestOptions {
    #[clap(short, long, help = "Unique identification of the test")]
    pub test_id: Option<String>,

    #[clap(short, long, help = "List of platforms")]
    pub platforms: Vec<String>,

    #[clap(short, long, help = "List of contexts/tags")]
    pub contexts: Vec<String>,

    #[clap(long, default_value = "false", help = "List unverfied tests also.")]
    pub show_un_verfied: bool,
}

#[derive(Parser, Debug)]
pub struct VerifyTestOptions {
    #[clap(short, long, help = "Unique identification of the test")]
    pub test_id: String,

    #[clap(short, long, help = "Version to be verify")]
    pub version: String,
}

#[derive(Parser, Debug)]
pub struct EnableDisableTestOptions {
    #[clap(short, long, help = "Unique identification of the test")]
    pub test_id: String,

    #[clap(short, long, help = "Version to be verify")]
    pub version: String,
}

#[derive(Parser, Debug)]
pub struct UpdateTestOptions {
    #[clap(long, help = "Unique identification of the test")]
    pub test_id: String,

    #[clap(long, help = "Version to be verify")]
    pub version: String,

    #[clap(long, help = "List of contexts")]
    pub contexts: Vec<String>,

    #[clap(long, help = "Container image name")]
    pub img_name: Option<String>,

    #[clap(long, help = "Run command using chroot in case of container")]
    pub execute_in_host: Option<bool>,

    #[clap(long, help = "Container args", allow_hyphen_values = true)]
    pub container_arg: Option<String>,

    #[clap(long, help = "Description")]
    pub description: Option<String>,

    #[clap(long, help = "Command ")]
    pub command: Option<String>,

    #[clap(long, help = "Command args", allow_hyphen_values = true)]
    pub args: Option<String>,

    #[clap(long, help = "Command output error file ")]
    pub extra_err_file: Option<String>,

    #[clap(long, help = "Command output file ")]
    pub extra_output_file: Option<String>,

    #[clap(long, help = "External file")]
    pub external_config_file: Option<String>,

    #[clap(long, help = "Pre condition")]
    pub pre_condition: Option<String>,

    #[clap(long, help = "Command Timeout")]
    pub timeout: Option<i64>,

    #[clap(long, help = "List of supported platforms")]
    pub supported_platforms: Vec<String>,

    #[clap(long, help = "List of custom tags")]
    pub custom_tags: Vec<String>,

    #[clap(long, help = "List of system components")]
    pub components: Vec<String>,

    #[clap(long, help = "Enable the test")]
    pub is_enabled: Option<bool>,
}

#[derive(Parser, Debug)]
pub struct AddTestOptions {
    #[clap(long, help = "Name of the test case")]
    pub name: String,

    #[clap(long, help = "Command of the test case")]
    pub command: String,

    #[clap(long, help = "Command args", allow_hyphen_values = true)]
    pub args: String,

    #[clap(long, help = "List of contexts")]
    pub contexts: Vec<String>,

    #[clap(long, help = "Container image name")]
    pub img_name: Option<String>,

    #[clap(long, help = "Run command using chroot in case of container")]
    pub execute_in_host: Option<bool>,

    #[clap(long, help = "Container args", allow_hyphen_values = true)]
    pub container_arg: Option<String>,

    #[clap(long, help = "Description")]
    pub description: Option<String>,

    #[clap(long, help = "Command output error file ")]
    pub extra_err_file: Option<String>,

    #[clap(long, help = "Command output file ")]
    pub extra_output_file: Option<String>,

    #[clap(long, help = "External file")]
    pub external_config_file: Option<String>,

    #[clap(long, help = "Pre condition")]
    pub pre_condition: Option<String>,

    #[clap(long, help = "Command Timeout")]
    pub timeout: Option<i64>,

    #[clap(long, help = "List of supported platforms")]
    pub supported_platforms: Vec<String>,

    #[clap(long, help = "List of custom tags")]
    pub custom_tags: Vec<String>,

    #[clap(long, help = "List of system components")]
    pub components: Vec<String>,

    #[clap(long, help = "Enable the test")]
    pub is_enabled: Option<bool>,

    #[clap(long, help = "Is read-only")]
    pub read_only: Option<bool>,
}
