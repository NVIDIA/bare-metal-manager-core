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

use std::pin::Pin;

use rpc::admin_cli::OutputFormat;

use crate::cfg::cli_options::SortField;
use crate::rpc::{ApiClient, RmsApiClient};

// RuntimeContext is context passed to all subcommand
// dispatch handlers. This is built at the beginning of
// runtime and then passed to the appropriate dispatcher.
pub struct RuntimeContext {
    pub api_client: ApiClient,
    pub config: RuntimeConfig,
    pub output_file: Pin<Box<dyn tokio::io::AsyncWrite>>,
    pub rms_client: RmsApiClient,
}

// RuntimeConfig contains runtime configuration parameters extracted
// from CLI options. This should contain the entirety of any options
// that need to be leveraged by any downstream command handler.
pub struct RuntimeConfig {
    pub format: OutputFormat,
    pub page_size: usize,
    pub extended: bool,
    pub cloud_unsafe_op_enabled: bool,
    pub sort_by: SortField,
}
