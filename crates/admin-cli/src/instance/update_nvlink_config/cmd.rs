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

use ::rpc::admin_cli::{CarbideCliError, CarbideCliResult};

use super::args::Args;
use crate::instance::common::GlobalOptions;
use crate::rpc::ApiClient;

pub async fn update_nvlink_config(
    api_client: &ApiClient,
    update_request: Args,
    opts: &GlobalOptions<'_>,
) -> CarbideCliResult<()> {
    if opts.cloud_unsafe_op.is_none() {
        return Err(CarbideCliError::GenericError(
            "Operation not allowed due to potential inconsistencies with cloud database."
                .to_owned(),
        ));
    }

    match api_client
        .update_instance_config_with(
            update_request.instance,
            |config| {
                config.nvlink = Some(update_request.config.clone());
            },
            |_metadata| {},
            opts.cloud_unsafe_op.clone(),
        )
        .await
    {
        Ok(i) => {
            tracing::info!(
                "update-nvlink-config was successful. Updated instance: {:?}",
                i
            );
        }
        Err(e) => {
            tracing::info!("update-nvlink-config failed with {} ", e);
        }
    };
    Ok(())
}
