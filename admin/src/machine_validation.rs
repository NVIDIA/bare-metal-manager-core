/*
 * SPDX-FileCopyrightText: Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use super::{rpc, CarbideCliResult};
use ::rpc::forge_tls_client::ApiConfig;

pub async fn external_config_show(
    api_config: &ApiConfig<'_>,
    config_name: String,
) -> CarbideCliResult<()> {
    let response = rpc::get_machine_validation_external_config(config_name, api_config).await?;

    println!("---------------------------");
    if response.config.is_some() {
        // println!("{:?}", response.config.unwrap_or_default());
        let s = String::from_utf8(response.config.unwrap_or_default().config)
            .expect("Found invalid UTF-8");

        println!("{}", s);
    }
    println!("---------------------------");
    Ok(())
}
pub async fn external_config_add_update(
    api_config: &ApiConfig<'_>,
    config_name: String,
    file_name: String,
    description: String,
) -> CarbideCliResult<()> {
    // Read the file data from disk
    let file_data = std::fs::read(&file_name)?;
    rpc::add_update_machine_validation_external_config(
        config_name,
        description,
        file_data,
        api_config,
    )
    .await?;
    Ok(())
}
