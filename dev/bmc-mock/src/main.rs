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
mod command_line;

use tracing::info;
use tracing_subscriber::filter::{EnvFilter, LevelFilter};
use tracing_subscriber::fmt::Layer;
use tracing_subscriber::prelude::*;

///
/// bmc-mock behaves like a Redfish BMC server
/// Run: 'cargo run'
/// Try it:
///  - start docker-compose things
///  - `cargo make bootstrap-forge-docker`
///  - `grpcurl -d '{"machine_id": {"value": "71363261-a95a-4964-9eb1-8dd98b870746"}}' -insecure
///  127.0.0.1:1079 forge.Forge/CleanupMachineCompleted`
///  where that UUID is a host machine in DB.
#[tokio::main]
async fn main() {
    let env_filter = EnvFilter::from_default_env()
        .add_directive(LevelFilter::DEBUG.into())
        .add_directive("tower=warn".parse().unwrap())
        .add_directive("rustls=warn".parse().unwrap())
        .add_directive("hyper=warn".parse().unwrap())
        .add_directive("h2=warn".parse().unwrap());

    tracing_subscriber::registry()
        .with(Layer::default().compact())
        .with(env_filter)
        .init();

    let args = command_line::parse_args();
    info!("Using qemu: {}", args.use_qemu);
    info!("Using cert_path: {:?}", args.cert_path);
    bmc_mock::run(bmc_mock::BmcState {
        use_qemu: args.use_qemu,
        cert_path: args.cert_path,
    })
    .await;
}
