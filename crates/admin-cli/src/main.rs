/*
 * SPDX-FileCopyrightText: Copyright (c) 2022-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

// CLI enums variants can be rather large, we are ok with that.
#![allow(clippy::large_enum_variant)]
use std::pin::Pin;

use ::rpc::admin_cli::CarbideCliError;
use ::rpc::forge_api_client::ForgeApiClient;
use ::rpc::forge_tls_client::{ApiConfig, ForgeClientConfig};
use ::rpc::protos::rack_manager_client::RackManagerApiClient;
use cfg::cli_options::{CliCommand, CliOptions};
use clap::CommandFactory;
use forge_tls::client_config::{
    get_carbide_api_url, get_client_cert_info, get_config_from_file, get_forge_root_ca_path,
    get_proxy_info,
};
use forge_tls::rms_client_config::{get_rms_api_url, rms_client_cert_info, rms_root_ca_path};
use tracing_subscriber::filter::{EnvFilter, LevelFilter};
use tracing_subscriber::fmt;
use tracing_subscriber::prelude::*;

use crate::cfg::dispatch::Dispatch;
use crate::cfg::runtime::{RuntimeConfig, RuntimeContext};
use crate::rpc::{ApiClient, RmsApiClient};

mod async_write;
mod bmc_machine;
mod boot_override;
mod cfg;
mod credential;
mod debug_bundle;
mod devenv;
mod domain;
mod dpa;
mod dpf;
mod dpu;
mod dpu_remediation;
mod expected_machines;
mod expected_power_shelf;
mod expected_switch;
mod extension_service;
mod firmware;
mod generate_shell_complete;
mod host;
mod ib_partition;
mod instance;
mod instance_type;
mod inventory;
mod ip;
mod jump;
mod machine;
mod machine_interfaces;
mod machine_validation;
mod managed_host;
mod measurement;
mod metadata;
mod mlx;
mod network_devices;
mod network_security_group;
mod network_segment;
mod nvl_logical_partition;
mod nvl_partition;
mod os_image;
mod ping;
mod power_shelf;
mod rack;
mod rack_firmware;
mod redfish;
mod resource_pool;
mod rms;
mod route_server;
mod rpc;
mod scout_stream;
mod set;
mod site_explorer;
mod sku;
mod ssh;
mod switch;
mod tenant;
mod tenant_keyset;
mod tpm_ca;
mod trim_table;
mod version;
mod vpc;
mod vpc_peering;
mod vpc_prefix;

pub fn default_uuid() -> ::rpc::common::Uuid {
    ::rpc::common::Uuid {
        value: "00000000-0000-0000-0000-000000000000".to_string(),
    }
}

pub fn invalid_machine_id() -> String {
    "INVALID_MACHINE".to_string()
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;

    let config = CliOptions::load();
    if config.version {
        println!("{}", carbide_version::version!());
        return Ok(());
    }
    let file_config = get_config_from_file();

    // Log level is set from, in order of preference:
    // 1. `--debug N` on cmd line
    // 2. RUST_LOG environment variable
    // 3. Level::Info
    let mut env_filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy()
        .add_directive("tower=warn".parse()?)
        .add_directive("rustls=warn".parse()?)
        .add_directive("hyper=info".parse()?)
        .add_directive("h2=warn".parse()?);
    if config.debug != 0 {
        env_filter = env_filter.add_directive(
            match config.debug {
                1 => LevelFilter::DEBUG,
                _ => LevelFilter::TRACE,
            }
            .into(),
        );
    }
    tracing_subscriber::registry()
        .with(fmt::Layer::default().compact().with_writer(std::io::stderr))
        .with(env_filter)
        .try_init()?;

    if let Some(CliCommand::Redfish(ref ra)) = config.commands {
        match ra.command {
            redfish::Cmd::Browse(_) => {}
            _ => {
                return redfish::action(ra.clone()).await;
            }
        }
    }

    let url = get_carbide_api_url(config.carbide_api, file_config.as_ref());
    let forge_root_ca_path =
        get_forge_root_ca_path(config.forge_root_ca_path, file_config.as_ref());

    // RMS client configuration with optional CLI overrides
    let rms_url = get_rms_api_url(config.rms_api_url);
    let rms_root_ca = rms_root_ca_path(config.rms_root_ca_path.clone(), file_config.as_ref());
    let rms_client_cert = rms_client_cert_info(
        config.rms_client_cert_path.clone(),
        config.rms_client_key_path.clone(),
    );
    let rms_client_config = ForgeClientConfig::new(rms_root_ca, rms_client_cert);
    let rms_api_config = ApiConfig::new(&rms_url, &rms_client_config);
    let rms_client = RmsApiClient(RackManagerApiClient::new(&rms_api_config));

    let command = match config.commands {
        None => {
            return Ok(CliOptions::command().print_long_help()?);
        }
        Some(s) => s,
    };

    let forge_client_cert = if matches!(command, CliCommand::Version(_)) {
        None
    } else {
        Some(get_client_cert_info(
            config.client_cert_path,
            config.client_key_path,
            file_config.as_ref(),
        ))
    };

    let proxy = get_proxy_info()?;

    let mut client_config = ForgeClientConfig::new(forge_root_ca_path, forge_client_cert);
    client_config.socks_proxy(proxy);

    let ctx = RuntimeContext {
        api_client: ApiClient(ForgeApiClient::new(&ApiConfig::new(&url, &client_config))),
        config: RuntimeConfig {
            format: config.format,
            page_size: config.internal_page_size,
            extended: config.extended,
            cloud_unsafe_op_enabled: config.cloud_unsafe_op.is_some(),
            sort_by: config.sort_by,
        },
        output_file: get_output_file_or_stdout(config.output.as_deref()).await?,
        rms_client,
    };

    // Command to talk to Carbide API.
    match command {
        CliCommand::BmcMachine(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::BootOverride(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::Credential(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::DevEnv(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::Domain(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::Dpa(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::Dpu(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::DpuRemediation(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::ExpectedMachine(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::ExpectedPowerShelf(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::ExpectedSwitch(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::ExtensionService(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::Firmware(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::GenerateShellComplete(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::Host(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::IbPartition(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::Instance(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::InstanceType(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::Inventory(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::Ip(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::Jump(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::LogicalPartition(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::Machine(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::MachineInterfaces(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::MachineValidation(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::ManagedHost(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::Measurement(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::Mlx(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::NetworkDevice(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::NetworkSecurityGroup(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::NetworkSegment(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::NvlPartition(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::OsImage(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::Ping(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::PowerShelf(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::Rack(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::ResourcePool(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::Rms(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::RouteServer(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::ScoutStream(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::Set(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::Ssh(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::SiteExplorer(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::Sku(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::Switch(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::Tenant(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::TenantKeySet(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::TpmCa(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::TrimTable(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::Version(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::Vpc(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::VpcPeering(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::VpcPrefix(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::RackFirmware(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::Dpf(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::Redfish(action) => {
            if let redfish::Cmd::Browse(redfish::UriInfo { uri }) = &action.command {
                return redfish::handle_browse_command(&ctx.api_client, uri).await;
            }

            // Handled earlier
            unreachable!();
        }
    }

    Ok(())
}

pub async fn get_output_file_or_stdout(
    output_filename: Option<&str>,
) -> Result<Pin<Box<dyn tokio::io::AsyncWrite>>, CarbideCliError> {
    if let Some(filename) = output_filename {
        let file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(filename)
            .await?;
        Ok(Box::pin(file))
    } else {
        Ok(Box::pin(tokio::io::stdout()))
    }
}

pub(crate) trait IntoOnlyOne<T> {
    fn into_only_one_or_else<E, F: FnOnce(usize) -> E>(self, f: F) -> Result<T, E>;
}

impl<T> IntoOnlyOne<T> for Vec<T> {
    fn into_only_one_or_else<E, F: FnOnce(usize) -> E>(self, f: F) -> Result<T, E> {
        if self.len() != 1 {
            return Err(f(self.len()));
        }
        let Some(first) = self.into_iter().next() else {
            return Err(f(0));
        };
        Ok(first)
    }
}
