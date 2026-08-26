/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

use ::rpc::forge::{
    self as forgerpc, MachineValidationTestEnableDisableTestRequest,
    MachineValidationTestFullHostApprovalRequest, MachineValidationTestVerfiedRequest,
};
use clap::Parser;

use crate::cfg::run::Run;
use crate::cfg::runtime::RuntimeContext;
use crate::errors::CarbideCliResult;

#[derive(Parser, Debug)]
pub(crate) enum Args {
    #[clap(about = "Create an OCI Machine Validation plugin")]
    Create(CreateArgs),
    #[command(
        about = "Verify a plugin revision",
        after_long_help = "\
EXAMPLES:

Verify a plugin revision:
    $ nico-admin-cli machine-validation plugins verify --test-id forge_gpu_health --version 1.0.0

"
    )]
    Verify(RevisionArgs),
    #[command(
        about = "Approve full host access for a verified plugin revision",
        after_long_help = "\
EXAMPLES:

Approve full host access for a verified plugin revision:
    $ nico-admin-cli machine-validation plugins approve-full-host --test-id forge_gpu_health --version 1.0.0

"
    )]
    ApproveFullHost(RevisionArgs),
    #[command(
        about = "Enable a plugin revision",
        after_long_help = "\
EXAMPLES:

Enable a verified plugin revision:
    $ nico-admin-cli machine-validation plugins enable --test-id forge_gpu_health --version 1.0.0

"
    )]
    Enable(RevisionArgs),
    #[command(
        about = "Disable a plugin revision",
        after_long_help = "\
EXAMPLES:

Disable a plugin revision:
    $ nico-admin-cli machine-validation plugins disable --test-id forge_gpu_health --version 1.0.0

"
    )]
    Disable(RevisionArgs),
}

#[derive(Parser, Debug)]
#[command(
    after_long_help = "EXAMPLES:\n    Create an unprivileged GPU health plugin:\n\n        $ nico-admin-cli machine-validation plugins create --name gpu-health --image registry.example.com/plugins/gpu-health@sha256:REPLACE_WITH_DIGEST --entrypoint /plugin/entrypoint --context Discovery --platform HGX-B200 --parameters '{\"expectedGpuCount\":8}'\n\n    Create a privileged plugin with writable host access:\n\n        $ nico-admin-cli machine-validation plugins create --name host-gpu-health --image registry.example.com/plugins/host-gpu-health@sha256:REPLACE_WITH_DIGEST --entrypoint /plugin/entrypoint --context Discovery --platform HGX-B200 --parameters '{\"expectedGpuCount\":8}' --privileged --host-access-full"
)]
pub(crate) struct CreateArgs {
    #[clap(long)]
    name: String,
    #[clap(long)]
    image: String,
    #[clap(long, required = true)]
    entrypoint: Vec<String>,
    #[clap(long, default_value = "{}")]
    parameters: String,
    #[clap(long, default_value = "OnDemand")]
    context: Vec<String>,
    #[clap(long)]
    platform: Vec<String>,
    #[clap(long, default_value_t = 7200)]
    timeout: i64,
    #[clap(long)]
    privileged: bool,
    #[clap(long)]
    host_access_full: bool,
}

#[derive(Parser, Debug)]
pub(crate) struct RevisionArgs {
    #[clap(long)]
    test_id: String,
    #[clap(long)]
    version: String,
}

impl Run for Args {
    async fn run(self, ctx: &mut RuntimeContext) -> CarbideCliResult<()> {
        match self {
            Self::Create(args) => {
                let response = ctx
                    .api_client
                    .0
                    .add_machine_validation_test(forgerpc::MachineValidationTestAddRequest {
                        name: args.name,
                        description: None,
                        contexts: args.context,
                        img_name: None,
                        execute_in_host: None,
                        container_arg: None,
                        command: String::new(),
                        args: String::new(),
                        extra_err_file: None,
                        external_config_file: None,
                        pre_condition: None,
                        timeout: Some(args.timeout),
                        extra_output_file: None,
                        supported_platforms: args.platform,
                        read_only: None,
                        custom_tags: Vec::new(),
                        components: Vec::new(),
                        is_enabled: None,
                        plugin: Some(forgerpc::MachineValidationPlugin {
                            image: args.image,
                            entrypoint: args.entrypoint,
                            parameters_json: args.parameters,
                            privileged: args.privileged,
                            host_access_full: args.host_access_full,
                        }),
                    })
                    .await?;
                println!(
                    "Created plugin revision: {} {}",
                    response.test_id, response.version
                );
            }
            Self::Verify(args) => {
                let response = ctx
                    .api_client
                    .0
                    .machine_validation_test_verfied(MachineValidationTestVerfiedRequest {
                        test_id: args.test_id,
                        version: args.version,
                    })
                    .await?;
                println!("{}", response.message);
            }
            Self::ApproveFullHost(args) => {
                let response = ctx
                    .api_client
                    .0
                    .machine_validation_test_approve_full_host(
                        MachineValidationTestFullHostApprovalRequest {
                            test_id: args.test_id,
                            version: args.version,
                        },
                    )
                    .await?;
                println!("{}", response.message);
            }
            Self::Enable(args) => {
                let response = ctx
                    .api_client
                    .0
                    .machine_validation_test_enable_disable_test(
                        MachineValidationTestEnableDisableTestRequest {
                            test_id: args.test_id,
                            version: args.version,
                            is_enabled: true,
                        },
                    )
                    .await?;
                println!("{}", response.message);
            }
            Self::Disable(args) => {
                let response = ctx
                    .api_client
                    .0
                    .machine_validation_test_enable_disable_test(
                        MachineValidationTestEnableDisableTestRequest {
                            test_id: args.test_id,
                            version: args.version,
                            is_enabled: false,
                        },
                    )
                    .await?;
                println!("{}", response.message);
            }
        }
        Ok(())
    }
}
