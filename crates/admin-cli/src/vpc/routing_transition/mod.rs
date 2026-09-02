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

use carbide_uuid::vpc::VpcId;
use carbide_uuid::vpc_routing_profile_transition::VpcRoutingProfileTransitionId;
use clap::Parser;
use prettytable::{Table, row};
use rpc::admin_cli::OutputFormat;
use rpc::forge::{
    BeginVpcRoutingProfileTransitionRequest, FinalizeVpcRoutingProfileTransitionRequest,
    RecutoverVpcRoutingProfileTransitionRequest, RollbackVpcRoutingProfileTransitionRequest,
    VpcRoutingProfileTransition, VpcRoutingProfileTransitionList,
    VpcRoutingProfileTransitionResult, VpcRoutingProfileTransitionSearchFilter,
    VpcRoutingProfileTransitionState,
};

use crate::cfg::dispatch::Dispatch;
use crate::cfg::run::Run;
use crate::cfg::runtime::RuntimeContext;
use crate::errors::{CarbideCliError, CarbideCliResult};
use crate::rpc::ApiClient;

#[derive(Parser, Debug, Dispatch)]
#[command(after_long_help = "\
EXAMPLES:

Begin an INTERNAL to EXTERNAL cutover with an automatically allocated VNI:
    $ nico-admin-cli --cloud-unsafe-op=my_username vpc routing-transition begin \
        12345678-1234-5678-90ab-cdef01234567 EXTERNAL --reason 'approved migration'

Begin with an exact target VNI:
    $ nico-admin-cli --cloud-unsafe-op=my_username vpc routing-transition begin \
        12345678-1234-5678-90ab-cdef01234567 EXTERNAL --vni 51000 \
        --reason 'approved migration'

Inspect active transitions:
    $ nico-admin-cli vpc routing-transition show --active-only

After external convergence has been verified, release the old VNI:
    $ nico-admin-cli --cloud-unsafe-op=my_username vpc routing-transition finalize \
        87654321-4321-8765-ba09-123456789abc --confirm-converged

")]
pub(crate) enum Cmd {
    #[clap(about = "Reserve a target VNI and cut the VPC over while retaining rollback")]
    Begin(BeginArgs),
    #[clap(about = "Switch a pending cutover back to its retained source endpoint")]
    Rollback(RollbackArgs),
    #[clap(about = "Switch a rolled-back transition to its retained target again")]
    Recutover(RecutoverArgs),
    #[clap(about = "Release the inactive VNI after out-of-band convergence confirmation")]
    Finalize(FinalizeArgs),
    #[clap(about = "Show routing-profile transition state and history")]
    Show(ShowArgs),
}

#[derive(Parser, Debug)]
#[command(after_long_help = "\
EXAMPLES:

Begin a cutover with an automatically allocated target VNI:
    $ nico-admin-cli --cloud-unsafe-op=my_username vpc routing-transition begin 12345678-1234-5678-90ab-cdef01234567 EXTERNAL --reason 'approved migration'

Begin with an exact target VNI:
    $ nico-admin-cli --cloud-unsafe-op=my_username vpc routing-transition begin 12345678-1234-5678-90ab-cdef01234567 EXTERNAL --vni 51000 --reason 'approved migration'

Adopt a target lease already owned by the VPC during manual-state recovery:
    $ nico-admin-cli --cloud-unsafe-op=my_username vpc routing-transition begin 12345678-1234-5678-90ab-cdef01234567 EXTERNAL --vni 51000 --adopt-existing-target-allocation --reason 'recover prepared lease'

")]
pub(crate) struct BeginArgs {
    #[clap(help = "VPC to transition")]
    vpc_id: VpcId,
    #[clap(help = "Target named routing profile")]
    target_routing_profile_type: String,
    #[clap(long, help = "Exact target VNI; omit for automatic allocation")]
    vni: Option<u32>,
    #[clap(
        long,
        help = "Client operation ID; omit to generate a new idempotency key"
    )]
    id: Option<VpcRoutingProfileTransitionId>,
    #[clap(
        long,
        help = "Expected VPC version; omit to read the current version immediately before begin"
    )]
    if_vpc_version_match: Option<String>,
    #[clap(long, help = "Operator change reason (required for the audit record)")]
    reason: String,
    #[clap(
        long,
        requires = "vni",
        help = "Adopt the exact --vni already allocated to this VPC (requires --vni)"
    )]
    adopt_existing_target_allocation: bool,
}

#[derive(Parser, Debug)]
#[command(after_long_help = "\
EXAMPLES:

Return a pending cutover to its retained source profile and VNI:
    $ nico-admin-cli --cloud-unsafe-op=my_username vpc routing-transition rollback abcdef01-2345-6789-abcd-ef0123456789

")]
pub(crate) struct RollbackArgs {
    #[clap(help = "Transition operation ID")]
    id: VpcRoutingProfileTransitionId,
    #[clap(
        long,
        help = "Expected transition version; omit to read the current version immediately before the action"
    )]
    if_version_match: Option<String>,
}

#[derive(Parser, Debug)]
#[command(after_long_help = "\
EXAMPLES:

Cut a rolled-back transition over to its retained target again:
    $ nico-admin-cli --cloud-unsafe-op=my_username vpc routing-transition recutover abcdef01-2345-6789-abcd-ef0123456789

")]
pub(crate) struct RecutoverArgs {
    #[clap(help = "Transition operation ID")]
    id: VpcRoutingProfileTransitionId,
    #[clap(
        long,
        help = "Expected transition version; omit to read the current version immediately before the action"
    )]
    if_version_match: Option<String>,
}

#[derive(Parser, Debug)]
#[command(after_long_help = "\
EXAMPLES:

Release the inactive VNI after every affected DPU has converged:
    $ nico-admin-cli --cloud-unsafe-op=my_username vpc routing-transition finalize abcdef01-2345-6789-abcd-ef0123456789 --confirm-converged

")]
pub(crate) struct FinalizeArgs {
    #[clap(help = "Transition operation ID")]
    id: VpcRoutingProfileTransitionId,
    #[clap(
        long,
        help = "Expected transition version; omit to read the current version immediately before finalization"
    )]
    if_version_match: Option<String>,
    #[clap(
        long,
        required = true,
        help = "Assert that every affected DPU has converged to the currently active endpoint"
    )]
    confirm_converged: bool,
}

#[derive(Parser, Debug)]
#[command(after_long_help = "\
EXAMPLES:

List all retained transition history:
    $ nico-admin-cli vpc routing-transition show

Show one transition by operation ID:
    $ nico-admin-cli vpc routing-transition show abcdef01-2345-6789-abcd-ef0123456789

Show transition history for one VPC:
    $ nico-admin-cli vpc routing-transition show --vpc-id 12345678-1234-5678-90ab-cdef01234567

Show only transitions that still retain both VNI leases:
    $ nico-admin-cli vpc routing-transition show --active-only

")]
pub(crate) struct ShowArgs {
    #[clap(help = "Optional transition operation ID")]
    id: Option<VpcRoutingProfileTransitionId>,
    #[clap(long, help = "Filter transition history by VPC ID")]
    vpc_id: Option<VpcId>,
    #[clap(long, help = "Show only transitions retaining both VNI leases")]
    active_only: bool,
}

async fn current_vpc_version(api_client: &ApiClient, vpc_id: VpcId) -> CarbideCliResult<String> {
    let mut response = api_client.0.find_vpcs_by_ids(vec![vpc_id]).await?;
    if response.vpcs.len() != 1 {
        return Err(CarbideCliError::GenericError(format!(
            "VPC `{vpc_id}` was not found"
        )));
    }
    Ok(response.vpcs.remove(0).version)
}

async fn current_transition_version(
    api_client: &ApiClient,
    id: VpcRoutingProfileTransitionId,
) -> CarbideCliResult<String> {
    let response = api_client
        .0
        .find_vpc_routing_profile_transitions(VpcRoutingProfileTransitionSearchFilter {
            id: Some(id),
            vpc_id: None,
            active_only: None,
        })
        .await?;
    let mut transitions = response.transitions;
    if transitions.len() != 1 {
        return Err(CarbideCliError::GenericError(format!(
            "VPC routing-profile transition `{id}` was not found"
        )));
    }
    Ok(transitions.remove(0).version)
}

fn state_name(value: i32) -> &'static str {
    VpcRoutingProfileTransitionState::try_from(value)
        .unwrap_or(VpcRoutingProfileTransitionState::Unspecified)
        .as_str_name()
}

fn timestamp(value: Option<rpc::Timestamp>) -> String {
    value
        .map(|timestamp| format!("{}.{:09}Z", timestamp.seconds, timestamp.nanos))
        .unwrap_or_default()
}

fn transition_table(transitions: &[VpcRoutingProfileTransition]) -> Table {
    let mut table = Table::new();
    table.set_titles(row![
        "ID",
        "VPC ID",
        "STATE",
        "SOURCE PROFILE",
        "SOURCE VNI",
        "TARGET PROFILE",
        "TARGET VNI",
        "VERSION",
        "COMPLETED"
    ]);
    for transition in transitions {
        table.add_row(row![
            transition.id.unwrap_or_default(),
            transition.vpc_id.unwrap_or_default(),
            state_name(transition.state),
            transition.source_routing_profile_type,
            transition.source_vni,
            transition.target_routing_profile_type,
            transition.target_vni,
            transition.version,
            timestamp(transition.completed)
        ]);
    }
    table
}

fn write_transition_csv(
    transitions: &[VpcRoutingProfileTransition],
    output: impl std::io::Write,
) -> CarbideCliResult<()> {
    let mut writer = csv::Writer::from_writer(output);
    writer.write_record([
        "id",
        "vpc_id",
        "state",
        "source_profile",
        "source_pool",
        "source_vni",
        "target_profile",
        "target_pool",
        "target_vni",
        "version",
        "completed",
    ])?;
    for transition in transitions {
        writer.write_record([
            transition.id.unwrap_or_default().to_string(),
            transition.vpc_id.unwrap_or_default().to_string(),
            state_name(transition.state).to_string(),
            transition.source_routing_profile_type.clone(),
            transition.source_vni_pool.clone(),
            transition.source_vni.to_string(),
            transition.target_routing_profile_type.clone(),
            transition.target_vni_pool.clone(),
            transition.target_vni.to_string(),
            transition.version.clone(),
            timestamp(transition.completed),
        ])?;
    }
    writer.flush()?;
    Ok(())
}

fn print_transitions(
    transitions: &[VpcRoutingProfileTransition],
    output_format: OutputFormat,
) -> CarbideCliResult<()> {
    match output_format {
        OutputFormat::AsciiTable => transition_table(transitions).printstd(),
        OutputFormat::Csv => write_transition_csv(transitions, std::io::stdout())?,
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(transitions)?);
        }
        OutputFormat::Yaml => {
            println!("{}", serde_yaml::to_string(transitions)?);
        }
    };
    Ok(())
}

fn print_result(
    result: &VpcRoutingProfileTransitionResult,
    output_format: OutputFormat,
) -> CarbideCliResult<()> {
    match output_format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(result)?),
        OutputFormat::Yaml => println!("{}", serde_yaml::to_string(result)?),
        _ => {
            let transition = result.transition.as_ref().ok_or_else(|| {
                CarbideCliError::GenericError("API response omitted transition".to_string())
            })?;
            print_transitions(std::slice::from_ref(transition), output_format)?;
            if output_format == OutputFormat::AsciiTable
                && let Some(vpc) = result.vpc.as_ref()
            {
                println!("VPC version: {}", vpc.version);
            }
        }
    }
    Ok(())
}

impl Run for BeginArgs {
    async fn run(self, ctx: &mut RuntimeContext) -> CarbideCliResult<()> {
        ctx.assert_cloud_unsafe_op_message()?;
        let version = match self.if_vpc_version_match {
            Some(version) => version,
            None => current_vpc_version(&ctx.api_client, self.vpc_id).await?,
        };
        // `Default` for typed UUIDs is nil; omitted operation IDs must instead
        // get a fresh idempotency key.
        let operation_id = match self.id {
            Some(id) => id,
            None => VpcRoutingProfileTransitionId::new(),
        };
        eprintln!("Transition operation ID: {operation_id}");
        let result = ctx
            .api_client
            .0
            .begin_vpc_routing_profile_transition(BeginVpcRoutingProfileTransitionRequest {
                id: Some(operation_id),
                vpc_id: Some(self.vpc_id),
                if_vpc_version_match: version,
                target_routing_profile_type: self.target_routing_profile_type,
                target_vni: self.vni,
                target_routing_profile_overrides: None,
                reason: self.reason,
                adopt_existing_target_allocation: self.adopt_existing_target_allocation,
            })
            .await?;
        print_result(&result, ctx.config.format)
    }
}

impl Run for RollbackArgs {
    async fn run(self, ctx: &mut RuntimeContext) -> CarbideCliResult<()> {
        ctx.assert_cloud_unsafe_op_message()?;
        let version = match self.if_version_match {
            Some(version) => version,
            None => current_transition_version(&ctx.api_client, self.id).await?,
        };
        let result = ctx
            .api_client
            .0
            .rollback_vpc_routing_profile_transition(RollbackVpcRoutingProfileTransitionRequest {
                id: Some(self.id),
                if_version_match: version,
            })
            .await?;
        print_result(&result, ctx.config.format)
    }
}

impl Run for RecutoverArgs {
    async fn run(self, ctx: &mut RuntimeContext) -> CarbideCliResult<()> {
        ctx.assert_cloud_unsafe_op_message()?;
        let version = match self.if_version_match {
            Some(version) => version,
            None => current_transition_version(&ctx.api_client, self.id).await?,
        };
        let result = ctx
            .api_client
            .0
            .recutover_vpc_routing_profile_transition(RecutoverVpcRoutingProfileTransitionRequest {
                id: Some(self.id),
                if_version_match: version,
            })
            .await?;
        print_result(&result, ctx.config.format)
    }
}

impl Run for FinalizeArgs {
    async fn run(self, ctx: &mut RuntimeContext) -> CarbideCliResult<()> {
        ctx.assert_cloud_unsafe_op_message()?;
        let version = match self.if_version_match {
            Some(version) => version,
            None => current_transition_version(&ctx.api_client, self.id).await?,
        };
        let result = ctx
            .api_client
            .0
            .finalize_vpc_routing_profile_transition(FinalizeVpcRoutingProfileTransitionRequest {
                id: Some(self.id),
                if_version_match: version,
                convergence_confirmed: self.confirm_converged,
            })
            .await?;
        print_result(&result, ctx.config.format)
    }
}

impl Run for ShowArgs {
    async fn run(self, ctx: &mut RuntimeContext) -> CarbideCliResult<()> {
        let list: VpcRoutingProfileTransitionList = ctx
            .api_client
            .0
            .find_vpc_routing_profile_transitions(VpcRoutingProfileTransitionSearchFilter {
                id: self.id,
                vpc_id: self.vpc_id,
                active_only: self.active_only.then_some(true),
            })
            .await?;
        print_transitions(&list.transitions, ctx.config.format)
    }
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;
    use crate::cfg::cli_options::{CliCommand, CliOptions};

    const VPC_ID: &str = "12345678-1234-5678-90ab-cdef01234567";
    const TRANSITION_ID: &str = "abcdef01-2345-6789-abcd-ef0123456789";

    fn transition() -> VpcRoutingProfileTransition {
        VpcRoutingProfileTransition {
            id: Some(TRANSITION_ID.parse().unwrap()),
            vpc_id: Some(VPC_ID.parse().unwrap()),
            version: "1".to_string(),
            state: VpcRoutingProfileTransitionState::CutoverPendingFinalize as i32,
            source_routing_profile_type: "INTERNAL".to_string(),
            source_vni_pool: "vpc-vni".to_string(),
            source_vni: 60_001,
            target_routing_profile_type: "EXTERNAL".to_string(),
            target_vni_pool: "external-vpc-vni".to_string(),
            target_vni: 51_000,
            completed: None,
            ..Default::default()
        }
    }

    #[test]
    fn public_begin_command_routes_all_transition_inputs() {
        let parsed = CliOptions::try_parse_from([
            "nico-admin-cli",
            "--cloud-unsafe-op=my_username",
            "vpc",
            "routing-transition",
            "begin",
            VPC_ID,
            "EXTERNAL",
            "--vni",
            "51000",
            "--id",
            TRANSITION_ID,
            "--if-vpc-version-match",
            "7",
            "--reason",
            "approved migration",
            "--adopt-existing-target-allocation",
        ])
        .expect("public begin command should parse");

        let Some(CliCommand::Vpc(super::super::Cmd::RoutingTransition(Cmd::Begin(args)))) =
            parsed.commands
        else {
            panic!("public command did not route to routing-transition begin");
        };
        assert_eq!(args.vpc_id, VPC_ID.parse::<VpcId>().unwrap());
        assert_eq!(args.target_routing_profile_type, "EXTERNAL");
        assert_eq!(args.vni, Some(51_000));
        assert_eq!(args.id, Some(TRANSITION_ID.parse().unwrap()));
        assert_eq!(args.if_vpc_version_match.as_deref(), Some("7"));
        assert_eq!(args.reason, "approved migration");
        assert!(args.adopt_existing_target_allocation);

        assert!(
            CliOptions::try_parse_from([
                "nico-admin-cli",
                "--cloud-unsafe-op=my_username",
                "vpc",
                "routing-transition",
                "begin",
                VPC_ID,
                "EXTERNAL",
                "--reason",
                "recover prepared lease",
                "--adopt-existing-target-allocation",
            ])
            .is_err(),
            "adoption without an exact --vni must be rejected by the public CLI"
        );
    }

    #[test]
    fn every_leaf_long_help_contains_a_real_command_example() {
        let command = Cmd::command();
        for leaf in ["begin", "rollback", "recutover", "finalize", "show"] {
            let mut leaf_command = command
                .find_subcommand(leaf)
                .unwrap_or_else(|| panic!("missing {leaf} command"))
                .clone();
            let help = leaf_command.render_long_help().to_string();
            assert!(
                help.contains("EXAMPLES:"),
                "missing examples in {leaf} help"
            );
            assert!(
                help.contains(&format!("vpc routing-transition {leaf}")),
                "example uses the wrong command path in {leaf} help: {help}"
            );
        }
    }

    #[test]
    fn public_transition_outputs_include_headers_values_and_empty_completed_cell() {
        let transition = transition();
        let mut ascii = Vec::new();
        transition_table(std::slice::from_ref(&transition))
            .print(&mut ascii)
            .expect("render ASCII transition output");
        let ascii = String::from_utf8(ascii).unwrap();
        let mut lines = ascii.lines();
        let header_line = lines
            .find(|line| line.contains("SOURCE PROFILE"))
            .expect("ASCII header row");
        let headers = header_line
            .trim_matches('|')
            .split('|')
            .map(str::trim)
            .collect::<Vec<_>>();
        assert_eq!(
            headers,
            [
                "ID",
                "VPC ID",
                "STATE",
                "SOURCE PROFILE",
                "SOURCE VNI",
                "TARGET PROFILE",
                "TARGET VNI",
                "VERSION",
                "COMPLETED",
            ]
        );
        let value_line = ascii
            .lines()
            .find(|line| line.contains(TRANSITION_ID))
            .expect("ASCII value row");
        let values = value_line
            .trim_matches('|')
            .split('|')
            .map(str::trim)
            .collect::<Vec<_>>();
        assert_eq!(values[1], VPC_ID);
        assert_eq!(
            values[2],
            "VPC_ROUTING_PROFILE_TRANSITION_STATE_CUTOVER_PENDING_FINALIZE"
        );
        assert_eq!(values[3], "INTERNAL");
        assert_eq!(values[4], "60001");
        assert_eq!(values[5], "EXTERNAL");
        assert_eq!(values[6], "51000");
        assert_eq!(values[8], "");

        let mut csv = Vec::new();
        write_transition_csv(&[transition], &mut csv).expect("render CSV transition output");
        let mut csv = csv::Reader::from_reader(csv.as_slice());
        assert_eq!(
            csv.headers().unwrap().iter().collect::<Vec<_>>(),
            vec![
                "id",
                "vpc_id",
                "state",
                "source_profile",
                "source_pool",
                "source_vni",
                "target_profile",
                "target_pool",
                "target_vni",
                "version",
                "completed",
            ]
        );
        let values = csv.records().next().unwrap().unwrap();
        assert_eq!(&values[0], TRANSITION_ID);
        assert_eq!(&values[4], "vpc-vni");
        assert_eq!(&values[7], "external-vpc-vni");
        assert_eq!(&values[10], "");
    }
}
