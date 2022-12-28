/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use std::fmt::Debug;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sqlx::{self, PgPool};
use sqlxmq::{job, CurrentJob, JobRegistry, OwnedHandle};
use uuid::Uuid;

use ::rpc::forge as rpc;
use ::rpc::forge::instance_power_request::Operation as rpcOperation;
use forge_credentials::{CredentialKey, CredentialProvider, Credentials};
use libredfish::manager::OemDellBootDevices;
use libredfish::system::SystemPowerControl;

use crate::bg::{CurrentState, Status, TaskState};
use crate::db::dpu_machine::DpuMachine;
use crate::db::instance::Instance;
use crate::db::ipmi::{BmcMetaDataGetRequest, UserRoles};
use crate::reachability::{wait_for_requested_state, PingReachabilityChecker, ReachabilityError};
use crate::{CarbideError, CarbideResult};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum IpmiTask {
    Status,
    PowerControl(SystemPowerControl),
    EnableLockdown,
    DisableLockdown,
    SetupSerialConsole,
    FirstBootDevice(OemDellBootDevices, bool),
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct IpmiCommand {
    pub host: String,
    pub machine_id: Uuid,
    pub user_role: UserRoles,
    pub action: Option<IpmiTask>,
}

async fn update_status(current_job: &CurrentJob, checkpoint: u32, msg: String, state: TaskState) {
    if let TaskState::Error(..) = &state {
        log::error!("Error status: {}, checkpoint: {}", msg, checkpoint);
    } else {
        log::info!("Current status: {}, checkpoint: {}", msg, checkpoint);
    }

    match Status::update(
        current_job.pool(),
        current_job.id(),
        CurrentState {
            checkpoint,
            msg,
            state,
        },
    )
    .await
    {
        Ok(_) => (),
        Err(x) => {
            log::error!("Status update failed. Error: {:?}", x)
        }
    }
}

// Clone shenanigans to make the damn sqlxmq framework happy with this.
// almost wholesale stolen from https://stackoverflow.com/questions/50017987/cant-clone-vecboxtrait-because-trait-cannot-be-made-into-an-object
pub trait IpmiCommandHandlerClone {
    fn clone_box(&self) -> Box<dyn IpmiCommandHandler>;
}

impl<T: 'static + IpmiCommandHandler + Clone> IpmiCommandHandlerClone for T {
    fn clone_box(&self) -> Box<dyn IpmiCommandHandler> {
        Box::new(self.clone())
    }
}

impl Clone for Box<dyn IpmiCommandHandler> {
    fn clone(&self) -> Box<dyn IpmiCommandHandler> {
        self.clone_box()
    }
}

#[async_trait]
pub trait IpmiCommandHandler: Send + Sync + 'static + Debug + IpmiCommandHandlerClone {
    async fn handle_ipmi_command(
        &self,
        cmd: IpmiCommand,
        credential_provider: Arc<dyn CredentialProvider>,
        pool: PgPool,
    ) -> CarbideResult<String>;
}

// This function will observe DPU state and take necessary actions.
// The idea this function is to wait until DPU goes down, then wait until it is reachable. Post
// this reboot host.
async fn observe_dpu_state_and_reboot_host(
    pool: sqlx::PgPool,
    cmd: &IpmiCommand,
) -> CarbideResult<()> {
    let mut txn = pool.begin().await.map_err(CarbideError::from)?;
    let dpu = DpuMachine::find_by_host_machine_id(&mut txn, &cmd.machine_id).await?;
    txn.commit().await?;

    // Wait until DPU goes down.
    match wait_for_requested_state(
        Duration::from_secs(300),
        PingReachabilityChecker::new(dpu.address().ip(), crate::reachability::State::Dead),
    )
    .await
    {
        Err(ReachabilityError::TokioTimeout) => {
            log::warn!(
                "Even after given duration (300 secs), DPU didn't reboot post Bios Lockdown."
            );
            return Ok(());
        }
        Err(x) => {
            return Err(CarbideError::from(x));
        }
        Ok(_) => {}
    };

    log::info!(
        "DPU with id {} attached to host {} went down.",
        dpu.machine_id(),
        cmd.machine_id
    );

    // Wait for DPU to come up.
    wait_for_requested_state(
        Duration::from_secs(600),
        PingReachabilityChecker::new(dpu.address().ip(), crate::reachability::State::Alive),
    )
    .await
    .map_err(CarbideError::from)?;

    log::info!(
        "DPU with id {} attached to host {} is up now.",
        dpu.machine_id(),
        cmd.machine_id
    );

    // Reboot host now. Raise it as separate task. It will give some breathing time to DPU.
    let machine_power_request = MachineBmcRequest::new(cmd.machine_id, Operation::Reset, true);
    let task_id = machine_power_request.invoke_bmc_command(pool).await?;
    log::info!("Spawned job to reboot host with id: {}", task_id);
    Ok(())
}

#[derive(Copy, Clone, Debug)]
pub struct RealIpmiCommandHandler {}

#[async_trait]
impl IpmiCommandHandler for RealIpmiCommandHandler {
    async fn handle_ipmi_command(
        &self,
        cmd: IpmiCommand,
        credential_provider: Arc<dyn CredentialProvider>,
        pool: PgPool,
    ) -> CarbideResult<String> {
        log::info!("IPMI command: {:?}", cmd);
        let credentials = credential_provider
            .get_credentials(CredentialKey::Bmc {
                machine_id: cmd.machine_id.to_string(),
                user_role: cmd.user_role.to_string(),
            })
            .await
            .map_err(|err| {
                CarbideError::GenericError(format!("Error getting credentials for BMC: {:?}", err))
            })?;

        let (username, password) = match credentials {
            Credentials::UsernamePassword { username, password } => (username, password),
        };

        let conf = libredfish::Config {
            user: Some(username),
            endpoint: cmd.host.clone(),
            password: Some(password),
            port: None,
            system: "".to_string(),
            manager: "".to_string(),
            vendor: libredfish::Vendor::Unknown,
        };

        let action = cmd.action.clone();

        let result = tokio::task::spawn_blocking(move || {
            let result: CarbideResult<String>;

            let mut redfish = libredfish::Redfish::new(conf);

            match redfish.get_system_id() {
                Ok(()) => {}
                Err(e) => {
                    return Err(CarbideError::GenericError(format!(
                        "Error getting system id: {:?}",
                        e.to_string()
                    )));
                }
            }
            match redfish.get_manager_id() {
                Ok(()) => {}
                Err(e) => {
                    return Err(CarbideError::GenericError(format!(
                        "Error getting manager id: {:?}",
                        e.to_string()
                    )));
                }
            }

            result = match action.unwrap() {
                IpmiTask::PowerControl(task) => match redfish.set_system_power(task) {
                    Ok(()) => Ok("Success".to_string()),
                    Err(e) => {
                        let error_msg = format!("Failed to run power control command {}", e);
                        Err(CarbideError::GenericError(error_msg))
                    }
                },
                IpmiTask::Status => match redfish.get_system() {
                    Ok(status) => Ok(status.power_state),
                    Err(e) => {
                        let error_msg = format!("Failed to run status command {}", e);
                        Err(CarbideError::GenericError(error_msg))
                    }
                },
                IpmiTask::EnableLockdown => {
                    match redfish.enable_bios_lockdown() {
                        Ok(()) => {}
                        Err(e) => {
                            let error_msg = format!("Failed to enable bios lockdown {}", e);
                            return Err(CarbideError::GenericError(error_msg));
                        }
                    }
                    match redfish
                        .enable_bmc_lockdown(libredfish::manager::OemDellBootDevices::PXE, false)
                    {
                        Ok(()) => {}
                        Err(e) => {
                            let error_msg = format!("Failed to enable bmc lockdown {}", e);
                            return Err(CarbideError::GenericError(error_msg));
                        }
                    }
                    match redfish.set_system_power(SystemPowerControl::ForceRestart) {
                        Ok(()) => Ok("Success".to_string()),
                        Err(e) => {
                            let error_msg = format!("Failed to run power control command {}", e);
                            Err(CarbideError::GenericError(error_msg))
                        }
                    }
                }
                IpmiTask::DisableLockdown => {
                    match redfish
                        .disable_bmc_lockdown(libredfish::manager::OemDellBootDevices::PXE, false)
                    {
                        Ok(()) => {}
                        Err(e) => {
                            let error_msg = format!("Failed to disable bmc lockdown {}", e);
                            return Err(CarbideError::GenericError(error_msg));
                        }
                    }
                    match redfish.disable_bios_lockdown() {
                        Ok(()) => {}
                        Err(e) => {
                            let error_msg =
                                format!("Failed to run disable bios lockdown command {}", e);
                            return Err(CarbideError::GenericError(error_msg));
                        }
                    }
                    match redfish.set_system_power(SystemPowerControl::ForceRestart) {
                        Ok(()) => Ok("Success".to_string()),
                        Err(e) => {
                            let error_msg = format!("Failed to run power control command {}", e);
                            Err(CarbideError::GenericError(error_msg))
                        }
                    }
                }
                IpmiTask::SetupSerialConsole => {
                    match redfish.setup_bmc_remote_access() {
                        Ok(()) => {}
                        Err(e) => {
                            let error_msg = format!("Failed to set bmc remote access {}", e);
                            return Err(CarbideError::GenericError(error_msg));
                        }
                    }
                    match redfish.setup_serial_console() {
                        Ok(()) => {}
                        Err(e) => {
                            let error_msg =
                                format!("Failed to set bios serial port settings {}", e);
                            return Err(CarbideError::GenericError(error_msg));
                        }
                    }
                    match redfish.set_system_power(SystemPowerControl::ForceRestart) {
                        Ok(()) => Ok("Success".to_string()),
                        Err(e) => {
                            let error_msg = format!("Failed to run power control command {}", e);
                            Err(CarbideError::GenericError(error_msg))
                        }
                    }
                }
                IpmiTask::FirstBootDevice(device, only_once) => {
                    match redfish.set_boot_first(device, only_once) {
                        Ok(()) => Ok("Success".to_string()),
                        Err(e) => {
                            let error_msg =
                                format!("Failed to set {} as first boot device, {}", device, e);
                            Err(CarbideError::GenericError(error_msg))
                        }
                    }
                }
            };
            result
        })
        .await
        .map_err(CarbideError::TokioJoinError)?;

        // Observe if DPU is also rebooted. If yes, reboot host again once DPU is up.
        // TODO: Do this only if BIOS Lockdown state is changed. In case, there is no
        // change, don't observe.
        if let Some(IpmiTask::EnableLockdown | IpmiTask::DisableLockdown) = cmd.action {
            observe_dpu_state_and_reboot_host(pool, &cmd).await?;
        }

        result
    }
}

// It took me three hours to realize the reason
// the test was hanging was because you're only allowed to specify one argument to the handler fn.
// or it can't find it in the database.
// If you try to specify these as independent arguments to the handler, the test hangs.  Forever.
// Hilariously, you can specify another string argument if you want, so that's fun.
#[derive(Clone)]
pub struct IpmiCommandHandlerArguments {
    credential_provider: Arc<dyn CredentialProvider>,
    ipmi_command_handler: Box<dyn IpmiCommandHandler>,
}

#[job(channel_name = "ipmi_handler")]
async fn command_handler(
    mut current_job: CurrentJob,
    hack: IpmiCommandHandlerArguments,
) -> CarbideResult<()> {
    let credential_provider = hack.credential_provider;
    let ipmi_command_handler = hack.ipmi_command_handler;
    update_status(&current_job, 1, "Started".to_string(), TaskState::Started).await;

    let data: Option<String> = current_job.json()?;
    let cmd: IpmiCommand = serde_json::from_str(&(data.unwrap()))?;
    update_status(
        &current_job,
        2,
        "Json parsing ok.".to_string(),
        TaskState::Ongoing,
    )
    .await;

    if cmd.action.is_none() {
        return Err(CarbideError::GenericError(
            "Didn't received any command in job.".to_string(),
        ));
    }

    let result = ipmi_command_handler
        .handle_ipmi_command(cmd, credential_provider.clone(), current_job.pool().clone())
        .await;
    match result {
        Ok(s) => {
            update_status(&current_job, 4, s, TaskState::Finished).await;
            let _ = current_job.complete().await.map_err(CarbideError::from);
            Ok(())
        }
        Err(e) => {
            update_status(
                &current_job,
                6,
                "Failed.".to_string(),
                TaskState::Error(e.to_string()),
            )
            .await;
            Err(e)
        }
    }
}

impl IpmiCommand {
    fn update_power_action(mut self, action: SystemPowerControl) -> Self {
        self.action = Some(IpmiTask::PowerControl(action));
        self
    }

    fn update_status(mut self) -> Self {
        self.action = Some(IpmiTask::Status);
        self
    }

    fn update_action(mut self, action: IpmiTask) -> Self {
        self.action = Some(action);
        self
    }

    async fn launch_command(&self, pool: sqlx::PgPool) -> CarbideResult<Uuid> {
        if self.host.is_empty() {
            return Err(CarbideError::GenericError(
                "Hostname not specified for lan connection".to_string(),
            ));
        }
        let json = serde_json::to_string(self)?;
        if self.action.is_none() {
            return Err(CarbideError::GenericError(
                "Didn't received any command.".to_string(),
            ));
        }
        // Default retry 5.
        command_handler
            .builder()
            .set_channel_name("ipmi_handler")
            .set_retry_backoff(Duration::from_millis(10))
            .set_json(&json)?
            .spawn(&pool)
            .await
            .map_err(CarbideError::from)
    }
}

impl IpmiCommand {
    pub fn new(host: String, machine_id: Uuid, user_role: UserRoles) -> Self {
        IpmiCommand {
            host,
            machine_id,
            user_role,
            action: None,
        }
    }

    pub async fn power_up(self, pool: &sqlx::PgPool) -> CarbideResult<Uuid> {
        self.update_power_action(SystemPowerControl::On)
            .launch_command(pool.clone())
            .await
    }
    pub async fn power_down(self, pool: &sqlx::PgPool) -> CarbideResult<Uuid> {
        self.update_power_action(SystemPowerControl::GracefulShutdown)
            .launch_command(pool.clone())
            .await
    }
    pub async fn power_cycle(self, pool: &sqlx::PgPool) -> CarbideResult<Uuid> {
        self.update_power_action(SystemPowerControl::PowerCycle)
            .launch_command(pool.clone())
            .await
    }
    pub async fn power_reset(self, pool: &sqlx::PgPool) -> CarbideResult<Uuid> {
        self.update_power_action(SystemPowerControl::ForceRestart)
            .launch_command(pool.clone())
            .await
    }
    pub async fn ipmi_status(self, pool: &sqlx::PgPool) -> CarbideResult<Uuid> {
        self.update_status().launch_command(pool.clone()).await
    }
    pub async fn enable_lockdown(self, pool: &sqlx::PgPool) -> CarbideResult<Uuid> {
        self.update_action(IpmiTask::EnableLockdown)
            .launch_command(pool.clone())
            .await
    }
    pub async fn disable_lockdown(self, pool: &sqlx::PgPool) -> CarbideResult<Uuid> {
        self.update_action(IpmiTask::DisableLockdown)
            .launch_command(pool.clone())
            .await
    }
    pub async fn setup_serial(self, pool: &sqlx::PgPool) -> CarbideResult<Uuid> {
        self.update_action(IpmiTask::SetupSerialConsole)
            .launch_command(pool.clone())
            .await
    }
    //pub async fn boot_from_network(self, pool: &sqlx::PgPool) -> CarbideResult<Uuid> {
    //    self.update_option(Actions::NetworkBoot)
    //        .launch_command(pool.clone())
    //        .await
    //}
}

pub async fn ipmi_handler<H>(
    pool: sqlx::PgPool,
    ipmi_command_handler: H,
    credential_provider: Arc<dyn CredentialProvider>,
) -> CarbideResult<OwnedHandle>
where
    H: IpmiCommandHandler + Clone,
{
    log::info!("Starting IPMI handler.");
    let mut registry = JobRegistry::new(&[command_handler]);
    registry.set_context(IpmiCommandHandlerArguments {
        credential_provider,
        ipmi_command_handler: Box::new(ipmi_command_handler),
    });
    let new_pool = pool.clone();

    // This function returns an OwnedHandle.
    // If the OwnedHandle is dropped, it will stop main event loop also.
    registry
        .runner(&new_pool)
        .set_concurrency(10, 20)
        .set_channel_names(&["ipmi_handler"])
        .run()
        .await
        .map_err(CarbideError::from)
}

#[derive(Debug)]
pub enum Operation {
    Reset = 0,
    On = 1,
    Off = 2,
    Cycle = 3,
    EnableLockdown = 4,
    DisableLockdown = 5,
    SetupSerial = 6,
}

impl TryFrom<i32> for Operation {
    type Error = CarbideError;
    fn try_from(value: i32) -> Result<Self, Self::Error> {
        Ok(match value {
            x if x == rpcOperation::PowerReset as i32 => Operation::Reset,
            x => {
                return Err(CarbideError::InvalidValueInEnum(format!(
                    "Unknown Operation {}.",
                    x
                )));
            }
        })
    }
}

pub struct MachineBmcRequest {
    pub machine_id: uuid::Uuid,
    operation: Operation,
    boot_with_custom_ipxe: bool,
}

impl TryFrom<rpc::InstancePowerRequest> for MachineBmcRequest {
    type Error = CarbideError;
    fn try_from(ipr: rpc::InstancePowerRequest) -> Result<Self, Self::Error> {
        let machine_id = ipr
            .machine_id
            .ok_or(CarbideError::MissingArgument("UUID is missing."))?;

        Ok(MachineBmcRequest {
            machine_id: uuid::Uuid::try_from(machine_id)?,
            operation: Operation::try_from(ipr.operation)?,
            boot_with_custom_ipxe: ipr.boot_with_custom_ipxe,
        })
    }
}

impl MachineBmcRequest {
    pub fn new(machine_id: uuid::Uuid, operation: Operation, boot_with_custom_ipxe: bool) -> Self {
        MachineBmcRequest {
            machine_id,
            operation,
            boot_with_custom_ipxe,
        }
    }

    pub async fn set_custom_pxe_on_next_boot(
        &self,
        txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    ) -> CarbideResult<()> {
        Instance::use_custom_ipxe_on_next_boot(
            self.machine_id,
            self.boot_with_custom_ipxe,
            &mut *txn,
        )
        .await
    }

    pub async fn invoke_bmc_command(&self, pool: sqlx::PgPool) -> CarbideResult<Uuid> {
        let mut txn = pool.begin().await.map_err(CarbideError::from)?;

        let role = UserRoles::Administrator;
        let ip = BmcMetaDataGetRequest {
            machine_id: self.machine_id,
            role,
        }
        .get_bmc_host_ip(&mut txn)
        .await?;

        txn.commit().await.map_err(CarbideError::from)?;

        let ipmi_command = IpmiCommand::new(ip, self.machine_id, role);

        let task_id = match self.operation {
            Operation::Reset => ipmi_command.power_reset(&pool).await?,
            Operation::On => ipmi_command.power_up(&pool).await?,
            Operation::Off => ipmi_command.power_down(&pool).await?,
            Operation::Cycle => ipmi_command.power_cycle(&pool).await?,
            Operation::EnableLockdown => ipmi_command.enable_lockdown(&pool).await?,
            Operation::DisableLockdown => ipmi_command.disable_lockdown(&pool).await?,
            Operation::SetupSerial => ipmi_command.setup_serial(&pool).await?,
        };

        log::info!(
            "Started bmc operation {:?} with task_id: {} for machine_id {}",
            self.operation,
            task_id,
            self.machine_id
        );
        Ok(task_id)
    }
}
