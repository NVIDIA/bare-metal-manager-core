use std::time::Duration;

use serde::{Deserialize, Serialize};
use sqlx;
use uuid::Uuid;

use freeipmi_sys::{self, IpmiChassisControl};

use crate::bg::{job, CurrentJob, CurrentState, JobRegistry, OwnedHandle, Status, TaskState};
use crate::{CarbideError, CarbideResult};

#[derive(Serialize, Deserialize, Clone, Debug)]
enum IpmiTask {
    Status,
    PowerControl(IpmiChassisControl),
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct IpmiCommand {
    host: String,
    user: String,
    password: String,
    action: Option<IpmiTask>,
}

async fn update_status(current_job: &CurrentJob, checkpoint: u32, msg: String, state: TaskState) {
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

//Ron: this isn't the right way to do this -- it should be a trait that has this function
//so that we don't conditionally compile out code during tests.  We have to do shenanigans with 
//impots 
#[cfg(test)]
async fn handle_ipmi_command(cmd: IpmiCommand) -> CarbideResult<String> {
    match cmd.action.unwrap() {
        IpmiTask::PowerControl(_task) => Ok("Power Control".to_string()),
        IpmiTask::Status => Ok("Status".to_string()),
    }
}

#[cfg(not(test))]
async fn handle_ipmi_command(cmd: IpmiCommand) -> CarbideResult<String> {
    use freeipmi_sys::{
        ipmi::IpmiContext, IpmiAuthenticationType, IpmiCipherSuite, IpmiDevice, IpmiPrivilegeLevel,
    };

    let interface = IpmiDevice::Lan2_0;
    let cipher = IpmiCipherSuite::HmacSha256AesCbc128;
    let auth = IpmiAuthenticationType::Md5;
    let mode = IpmiPrivilegeLevel::Admin;
    let result: CarbideResult<String>;

    let mut ctx = IpmiContext::new(
        cmd.host,
        cmd.user,
        cmd.password,
        Option::from(interface),
        Option::from(cipher),
        Option::from(mode),
        Option::from(auth),
    );

    if ctx.connect().is_ok() {
        result = match cmd.action.unwrap() {
            IpmiTask::PowerControl(task) => match ctx.power_control(task) {
                Ok(()) => Ok("Success".to_string()),
                Err(e) => {
                    let error_msg = format!("Failed to run power control command {}", e);
                    Err(CarbideError::GenericError(error_msg))
                }
            },
            IpmiTask::Status => match ctx.chassis_status() {
                Ok(status) => Ok(status
                    .iter()
                    .map(|x| format!("{}", x))
                    .collect::<Vec<String>>()
                    .join("\n")),
                Err(e) => {
                    let error_msg = format!("Failed to run status command {}", e);
                    Err(CarbideError::GenericError(error_msg))
                }
            },
        };
        let _ = ctx.disconnect();
    } else {
        result = Err(CarbideError::GenericError("Failed to connect".to_string()))
    }
    ctx.destroy();
    result
}

#[job(channel_name = "ipmi_handler")]
async fn command_handler(mut current_job: CurrentJob) -> CarbideResult<()> {
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

    let result = handle_ipmi_command(cmd).await;
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
    fn update_action(mut self, action: IpmiChassisControl) -> Self {
        self.action = Some(IpmiTask::PowerControl(action));
        self
    }

    fn update_status(mut self) -> Self {
        self.action = Some(IpmiTask::Status);
        self
    }

    async fn launch_command(&self, pool: sqlx::PgPool) -> CarbideResult<Uuid> {
        if self.host.is_empty() || self.user.is_empty() || self.password.is_empty() {
            return Err(CarbideError::GenericError(
                "Hostname or Username or Password not specified for lan connection".to_string(),
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
    pub fn new(host: String, user: String, password: String) -> Self {
        IpmiCommand {
            host,
            user,
            password,
            action: None,
        }
    }
    pub async fn power_up(self, pool: &sqlx::PgPool) -> CarbideResult<Uuid> {
        self.update_action(IpmiChassisControl::PowerUp)
            .launch_command(pool.clone())
            .await
    }
    pub async fn power_down(self, pool: &sqlx::PgPool) -> CarbideResult<Uuid> {
        self.update_action(IpmiChassisControl::PowerDown)
            .launch_command(pool.clone())
            .await
    }
    pub async fn power_cycle(self, pool: &sqlx::PgPool) -> CarbideResult<Uuid> {
        self.update_action(IpmiChassisControl::PowerCycle)
            .launch_command(pool.clone())
            .await
    }
    pub async fn power_reset(self, pool: &sqlx::PgPool) -> CarbideResult<Uuid> {
        self.update_action(IpmiChassisControl::HardReset)
            .launch_command(pool.clone())
            .await
    }
    pub async fn ipmi_status(self, pool: &sqlx::PgPool) -> CarbideResult<Uuid> {
        self.update_status().launch_command(pool.clone()).await
    }
    //pub async fn boot_from_network(self, pool: &sqlx::PgPool) -> CarbideResult<Uuid> {
    //    self.update_option(Actions::NetworkBoot)
    //        .launch_command(pool.clone())
    //        .await
    //}
}

pub async fn ipmi_handler(pool: sqlx::PgPool) -> CarbideResult<OwnedHandle> {
    log::info!("Starting IPMI handler.");
    let registry = JobRegistry::new(&[command_handler]);
    let new_pool = pool.clone();

    // This function should return ownedhandle. If ownedhandle is dropped, it will stop main event loop also.
    registry
        .runner(&new_pool)
        .set_concurrency(10, 20)
        .run()
        .await
        .map_err(CarbideError::from)
}

#[cfg(test)]
mod tests {
    use tokio::time;

    use super::*;

    static TEMP_DB_NAME: &str = "ipmihandler_test";

    fn get_base_uri() -> String {
        if std::env::var("TESTDB_HOST").is_ok()
            && std::env::var("TESTDB_USER").is_ok()
            && std::env::var("TESTDB_PASSWORD").is_ok()
        {
            format!(
                "postgres://{0}:{1}@{2}",
                std::env::var("TESTDB_USER").unwrap(),
                std::env::var("TESTDB_PASSWORD").unwrap(),
                std::env::var("TESTDB_HOST").unwrap(),
            )
        } else {
            "postgres://%2Fvar%2Frun%2Fpostgresql".to_string()
        }
    }

    async fn get_database_connection() -> Result<sqlx::PgPool, sqlx::Error> {
        let base_uri = get_base_uri();
        let full_uri_template = [base_uri.clone(), "/template1".to_string()].concat();

        let template_pool = sqlx::PgPool::connect(&full_uri_template).await?;
        let pool = template_pool.clone();
        let _x = sqlx::query(format!("DROP DATABASE {0}", TEMP_DB_NAME).as_str())
            .execute(&(pool.clone()))
            .await;
        sqlx::query(format!("CREATE DATABASE {0} TEMPLATE template0", TEMP_DB_NAME).as_str())
            .execute(&pool)
            .await
            .unwrap_or_else(|x| panic!("Database creation failed: {} - {}.", x, base_uri));

        let full_uri_db = [base_uri, "/".to_string(), TEMP_DB_NAME.to_string()].concat();

        let real_pool = sqlx::PgPool::connect(&full_uri_db).await?;

        sqlx::migrate!().run(&(real_pool.clone())).await.unwrap();

        Ok(real_pool)
    }

    #[tokio::test]
    async fn test_ipmi() {
        let pool = get_database_connection().await.unwrap();
        let _handle = ipmi_handler(pool.clone()).await;
        let job = IpmiCommand::new(
            "127.0.0.1".to_string(),
            "test".to_string(),
            "password".to_string(),
        );
        // use job.clone() if want to reuse job again.
        let job_id = job.power_up(&pool).await.unwrap();

        loop {
            if Status::is_finished(&pool, job_id).await.unwrap() {
                break;
            }
            time::sleep(time::Duration::from_millis(1000)).await;
        }

        let fs = Status::poll(&pool, job_id).await.unwrap();
        assert_eq!(fs.state, TaskState::Finished);
        assert_eq!(fs.msg.trim(), "Power Control");
    }
}
