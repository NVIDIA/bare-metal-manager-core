use crate::bg::{job, CurrentJob, CurrentState, JobRegistry, OwnedHandle, Status, TaskState};
use crate::{CarbideError, CarbideResult};
use log::{error, info};
use serde::{Deserialize, Serialize};
use shell_words;
use sqlx;
use std::process::Command;
use uuid::Uuid;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct IpmiCommand {
    host: String,
    user: String,
    password: String,
    cmd: Option<String>,
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
            error!("Status update failed. Error: {:?}", x)
        }
    }
}

#[cfg(not(test))]
fn get_command_name() -> String {
    "ipmitool".to_string()
}

#[cfg(test)]
fn get_command_name() -> String {
    "sh".to_string()
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

    if cmd.cmd.is_none() {
        return Err(CarbideError::GenericError(
            "Didn't received any command in job.".to_string(),
        ));
    }

    let args: String = if cfg!(test) {
        cmd.cmd.unwrap() // Don't expect it to be None.
    } else {
        format!(
            "-I lanplus -U {user} -P {password} -H {host} {cmd}",
            user = cmd.user,
            password = cmd.password,
            host = cmd.host,
            cmd = cmd.cmd.unwrap()
        )
    };

    let args = shell_words::split(&args)
        .map_err(|_| CarbideError::GenericError("Parsing failed".to_string()))?;

    let output = match Command::new(get_command_name()).args(args).output() {
        Ok(sts) => sts,
        Err(e) => {
            update_status(
                &current_job,
                3,
                "Command execution failed.".to_string(),
                TaskState::Error(e.to_string()),
            )
            .await;
            return Err(CarbideError::GenericError(e.to_string()));
        }
    };

    if output.status.success() {
        let output_text = String::from_utf8(output.stdout)
            .unwrap_or_else(|_| "Couldn't parse output.".to_string());
        update_status(
            &current_job,
            4,
            output_text.to_string(),
            TaskState::Finished,
        )
        .await;
        let _ = current_job.complete().await.map_err(CarbideError::from);
    } else {
        let output_text = String::from_utf8(output.stderr)
            .unwrap_or_else(|_| "Couldn't parse output.".to_string());
        update_status(
            &current_job,
            5,
            "Failed.".to_string(),
            TaskState::Error(output_text.clone()),
        )
        .await;
        return Err(CarbideError::GenericError(output_text));
    }

    Ok(())
}

enum Actions {
    PowerUp,
    PowerDown,
    PowerStatus,
    PowerReset,
    NetworkBoot,
}

impl IpmiCommand {
    #[cfg(not(test))]
    fn update_option(mut self, action: Actions) -> Self {
        let cmd = match action {
            Actions::PowerUp => "chassis power up",
            Actions::PowerDown => "chassis power down",
            Actions::PowerStatus => "chassis power status",
            Actions::PowerReset => "chassis power reset",
            Actions::NetworkBoot => "chassis bootdev pxe options=efiboot",
        }
        .to_string();

        self.cmd = Some(cmd);
        self
    }

    #[cfg(test)]
    fn update_option(mut self, _action: Actions) -> Self {
        self.cmd = Some("-c \"echo test\"".to_string());
        self
    }

    async fn launch_command(&self, pool: sqlx::PgPool) -> CarbideResult<Uuid> {
        let json = serde_json::to_string(self)?;
        if self.cmd.is_none() {
            return Err(CarbideError::GenericError(
                "Didn't received any command.".to_string(),
            ));
        }
        // Default retry 5.
        Ok(command_handler
            .builder()
            .set_channel_name("ipmi_handler")
            .set_json(&json)?
            .spawn(&pool)
            .await
            .map_err(CarbideError::from)?)
    }
}

impl IpmiCommand {
    pub fn new(host: String, user: String, password: String) -> Self {
        IpmiCommand {
            host,
            user,
            password,
            cmd: None,
        }
    }
    pub async fn power_up(self, pool: &sqlx::PgPool) -> CarbideResult<Uuid> {
        self.update_option(Actions::PowerUp)
            .launch_command(pool.clone())
            .await
    }
    pub async fn power_down(self, pool: &sqlx::PgPool) -> CarbideResult<Uuid> {
        self.update_option(Actions::PowerDown)
            .launch_command(pool.clone())
            .await
    }
    pub async fn power_status(self, pool: &sqlx::PgPool) -> CarbideResult<Uuid> {
        self.update_option(Actions::PowerStatus)
            .launch_command(pool.clone())
            .await
    }
    pub async fn power_reset(self, pool: &sqlx::PgPool) -> CarbideResult<Uuid> {
        self.update_option(Actions::PowerReset)
            .launch_command(pool.clone())
            .await
    }
    pub async fn boot_from_network(self, pool: &sqlx::PgPool) -> CarbideResult<Uuid> {
        self.update_option(Actions::NetworkBoot)
            .launch_command(pool.clone())
            .await
    }
}

pub async fn ipmi_handler(pool: sqlx::PgPool) -> CarbideResult<OwnedHandle> {
    info!("Starting IPMI handler.");
    let registry = JobRegistry::new(&[command_handler]);
    let new_pool = pool.clone();

    // This function should return ownedhandle. If ownedhandle is dropped, it will stop main event loop also.
    Ok(registry
        .runner(&new_pool)
        .set_concurrency(10, 20)
        .run()
        .await
        .map_err(CarbideError::from)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time;

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
            .unwrap_or_else(|_| panic!("Database creation failed."));

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
        assert_eq!(fs.msg.trim(), "test");
    }
}
