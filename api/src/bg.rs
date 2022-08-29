use serde::{Deserialize, Serialize};
use serde_json::{self, json};
use sqlx::types::Json;
use sqlx::{self, postgres::PgRow, PgPool, Postgres, Row};
use uuid::Uuid;

pub struct Status {}

#[derive(Debug)]
pub struct BgStatus {
    _id: Uuid,
    status: Result<Json<CurrentState>, sqlx::Error>,
    _last_updated: chrono::DateTime<chrono::Utc>,
}

/// TaskState and CurrentState are used to update status into bg_status table.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum TaskState {
    Started,
    Ongoing,
    Finished,
    Error(String),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CurrentState {
    pub checkpoint: u32,
    // Checkpoint location. It can be used in case of retries to identify last failure location.
    pub msg: String,
    // Any message which can be fetched during poll. Can be used to store json also.
    pub state: TaskState, // Task state. Check TaskState for more details.
}

struct MqMsgs {
    // Limited dummy implementation to make FromRow happy.
    attempts: i32,
}

impl<'r> sqlx::FromRow<'r, PgRow> for BgStatus {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        Ok(BgStatus {
            _id: row.try_get("id")?,
            status: row.try_get("status"),
            _last_updated: row.try_get("last_updated")?,
        })
    }
}

impl<'r> sqlx::FromRow<'r, PgRow> for MqMsgs {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        Ok(MqMsgs {
            attempts: row.try_get("attempts")?,
        })
    }
}

async fn mq_msgs_entry(pool: &PgPool, id: Uuid) -> Result<MqMsgs, sqlx::Error> {
    let query = "SELECT attempts from mq_msgs WHERE id=$1";
    let mut txn: sqlx::Transaction<'_, Postgres> = pool.clone().begin().await?;

    sqlx::query_as::<_, MqMsgs>(query)
        .bind(id)
        .fetch_one(&mut txn)
        .await
}

impl Status {
    /// User is responsible to set periodic or final status by calling `update` method. This is
    /// complete user specific implementation when user wants to update status.
    pub async fn update(
        pool: &PgPool,
        id: Uuid,
        current_state: CurrentState,
    ) -> Result<(), sqlx::Error> {
        let query = r#"INSERT INTO bg_status(id, status) values($1, $2) 
                            ON CONFLICT (id) DO UPDATE 
                            SET last_updated = now(), status=$2;"#;
        let mut txn: sqlx::Transaction<'_, Postgres> = pool.clone().begin().await?;

        match sqlx::query_as::<_, BgStatus>(query)
            .bind(id)
            .bind(json!(current_state))
            .fetch_all(&mut txn)
            .await
        {
            Ok(_) => {
                txn.commit().await?;
                Ok(())
            }
            Err(x) => Err(x),
        }
    }

    /// This method will read from `bg_status` table based on `id` and resturn json status message.
    /// User should use `update` method to update status periodically.
    pub async fn poll(pool: &PgPool, id: Uuid) -> Result<CurrentState, sqlx::Error> {
        let query = "SELECT id, status, last_updated from bg_status WHERE id=$1";
        let mut txn: sqlx::Transaction<'_, Postgres> = pool.clone().begin().await?;

        match sqlx::query_as::<_, BgStatus>(query)
            .bind(id)
            .fetch_one(&mut txn)
            .await?
            .status
        {
            Ok(Json(value)) => Ok(value),
            Err(x) => Err(x),
        }
    }

    /// This method will read from `bg_status` table based on `id` and resturn boolean to indicate
    /// if task is finished or not. It also check if all retries are exhausted.
    /// User should use `update` method to update status periodically.
    pub async fn is_finished(pool: &PgPool, id: Uuid) -> Result<bool, sqlx::Error> {
        match mq_msgs_entry(pool, id).await {
            Ok(msg) => Ok(msg.attempts == 0),
            Err(sqlx::Error::RowNotFound) => Ok(true),
            Err(x) => Err(x),
        }
    }

    /// This method will read from `bg_status` table based on `id` and resturn boolean to indicate
    /// if task is finished or not. It also check if all retries are exhausted.
    /// User should use `update` method to update status periodically.
    pub async fn is_failed(pool: &PgPool, id: Uuid) -> Result<bool, sqlx::Error> {
        let status: Result<bool, sqlx::Error> = match Status::poll(pool, id).await {
            Ok(value) => match value.state {
                TaskState::Error(_) => Ok(true),
                _ => Ok(false),
            },
            Err(x) => Err(x),
        };

        match mq_msgs_entry(pool, id).await {
            Ok(msg) => {
                if msg.attempts == 0 {
                    // 0 indicates that even last retry exhausted and task didn't call complete method.
                    Ok(true)
                } else {
                    status
                }
            }
            Err(sqlx::Error::RowNotFound) => status,
            Err(x) => Err(x),
        }
    }
}

#[cfg(test)]
mod tests {
    use sqlxmq::{job, CurrentJob, JobRegistry};
    use tokio::time;

    use super::*;

    static mut TEST_VAR: i32 = 0;

    const TEMP_DB_NAME: &str = "bghandler_test";

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

    async fn update_status(
        current_job: &CurrentJob,
        checkpoint: u32,
        msg: String,
        state: TaskState,
    ) {
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
            Ok(_) => {
                log::debug!("State updated successfully.");
            }
            Err(x) => {
                log::error!("Status update failed. Error: {:?}", x)
            }
        }
    }

    #[job(channel_name = "foo")]
    async fn example_job(mut current_job: CurrentJob) -> sqlx::Result<()> {
        // Decode a JSON payload
        update_status(
            &current_job,
            1,
            "Starting Now".to_string(),
            TaskState::Started,
        )
        .await;
        time::sleep(time::Duration::from_millis(2000)).await;
        let who: Option<String> = current_job.json().unwrap();
        // Do some work
        let _js = who.as_deref().unwrap_or("world");
        update_status(&current_job, 1, "Got JS".to_string(), TaskState::Ongoing).await;
        time::sleep(time::Duration::from_millis(2000)).await;
        unsafe {
            TEST_VAR = 1;
        }
        // Mark the job as complete
        update_status(&current_job, 3, "Over now".to_string(), TaskState::Finished).await;
        current_job.complete().await.unwrap();

        Ok(())
    }

    #[tokio::test]
    async fn test_bg() {
        unsafe {
            TEST_VAR = 0;
        }
        let pool = get_database_connection().await.unwrap();
        let registry = JobRegistry::new(&[example_job]);
        let _runner = registry
            .runner(&pool)
            .set_concurrency(10, 20)
            .run()
            .await
            .unwrap();

        let job_id = example_job
            .builder()
            // This is where we can override job configuration
            .set_channel_name("bar")
            .set_json("Some test string")
            .unwrap()
            .spawn(&pool)
            .await
            .unwrap();

        // Let task execute.
        loop {
            if Status::is_finished(&pool, job_id).await.unwrap() {
                break;
            }
            time::sleep(time::Duration::from_millis(1000)).await;
        }

        assert!(Status::is_finished(&pool, job_id).await.unwrap());
        assert!(!Status::is_failed(&pool, job_id).await.unwrap());
        unsafe {
            assert_eq!(TEST_VAR, 1);
        }
    }
}
