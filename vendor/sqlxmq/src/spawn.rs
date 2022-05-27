use std::borrow::Cow;
use std::fmt::Debug;
use std::time::Duration;

use serde::Serialize;
use sqlx::Postgres;
use uuid::Uuid;

/// Type for building a job to send.
#[derive(Debug, Clone)]
pub struct JobBuilder<'a> {
    id: Uuid,
    delay: Duration,
    channel_name: &'a str,
    channel_args: &'a str,
    retries: u32,
    retry_backoff: Duration,
    commit_interval: Option<Duration>,
    ordered: bool,
    name: &'a str,
    payload_json: Option<Cow<'a, str>>,
    payload_bytes: Option<&'a [u8]>,
}

impl<'a> JobBuilder<'a> {
    /// Prepare to send a job with the specified name.
    pub fn new(name: &'a str) -> Self {
        Self::new_with_id(Uuid::new_v4(), name)
    }
    /// Prepare to send a job with the specified name and ID.
    pub fn new_with_id(id: Uuid, name: &'a str) -> Self {
        Self {
            id,
            delay: Duration::from_secs(0),
            channel_name: "",
            channel_args: "",
            retries: 4,
            retry_backoff: Duration::from_secs(1),
            commit_interval: None,
            ordered: false,
            name,
            payload_json: None,
            payload_bytes: None,
        }
    }
    /// Use the provided function to set any number of configuration
    /// options at once.
    pub fn set_proto<'b>(
        &'b mut self,
        proto: impl FnOnce(&'b mut Self) -> &'b mut Self,
    ) -> &'b mut Self {
        proto(self)
    }
    /// Set the channel name (default "").
    pub fn set_channel_name(&mut self, channel_name: &'a str) -> &mut Self {
        self.channel_name = channel_name;
        self
    }
    /// Set the channel arguments (default "").
    pub fn set_channel_args(&mut self, channel_args: &'a str) -> &mut Self {
        self.channel_args = channel_args;
        self
    }
    /// Set the number of retries after the initial attempt (default 4).
    pub fn set_retries(&mut self, retries: u32) -> &mut Self {
        self.retries = retries;
        self
    }
    /// Set the initial backoff for retries (default 1s).
    pub fn set_retry_backoff(&mut self, retry_backoff: Duration) -> &mut Self {
        self.retry_backoff = retry_backoff;
        self
    }
    /// Set the commit interval for two-phase commit (default disabled).
    pub fn set_commit_interval(&mut self, commit_interval: Option<Duration>) -> &mut Self {
        self.commit_interval = commit_interval;
        self
    }
    /// Set whether this job is strictly ordered with respect to other ordered
    /// job in the same channel (default false).
    pub fn set_ordered(&mut self, ordered: bool) -> &mut Self {
        self.ordered = ordered;
        self
    }

    /// Set a delay before this job is executed (default none).
    pub fn set_delay(&mut self, delay: Duration) -> &mut Self {
        self.delay = delay;
        self
    }

    /// Set a raw JSON payload for the job.
    pub fn set_raw_json(&mut self, raw_json: &'a str) -> &mut Self {
        self.payload_json = Some(Cow::Borrowed(raw_json));
        self
    }

    /// Set a raw binary payload for the job.
    pub fn set_raw_bytes(&mut self, raw_bytes: &'a [u8]) -> &mut Self {
        self.payload_bytes = Some(raw_bytes);
        self
    }

    /// Set a JSON payload for the job.
    pub fn set_json<T: ?Sized + Serialize>(
        &mut self,
        value: &T,
    ) -> Result<&mut Self, serde_json::Error> {
        let value = serde_json::to_string(value)?;
        self.payload_json = Some(Cow::Owned(value));
        Ok(self)
    }

    /// Spawn the job using the given executor. This might be a connection
    /// pool, a connection, or a transaction.
    pub async fn spawn<'b, E: sqlx::Executor<'b, Database = Postgres>>(
        &self,
        executor: E,
    ) -> Result<Uuid, sqlx::Error> {
        sqlx::query(
            "SELECT mq_insert(ARRAY[($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)::mq_new_t])",
        )
        .bind(self.id)
        .bind(self.delay)
        .bind(self.retries as i32)
        .bind(self.retry_backoff)
        .bind(self.channel_name)
        .bind(self.channel_args)
        .bind(self.commit_interval)
        .bind(self.ordered)
        .bind(self.name)
        .bind(self.payload_json.as_deref())
        .bind(self.payload_bytes)
        .execute(executor)
        .await?;
        Ok(self.id)
    }
}

/// Commit the specified jobs. The jobs should have been previously spawned
/// with the two-phase commit option enabled.
pub async fn commit<'b, E: sqlx::Executor<'b, Database = Postgres>>(
    executor: E,
    job_ids: &[Uuid],
) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT mq_commit($1)")
        .bind(job_ids)
        .execute(executor)
        .await?;
    Ok(())
}

/// Clear jobs from the specified queues.
pub async fn clear<'b, E: sqlx::Executor<'b, Database = Postgres>>(
    executor: E,
    channel_names: &[&str],
) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT mq_clear($1)")
        .bind(channel_names)
        .execute(executor)
        .await?;
    Ok(())
}

/// Clear jobs from the specified queues.
pub async fn clear_all<'b, E: sqlx::Executor<'b, Database = Postgres>>(
    executor: E,
) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT mq_clear_all()")
        .execute(executor)
        .await?;
    Ok(())
}
