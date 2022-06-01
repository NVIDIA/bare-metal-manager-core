use std::borrow::Cow;
use std::fmt::Debug;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sqlx::postgres::types::PgInterval;
use sqlx::postgres::PgListener;
use sqlx::{Pool, Postgres};
use tokio::sync::Notify;
use tokio::task;
use uuid::Uuid;

use crate::utils::{Opaque, OwnedHandle};

/// Type used to build a job runner.
#[derive(Debug, Clone)]
pub struct JobRunnerOptions {
    min_concurrency: usize,
    max_concurrency: usize,
    channel_names: Option<Vec<String>>,
    dispatch: Opaque<Arc<dyn Fn(CurrentJob) + Send + Sync + 'static>>,
    pool: Pool<Postgres>,
    keep_alive: bool,
}

#[derive(Debug)]
struct JobRunner {
    options: JobRunnerOptions,
    running_jobs: AtomicUsize,
    notify: Notify,
}

/// Type used to checkpoint a running job.
#[derive(Debug, Clone, Default)]
pub struct Checkpoint<'a> {
    duration: Duration,
    extra_retries: usize,
    payload_json: Option<Cow<'a, str>>,
    payload_bytes: Option<&'a [u8]>,
}

impl<'a> Checkpoint<'a> {
    /// Construct a new checkpoint which also keeps the job alive
    /// for the specified interval.
    pub fn new_keep_alive(duration: Duration) -> Self {
        Self {
            duration,
            extra_retries: 0,
            payload_json: None,
            payload_bytes: None,
        }
    }
    /// Construct a new checkpoint.
    pub fn new() -> Self {
        Self::default()
    }
    /// Add extra retries to the current job.
    pub fn set_extra_retries(&mut self, extra_retries: usize) -> &mut Self {
        self.extra_retries = extra_retries;
        self
    }
    /// Specify a new raw JSON payload.
    pub fn set_raw_json(&mut self, raw_json: &'a str) -> &mut Self {
        self.payload_json = Some(Cow::Borrowed(raw_json));
        self
    }
    /// Specify a new raw binary payload.
    pub fn set_raw_bytes(&mut self, raw_bytes: &'a [u8]) -> &mut Self {
        self.payload_bytes = Some(raw_bytes);
        self
    }
    /// Specify a new JSON payload.
    pub fn set_json<T: Serialize>(&mut self, value: &T) -> Result<&mut Self, serde_json::Error> {
        let value = serde_json::to_string(value)?;
        self.payload_json = Some(Cow::Owned(value));
        Ok(self)
    }
    async fn execute<'b, E: sqlx::Executor<'b, Database = Postgres>>(
        &self,
        job_id: Uuid,
        executor: E,
    ) -> Result<(), sqlx::Error> {
        sqlx::query("SELECT mq_checkpoint($1, $2, $3, $4, $5)")
            .bind(job_id)
            .bind(self.duration)
            .bind(self.payload_json.as_deref())
            .bind(self.payload_bytes)
            .bind(self.extra_retries as i32)
            .execute(executor)
            .await?;
        Ok(())
    }
}

/// Handle to the currently executing job.
/// When dropped, the job is assumed to no longer be running.
/// To prevent the job being retried, it must be explicitly completed using
/// one of the `.complete_` methods.
#[derive(Debug)]
pub struct CurrentJob {
    id: Uuid,
    name: String,
    payload_json: Option<String>,
    payload_bytes: Option<Vec<u8>>,
    job_runner: Arc<JobRunner>,
    keep_alive: Option<OwnedHandle>,
}

impl CurrentJob {
    /// Returns the database pool used to receive this job.
    pub fn pool(&self) -> &Pool<Postgres> {
        &self.job_runner.options.pool
    }
    async fn delete(
        &self,
        executor: impl sqlx::Executor<'_, Database = Postgres>,
    ) -> Result<(), sqlx::Error> {
        sqlx::query("SELECT mq_delete(ARRAY[$1])")
            .bind(self.id)
            .execute(executor)
            .await?;
        Ok(())
    }

    async fn stop_keep_alive(&mut self) {
        if let Some(keep_alive) = self.keep_alive.take() {
            keep_alive.stop().await;
        }
    }

    /// Complete this job and commit the provided transaction at the same time.
    /// If the transaction cannot be committed, the job will not be completed.
    pub async fn complete_with_transaction(
        &mut self,
        mut tx: sqlx::Transaction<'_, Postgres>,
    ) -> Result<(), sqlx::Error> {
        self.delete(&mut tx).await?;
        tx.commit().await?;
        self.stop_keep_alive().await;
        Ok(())
    }
    /// Complete this job.
    pub async fn complete(&mut self) -> Result<(), sqlx::Error> {
        self.delete(self.pool()).await?;
        self.stop_keep_alive().await;
        Ok(())
    }
    /// Checkpoint this job and commit the provided transaction at the same time.
    /// If the transaction cannot be committed, the job will not be checkpointed.
    /// Checkpointing allows the job payload to be replaced for the next retry.
    pub async fn checkpoint_with_transaction(
        &mut self,
        mut tx: sqlx::Transaction<'_, Postgres>,
        checkpoint: &Checkpoint<'_>,
    ) -> Result<(), sqlx::Error> {
        checkpoint.execute(self.id, &mut tx).await?;
        tx.commit().await?;
        Ok(())
    }
    /// Checkpointing allows the job payload to be replaced for the next retry.
    pub async fn checkpoint(&mut self, checkpoint: &Checkpoint<'_>) -> Result<(), sqlx::Error> {
        checkpoint.execute(self.id, self.pool()).await?;
        Ok(())
    }
    /// Prevent this job from being retried for the specified interval.
    pub async fn keep_alive(&mut self, duration: Duration) -> Result<(), sqlx::Error> {
        sqlx::query("SELECT mq_keep_alive(ARRAY[$1], $2)")
            .bind(self.id)
            .bind(duration)
            .execute(self.pool())
            .await?;
        Ok(())
    }
    /// Returns the ID of this job.
    pub fn id(&self) -> Uuid {
        self.id
    }
    /// Returns the name of this job.
    pub fn name(&self) -> &str {
        &self.name
    }
    /// Extracts the JSON payload belonging to this job (if present).
    pub fn json<'a, T: Deserialize<'a>>(&'a self) -> Result<Option<T>, serde_json::Error> {
        if let Some(payload_json) = &self.payload_json {
            serde_json::from_str(payload_json).map(Some)
        } else {
            Ok(None)
        }
    }
    /// Returns the raw JSON payload for this job.
    pub fn raw_json(&self) -> Option<&str> {
        self.payload_json.as_deref()
    }
    /// Returns the raw binary payload for this job.
    pub fn raw_bytes(&self) -> Option<&[u8]> {
        self.payload_bytes.as_deref()
    }
}

impl Drop for CurrentJob {
    fn drop(&mut self) {
        if self.job_runner.running_jobs.fetch_sub(1, Ordering::SeqCst)
            == self.job_runner.options.min_concurrency
        {
            self.job_runner.notify.notify_one();
        }
    }
}

impl JobRunnerOptions {
    /// Begin constructing a new job runner using the specified connection pool,
    /// and the provided execution function.
    pub fn new<F: Fn(CurrentJob) + Send + Sync + 'static>(pool: &Pool<Postgres>, f: F) -> Self {
        Self {
            min_concurrency: 16,
            max_concurrency: 32,
            channel_names: None,
            keep_alive: true,
            dispatch: Opaque(Arc::new(f)),
            pool: pool.clone(),
        }
    }
    /// Set the concurrency limits for this job runner. When the number of active
    /// jobs falls below the minimum, the runner will poll for more, up to the maximum.
    ///
    /// The difference between the min and max will dictate the maximum batch size which
    /// can be received: larger batch sizes are more efficient.
    pub fn set_concurrency(&mut self, min_concurrency: usize, max_concurrency: usize) -> &mut Self {
        self.min_concurrency = min_concurrency;
        self.max_concurrency = max_concurrency;
        self
    }
    /// Set the channel names which this job runner will subscribe to. If unspecified,
    /// the job runner will subscribe to all channels.
    pub fn set_channel_names<'a>(&'a mut self, channel_names: &[&str]) -> &'a mut Self {
        self.channel_names = Some(
            channel_names
                .iter()
                .copied()
                .map(ToOwned::to_owned)
                .collect(),
        );
        self
    }
    /// Choose whether to automatically keep jobs alive whilst they're still
    /// running. Defaults to `true`.
    pub fn set_keep_alive(&mut self, keep_alive: bool) -> &mut Self {
        self.keep_alive = keep_alive;
        self
    }

    /// Start the job runner in the background. The job runner will stop when the
    /// returned handle is dropped.
    pub async fn run(&self) -> Result<OwnedHandle, sqlx::Error> {
        let options = self.clone();
        let job_runner = Arc::new(JobRunner {
            options,
            running_jobs: AtomicUsize::new(0),
            notify: Notify::new(),
        });
        let listener_task = start_listener(job_runner.clone()).await?;
        Ok(OwnedHandle::new(task::spawn(main_loop(
            job_runner,
            listener_task,
        ))))
    }
}

async fn start_listener(job_runner: Arc<JobRunner>) -> Result<OwnedHandle, sqlx::Error> {
    let mut listener = PgListener::connect_with(&job_runner.options.pool).await?;
    if let Some(channels) = &job_runner.options.channel_names {
        let names: Vec<String> = channels.iter().map(|c| format!("mq_{}", c)).collect();
        listener
            .listen_all(names.iter().map(|s| s.as_str()))
            .await?;
    } else {
        listener.listen("mq").await?;
    }
    Ok(OwnedHandle::new(task::spawn(async move {
        let mut num_errors = 0;
        loop {
            if num_errors > 0 || listener.recv().await.is_ok() {
                job_runner.notify.notify_one();
                num_errors = 0;
            } else {
                tokio::time::sleep(Duration::from_secs(1 << num_errors)).await;
                num_errors += 1;
            }
        }
    })))
}

#[derive(sqlx::FromRow)]
struct PolledMessage {
    id: Option<Uuid>,
    is_committed: Option<bool>,
    name: Option<String>,
    payload_json: Option<String>,
    payload_bytes: Option<Vec<u8>>,
    retry_backoff: Option<PgInterval>,
    wait_time: Option<PgInterval>,
}

fn to_duration(interval: PgInterval) -> Duration {
    const SECONDS_PER_DAY: u64 = 24 * 60 * 60;
    if interval.microseconds < 0 || interval.days < 0 || interval.months < 0 {
        Duration::default()
    } else {
        let days = (interval.days as u64) + (interval.months as u64) * 30;
        Duration::from_micros(interval.microseconds as u64)
            + Duration::from_secs(days * SECONDS_PER_DAY)
    }
}

async fn poll_and_dispatch(
    job_runner: &Arc<JobRunner>,
    batch_size: i32,
) -> Result<Duration, sqlx::Error> {
    log::info!("Polling for messages");

    let options = &job_runner.options;
    let messages = sqlx::query_as::<_, PolledMessage>("SELECT * FROM mq_poll($1, $2)")
        .bind(&options.channel_names)
        .bind(batch_size)
        .fetch_all(&options.pool)
        .await?;

    let ids_to_delete: Vec<_> = messages
        .iter()
        .filter(|msg| msg.is_committed == Some(false))
        .filter_map(|msg| msg.id)
        .collect();

    log::info!("Deleting {} messages", ids_to_delete.len());
    if !ids_to_delete.is_empty() {
        sqlx::query("SELECT mq_delete($1)")
            .bind(ids_to_delete)
            .execute(&options.pool)
            .await?;
    }

    const MAX_WAIT: Duration = Duration::from_secs(60);

    let wait_time = messages
        .iter()
        .filter_map(|msg| msg.wait_time.clone())
        .map(to_duration)
        .min()
        .unwrap_or(MAX_WAIT);

    for msg in messages {
        if let PolledMessage {
            id: Some(id),
            is_committed: Some(true),
            name: Some(name),
            payload_json,
            payload_bytes,
            retry_backoff: Some(retry_backoff),
            ..
        } = msg
        {
            let retry_backoff = to_duration(retry_backoff);
            let keep_alive = if options.keep_alive {
                Some(OwnedHandle::new(task::spawn(keep_job_alive(
                    id,
                    options.pool.clone(),
                    retry_backoff,
                ))))
            } else {
                None
            };
            let current_job = CurrentJob {
                id,
                name,
                payload_json,
                payload_bytes,
                job_runner: job_runner.clone(),
                keep_alive,
            };
            job_runner.running_jobs.fetch_add(1, Ordering::SeqCst);
            (options.dispatch)(current_job);
        }
    }

    Ok(wait_time)
}

async fn main_loop(job_runner: Arc<JobRunner>, _listener_task: OwnedHandle) {
    let options = &job_runner.options;
    let mut failures = 0;
    loop {
        let running_jobs = job_runner.running_jobs.load(Ordering::SeqCst);
        let duration = if running_jobs < options.min_concurrency {
            let batch_size = (options.max_concurrency - running_jobs) as i32;

            match poll_and_dispatch(&job_runner, batch_size).await {
                Ok(duration) => {
                    failures = 0;
                    duration
                }
                Err(e) => {
                    failures += 1;
                    log::error!("Failed to poll for messages: {}", e);
                    Duration::from_millis(50 << failures)
                }
            }
        } else {
            Duration::from_secs(60)
        };

        // Wait for us to be notified, or for the timeout to elapse
        let _ = tokio::time::timeout(duration, job_runner.notify.notified()).await;
    }
}

async fn keep_job_alive(id: Uuid, pool: Pool<Postgres>, mut interval: Duration) {
    loop {
        tokio::time::sleep(interval / 2).await;
        interval *= 2;
        if let Err(e) = sqlx::query("SELECT mq_keep_alive(ARRAY[$1], $2)")
            .bind(id)
            .bind(interval)
            .execute(&pool)
            .await
        {
            log::error!("Failed to keep job {} alive: {}", id, e);
            break;
        }
    }
}
