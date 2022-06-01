# sqlxmq

[![CI Status](https://github.com/Diggsey/sqlxmq/workflows/CI/badge.svg)](https://github.com/Diggsey/sqlxmq/actions?query=workflow%3ACI)
[![Documentation](https://docs.rs/sqlxmq/badge.svg)](https://docs.rs/sqlxmq)
[![crates.io](https://img.shields.io/crates/v/sqlxmq.svg)](https://crates.io/crates/sqlxmq)

A job queue built on `sqlx` and `PostgreSQL`.

This library allows a CRUD application to run background jobs without complicating its
deployment. The only runtime dependency is `PostgreSQL`, so this is ideal for applications
already using a `PostgreSQL` database.

Although using a SQL database as a job queue means compromising on latency of
delivered jobs, there are several show-stopping issues present in ordinary job
queues which are avoided altogether.

With most other job queues, in-flight jobs are state that is not covered by normal
database backups. Even if jobs _are_ backed up, there is no way to restore both
a database and a job queue to a consistent point-in-time without manually
resolving conflicts.

By storing jobs in the database, existing backup procedures will store a perfectly
consistent state of both in-flight jobs and persistent data. Additionally, jobs can
be spawned and completed as part of other transactions, making it easy to write correct
application code.

Leveraging the power of `PostgreSQL`, this job queue offers several features not
present in other job queues.

# Features

- **Send/receive multiple jobs at once.**

  This reduces the number of queries to the database.

- **Send jobs to be executed at a future date and time.**

  Avoids the need for a separate scheduling system.

- **Reliable delivery of jobs.**

- **Automatic retries with exponential backoff.**

  Number of retries and initial backoff parameters are configurable.

- **Transactional sending of jobs.**

  Avoids sending spurious jobs if a transaction is rolled back.

- **Transactional completion of jobs.**

  If all side-effects of a job are updates to the database, this provides
  true exactly-once execution of jobs.

- **Transactional check-pointing of jobs.**

  Long-running jobs can check-point their state to avoid having to restart
  from the beginning if there is a failure: the next retry can continue
  from the last check-point.

- **Opt-in strictly ordered job delivery.**

  Jobs within the same channel will be processed strictly in-order
  if this option is enabled for the job.

- **Fair job delivery.**

  A channel with a lot of jobs ready to run will not starve a channel with fewer
  jobs.

- **Opt-in two-phase commit.**

  This is particularly useful on an ordered channel where a position can be "reserved"
  in the job order, but not committed until later.

- **JSON and/or binary payloads.**

  Jobs can use whichever is most convenient.

- **Automatic keep-alive of jobs.**

  Long-running jobs will automatically be "kept alive" to prevent them being
  retried whilst they're still ongoing.

- **Concurrency limits.**

  Specify the minimum and maximum number of concurrent jobs each runner should
  handle.

- **Built-in job registry via an attribute macro.**

  Jobs can be easily registered with a runner, and default configuration specified
  on a per-job basis.

- **Implicit channels.**

  Channels are implicitly created and destroyed when jobs are sent and processed,
  so no setup is required.

- **Channel groups.**

  Easily subscribe to multiple channels at once, thanks to the separation of
  channel name and channel arguments.

- **NOTIFY-based polling.**

  This saves resources when few jobs are being processed.

# Getting started

## Database schema

This crate expects certain database tables and stored procedures to exist.
You can copy the migration files from this crate into your own migrations
folder.

All database items created by this crate are prefixed with `mq`, so as not
to conflict with your own schema.

## Defining jobs

The first step is to define a function to be run on the job queue.

```rust
use sqlxmq::{job, CurrentJob};

// Arguments to the `#[job]` attribute allow setting default job options.
#[job(channel_name = "foo")]
async fn example_job(
    // The first argument should always be the current job.
    mut current_job: CurrentJob,
    // Additional arguments are optional, but can be used to access context
    // provided via `JobRegistry::set_context`.
    message: &'static str,
) -> sqlx::Result<()> {
    // Decode a JSON payload
    let who: Option<String> = current_job.json()?;

    // Do some work
    println!("{}, {}!", message, who.as_deref().unwrap_or("world"));

    // Mark the job as complete
    current_job.complete().await?;

    Ok(())
}
```

## Listening for jobs

Next we need to create a job runner: this is what listens for new jobs
and executes them.

```rust
use sqlxmq::JobRegistry;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // You'll need to provide a Postgres connection pool.
    let pool = connect_to_db().await?;

    // Construct a job registry from our single job.
    let mut registry = JobRegistry::new(&[example_job]);
    // Here is where you can configure the registry
    // registry.set_error_handler(...)

    // And add context
    registry.set_context("Hello");

    let runner = registry
        // Create a job runner using the connection pool.
        .runner(&pool)
        // Here is where you can configure the job runner
        // Aim to keep 10-20 jobs running at a time.
        .set_concurrency(10, 20)
        // Start the job runner in the background.
        .run()
        .await?;

    // The job runner will continue listening and running
    // jobs until `runner` is dropped.
}
```

## Spawning a job

The final step is to actually run a job.

```rust
example_job.builder()
    // This is where we can override job configuration
    .set_channel_name("bar")
    .set_json("John")
    .spawn(&pool)
    .await?;
```
