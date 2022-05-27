use std::any::type_name;
use std::collections::HashMap;
use std::error::Error;
use std::fmt::Display;
use std::future::Future;
use std::sync::Arc;
use std::time::Instant;

use anymap2::any::CloneAnySendSync;
use anymap2::Map;
use sqlx::{Pool, Postgres};
use uuid::Uuid;

use crate::hidden::{BuildFn, RunFn};
use crate::utils::Opaque;
use crate::{JobBuilder, JobRunnerOptions};

/// Stores a mapping from job name to job. Can be used to construct
/// a job runner.
pub struct JobRegistry {
    error_handler: Arc<dyn Fn(&str, Box<dyn Error + Send + 'static>) + Send + Sync>,
    job_map: HashMap<&'static str, &'static NamedJob>,
    context: Map<dyn CloneAnySendSync + Send + Sync>,
}

/// Error returned when a job is received whose name is not in the registry.
#[derive(Debug)]
pub struct UnknownJobError;

impl Error for UnknownJobError {}
impl Display for UnknownJobError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Unknown job")
    }
}

impl JobRegistry {
    /// Construct a new job registry from the provided job list.
    pub fn new(jobs: &[&'static NamedJob]) -> Self {
        let mut job_map = HashMap::new();
        for &job in jobs {
            if job_map.insert(job.name(), job).is_some() {
                panic!("Duplicate job registered: {}", job.name());
            }
        }
        Self {
            error_handler: Arc::new(Self::default_error_handler),
            job_map,
            context: Map::new(),
        }
    }

    /// Set a function to be called whenever a job returns an error.
    pub fn set_error_handler(
        &mut self,
        error_handler: impl Fn(&str, Box<dyn Error + Send + 'static>) + Send + Sync + 'static,
    ) -> &mut Self {
        self.error_handler = Arc::new(error_handler);
        self
    }

    /// Provide context for the jobs.
    pub fn set_context<C: Clone + Send + Sync + 'static>(&mut self, context: C) -> &mut Self {
        self.context.insert(context);
        self
    }

    /// Access job context. Will panic if context with this type has not been provided.
    pub fn context<C: Clone + Send + Sync + 'static>(&self) -> C {
        if let Some(c) = self.context.get::<C>() {
            c.clone()
        } else {
            panic!(
                "No context of type `{}` has been provided.",
                type_name::<C>()
            );
        }
    }

    /// Look-up a job by name.
    pub fn resolve_job(&self, name: &str) -> Option<&'static NamedJob> {
        self.job_map.get(name).copied()
    }

    /// The default error handler implementation, which simply logs the error.
    pub fn default_error_handler(name: &str, error: Box<dyn Error + Send + 'static>) {
        log::error!("Job `{}` failed: {}", name, error);
    }

    #[doc(hidden)]
    pub fn spawn_internal<E: Into<Box<dyn Error + Send + Sync + 'static>>>(
        &self,
        name: &'static str,
        f: impl Future<Output = Result<(), E>> + Send + 'static,
    ) {
        let error_handler = self.error_handler.clone();
        tokio::spawn(async move {
            let start_time = Instant::now();
            log::info!("Job `{}` started.", name);
            if let Err(e) = f.await {
                error_handler(name, e.into());
            } else {
                log::info!(
                    "Job `{}` completed in {}s.",
                    name,
                    start_time.elapsed().as_secs_f64()
                );
            }
        });
    }

    /// Construct a job runner from this registry and the provided connection
    /// pool.
    pub fn runner(self, pool: &Pool<Postgres>) -> JobRunnerOptions {
        JobRunnerOptions::new(pool, move |current_job| {
            if let Some(job) = self.resolve_job(current_job.name()) {
                (job.run_fn.0 .0)(&self, current_job);
            } else {
                (self.error_handler)(current_job.name(), Box::new(UnknownJobError))
            }
        })
    }
}

/// Type for a named job. Functions annotated with `#[job]` are
/// transformed into static variables whose type is `&'static NamedJob`.
#[derive(Debug)]
pub struct NamedJob {
    name: &'static str,
    build_fn: Opaque<BuildFn>,
    run_fn: Opaque<RunFn>,
}

impl NamedJob {
    #[doc(hidden)]
    pub const fn new_internal(name: &'static str, build_fn: BuildFn, run_fn: RunFn) -> Self {
        Self {
            name,
            build_fn: Opaque(build_fn),
            run_fn: Opaque(run_fn),
        }
    }
    /// Initialize a job builder with the name and defaults of this job.
    pub fn builder(&self) -> JobBuilder<'static> {
        let mut builder = JobBuilder::new(self.name);
        (self.build_fn.0 .0)(&mut builder);
        builder
    }
    /// Initialize a job builder with the name and defaults of this job,
    /// using the provided job ID.
    pub fn builder_with_id(&self, id: Uuid) -> JobBuilder<'static> {
        let mut builder = JobBuilder::new_with_id(id, self.name);
        (self.build_fn.0 .0)(&mut builder);
        builder
    }

    /// Returns the name of this job.
    pub const fn name(&self) -> &'static str {
        self.name
    }
}
