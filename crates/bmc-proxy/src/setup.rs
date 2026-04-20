use metrics_endpoint::MetricsSetup;
use tracing_subscriber::Layer;
use tracing_subscriber::filter::{EnvFilter, LevelFilter};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

#[derive(thiserror::Error, Debug)]
pub enum SetupError {
    #[error("Error configuring logging from environment variables: {0}")]
    EnvFilter(#[from] tracing_subscriber::filter::FromEnvError),
    #[error("Error initializing tracing subscriber: {0}")]
    TracingSubscriberInit(#[from] tracing_subscriber::util::TryInitError),
    #[error("Error setting up metrics: {0}")]
    Metrics(String),
}

pub type SetupResult<T> = Result<T, SetupError>;

pub fn setup_logging(debug: bool) -> SetupResult<()> {
    // Default log level if RUST_LOG is not set
    let default_log_level = if debug {
        LevelFilter::DEBUG
    } else {
        LevelFilter::INFO
    };

    // Ignore certain spans and events from 3rd party frameworks
    let log_filter = dep_log_filter(
        EnvFilter::builder()
            .with_default_directive(default_log_level.into())
            .from_env()?,
    );

    tracing_subscriber::registry()
        .with(logfmt::layer().with_filter(log_filter))
        .try_init()?;

    tracing::info!("current log level: {}", LevelFilter::current());
    Ok(())
}

pub fn setup_metrics() -> SetupResult<MetricsSetup> {
    metrics_endpoint::new_metrics_setup("carbide-bmc-proxy", "carbide-system", true)
        .map_err(|e| SetupError::Metrics(e.to_string()))
}

pub fn dep_log_filter(env_filter: EnvFilter) -> EnvFilter {
    [
        "hyper=error",
        "rustls=warn",
        "tokio_util::codec=warn",
        "vaultrs=error",
        "h2=warn",
    ]
    .iter()
    .fold(env_filter, |f, filter_str| {
        f.add_directive(
            filter_str
                .parse()
                .unwrap_or_else(|err| panic!("{filter_str} must be parsed; error: {err}")),
        )
    })
}
