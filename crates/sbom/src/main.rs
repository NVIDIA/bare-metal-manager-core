use std::collections::HashSet;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use sbom::{
    assemble_staging_directory, copy_files, download_sources, download_sources_from_config,
    generate_attribution, install_packages,
};
use tracing_subscriber::filter::EnvFilter;
use tracing_subscriber::prelude::*;
use tracing_subscriber::util::SubscriberInitExt;

#[derive(Debug, Parser)]
#[command(
    name = "sbom",
    about = "SBOM license attribution and source package management",
    version
)]
struct Cli {
    /// Directory for log files (if not specified, only console logging is used)
    #[arg(long, global = true)]
    log_dir: Option<PathBuf>,

    #[arg(long, default_value = "WARN", global = true)]
    log_level: Option<String>,

    #[arg(long, default_value = "DEBUG", global = true)]
    file_log_level: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Attribution {
        /// Path to SPDX SBOM JSON file
        #[arg(value_name = "SBOM_FILE")]
        sbom: PathBuf,

        /// Output ATTRIBUTION file path
        #[arg(short, long, value_name = "FILE", default_value = "ATTRIBUTION.txt")]
        output: PathBuf,

        /// Use concluded license over declared (default: false)
        #[arg(long, default_value = "false")]
        prefer_concluded: bool,

        /// Verbose output
        #[arg(long, default_value = "false")]
        verbose: bool,
    },

    /// Install Debian packages from deps.json (both build and runtime)
    InstallPackages {
        /// JSON file containing package list
        #[arg(short = 'f', long)]
        deps_file: PathBuf,
    },

    /// Download Debian source packages for installed packages
    DownloadSources {
        /// Package names to download sources for (if not using --deps-file)
        #[arg(conflicts_with = "deps_file")]
        packages: Vec<String>,

        /// JSON file containing package list and options
        #[arg(short = 'f', long, conflicts_with = "packages")]
        deps_file: Option<PathBuf>,

        /// Directory to download source packages to
        #[arg(short, long, default_value = "/distroless/src")]
        output_dir: PathBuf,
    },

    /// Copy package files to distroless container directories
    CopyFiles {
        /// JSON file containing package list and exclusions
        #[arg(short = 'f', long)]
        deps_file: PathBuf,

        /// Base directory for distroless structure
        #[arg(short, long, default_value = "/distroless")]
        distroless_dir: PathBuf,
    },

    /// Create staging directory for SBOM generation
    Stage {
        /// Root filesystem directory (contains base system files)
        #[arg(long, required = true)]
        rootfs: PathBuf,

        /// Application directory (e.g., /app with binaries)
        #[arg(long)]
        app_dir: Option<PathBuf>,

        /// Distroless directory (contains lib, bin, doc, src, dpkg)
        #[arg(long)]
        distroless_dir: Option<PathBuf>,

        /// Additional files/directories to copy (can specify multiple times)
        #[arg(long = "include", value_name = "SRC:DEST")]
        additional_files: Vec<String>,

        /// Output staging directory
        #[arg(short, long, default_value = "/sbom-staging")]
        output: PathBuf,

        /// Syft config file to copy into staging directory
        #[arg(long)]
        syft_config: Option<PathBuf>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let file_env_filter = EnvFilter::builder()
        .parse(
            cli.file_log_level
                .unwrap_or_else(|| "sbom=DEBUG".to_string()),
        )
        .map(|filter| {
            tracing::debug!("Setting file log level to {}", filter);
            filter
        })?;

    let console_env_filter = EnvFilter::builder()
        .parse(cli.log_level.unwrap_or_else(|| "sbom=WARN".to_string()))
        .map(|filter| {
            tracing::debug!("Setting log level to {}", filter);
            filter
        })?;

    let console_layer = tracing_subscriber::fmt::layer()
        .with_ansi(true)
        .with_target(true)
        .with_filter(console_env_filter);

    // Keep the guard alive
    let _guard = if let Some(log_dir) = &cli.log_dir {
        // Enable both console and file logging
        std::fs::create_dir_all(log_dir)
            .with_context(|| format!("Failed to create log directory: {}", log_dir.display()))?;

        let file_appender = tracing_appender::rolling::Builder::new()
            .filename_prefix("sbom")
            .filename_suffix("log")
            .build(log_dir)
            .context("Failed to create file appender")?;

        let (non_blocking_writer, guard) = tracing_appender::non_blocking(file_appender);
        let file_layer = tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .with_target(true)
            .with_writer(non_blocking_writer)
            .with_filter(file_env_filter);

        tracing_subscriber::registry()
            .with(console_layer)
            .with(file_layer)
            .try_init()?;

        Some(guard)
    } else {
        // Console logging only
        tracing_subscriber::registry()
            .with(console_layer)
            .try_init()?;

        None
    };

    match cli.command {
        Commands::Attribution {
            sbom,
            output,
            prefer_concluded,
            verbose: _,
        } => {
            generate_attribution(sbom.as_path(), output.as_path(), prefer_concluded)?;
        }

        Commands::InstallPackages { deps_file } => {
            install_packages(deps_file.as_path())?;
        }

        Commands::DownloadSources {
            packages,
            deps_file,
            output_dir,
        } => {
            if let Some(deps_path) = deps_file {
                download_sources_from_config(deps_path.as_path(), output_dir.as_path())?;
            } else {
                download_sources(&packages, output_dir.as_path(), &HashSet::new())?;
            }
        }

        Commands::CopyFiles {
            deps_file,
            distroless_dir,
        } => {
            copy_files(deps_file.as_path(), distroless_dir.as_path())?;
        }

        Commands::Stage {
            rootfs,
            app_dir,
            distroless_dir,
            additional_files,
            output,
            syft_config,
        } => {
            assemble_staging_directory(
                rootfs.as_path(),
                app_dir.as_deref(),
                distroless_dir.as_deref(),
                additional_files,
                output.as_path(),
                syft_config.as_deref(),
            )?;
        }
    }

    Ok(())
}
