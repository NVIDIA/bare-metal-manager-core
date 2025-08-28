use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Debug, Clone, ValueEnum, Default)]
pub enum OutputFormat {
    #[default]
    Table,
    Json,
    Yaml,
}

#[derive(Parser)]
#[command(name = "mlx-config")]
#[command(about = "MLX Hardware Configuration System")]
#[command(version = "0.0.1")]
#[command(author = "MLX Team")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Show version information
    Version,
    /// Registry management commands
    Registry {
        #[command(subcommand)]
        action: RegistryAction,
    },
}

#[derive(Subcommand)]
pub enum RegistryAction {
    /// Generate a registry YAML file from show_confs output
    Generate {
        /// Input file containing show_confs output
        input_file: PathBuf,
        /// Output file (stdout if not specified)
        #[arg(short, long)]
        out_file: Option<PathBuf>,
    },
    /// Validate a registry YAML file
    Validate {
        /// YAML file to validate
        yaml_file: PathBuf,
    },
    /// List all available registry names
    List,
    /// Show details about a specific registry
    Show {
        /// Name of the registry to show
        registry_name: String,
        /// Output format
        #[arg(short, long, default_value = "table")]
        output: OutputFormat,
    },
    /// Check if device info is compatible with a registry
    Check {
        /// Name of the registry to check against
        registry_name: String,
        /// Device type (e.g., "Bluefield3", "ConnectX-7")
        #[arg(long)]
        device_type: Option<String>,
        /// Part number (e.g., "900-9D3D4-00EN-HA0")
        #[arg(long)]
        part_number: Option<String>,
        /// Firmware version (e.g., "32.41.130")
        #[arg(long)]
        fw_version: Option<String>,
    },
}
