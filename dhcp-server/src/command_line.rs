use clap::{Parser, ValueEnum};

#[derive(Parser, Debug, Clone)]
#[clap(name = "forge-dhcp-server")]
#[clap(author = "Slack channel #swngc-forge-dev")]
pub struct Args {
    #[arg(long, help = "Interface name where to bind this server.")]
    pub interfaces: Vec<String>,

    #[arg(long, help = "DHCP Config file path.")]
    pub dhcp_config: String,

    #[arg(long, help = "DPU Agent provided input file path for IP selection.")]
    pub host_config: Option<String>,

    #[arg(long, help = "FNN config file.")]
    pub fnn_config: Option<String>,

    #[arg(short, long, value_enum, default_value_t=ServerMode::Dpu)]
    pub mode: ServerMode,
}

#[derive(ValueEnum, Clone, Debug)]
pub enum ServerMode {
    Dpu,
    Controller,
    Fnn,
}

impl Args {
    pub fn load() -> Self {
        Self::parse()
    }
}
