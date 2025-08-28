use clap::Parser;
use mlxconfig_embedded::cmd::{run_cli, Cli};

fn main() {
    let cli = Cli::parse();

    if let Err(e) = run_cli(cli) {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}
