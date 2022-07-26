// extern crate core;

mod cfg;
mod discovery;
mod done;
mod ipmi;

use cfg::{Command, Options};
use log::LevelFilter;

use once_cell::sync::Lazy;
use std::sync::RwLock;

struct DevEnv {
    in_qemu: bool,
}
static IN_QEMU_VM: Lazy<RwLock<DevEnv>> = Lazy::new(|| RwLock::new(DevEnv { in_qemu: false }));

fn check_if_running_in_qemu() {
    use std::process::Command;
    let output = match Command::new("systemd-detect-virt").output() {
        Ok(s) => s,
        Err(_) => {
            // Not sure. But if above command is not present,
            // assume it real machine.
            return;
        }
    };

    if let Ok(x) = String::from_utf8(output.stdout) {
        if x.trim() != "none" {
            IN_QEMU_VM.write().unwrap().in_qemu = true; // Not sure. But if above command is not present,
        }
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), color_eyre::Report> {
    color_eyre::install()?;

    let config = Options::load();
    check_if_running_in_qemu();

    pretty_env_logger::formatted_timed_builder()
        .filter_level(match config.debug {
            0 => LevelFilter::Info,
            1 => {
                // command line overrides config file
                std::env::set_var("RUST_BACKTRACE", "1");
                LevelFilter::Debug
            }
            _ => {
                std::env::set_var("RUST_BACKTRACE", "1");
                LevelFilter::Trace
            }
        })
        .init();

    match config.subcmd {
        Command::Discovery(d) => {
            discovery::Discovery::run(config.listen, &d.uuid).await?;
        }
        Command::Done(d) => {
            done::Done::run(config.listen, &d.uuid).await?;
        }
    }
    Ok(())
}
