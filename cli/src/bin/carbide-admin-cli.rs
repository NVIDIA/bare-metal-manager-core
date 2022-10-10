/*
 * SPDX-FileCopyrightText: Copyright (c) 2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
mod carbide_admin_cli;

use carbide_admin_cli::cfg::carbide_options::{CarbideCommand, CarbideOptions, Machine};
use log::LevelFilter;
use serde::Deserialize;

use std::env;
use std::error::Error;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;

#[derive(Debug, Deserialize)]
struct Config {
    carbide_api_url: Option<String>,
}

fn get_carbide_api_url(carbide_api: Option<String>, config: Option<Config>) -> String {
    // First from command line, second env var.
    if let Some(carbide_api) = carbide_api {
        return carbide_api;
    }

    // Third config file
    if let Some(config) = config {
        if let Some(carbide_api_url) = config.carbide_api_url {
            return carbide_api_url;
        }
    }

    panic!(
        r#"Unknown CARBIDE_API_URL. Set (will be read in same sequence.)
           1. --carbide_api/-c flag or 
           2. environment variable CARBIDE_API_URL or 
           3. add carbide_api_url in $HOME/.config/carbide_api_cli.json."#
    )
}

fn get_config_from_file() -> Option<Config> {
    // Third config file
    if let Ok(home) = env::var("HOME") {
        let file = Path::new(&home).join(".config/carbide_api_cli.json");
        if file.exists() {
            let file = File::open(file).unwrap();
            let reader = BufReader::new(file);
            let config: Config = serde_json::from_reader(reader).unwrap();

            return Some(config);
        }
    }

    None
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    color_eyre::install()?;

    let config = CarbideOptions::load();
    let file_config = get_config_from_file();

    pretty_env_logger::formatted_timed_builder()
        .filter_level(match config.debug {
            0 => LevelFilter::Info,
            1 => {
                // command line overrides config file
                LevelFilter::Debug
            }
            _ => LevelFilter::Trace,
        })
        .init();

    std::env::set_var("RUST_BACKTRACE", "1");
    let carbide_api = get_carbide_api_url(config.carbide_api, file_config);

    match config.commands {
        CarbideCommand::Machine(machine) => match machine {
            Machine::Show(machine) => {
                carbide_admin_cli::machine::handle_show(machine, config.json, carbide_api).await?
            }
        },
        CarbideCommand::Instance(_instance) => {
            todo!();
        }
    }

    Ok(())
}
