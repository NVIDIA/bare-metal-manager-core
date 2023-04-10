/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use std::{
    fmt,
    io::BufRead,
    str::{FromStr, SplitAsciiWhitespace},
};

use clap::Parser;
use owo_colors::{OwoColorize, Style};

#[derive(Parser, Debug)]
struct Args {
    /// Print the name of the container?
    #[arg(long, default_value_t = false)]
    container: bool,

    /// Date format
    // This is the input one: "%Y-%m-%dT%H:%M:%S%.6fZ"
    #[arg(long, default_value_t = String::from("%H:%M:%S%.3f"))]
    date_format: String,

    /// Debug - for working on rainbow itself
    #[arg(short, long, default_value_t = false)]
    debug: bool,
}

fn main() -> eyre::Result<()> {
    let args = Args::parse();

    let stdin = std::io::stdin();
    for line in stdin.lock().lines() {
        let line = line.unwrap();
        let l = parse(line, args.debug);

        if l.has_err {
            println!("{}", l.message);
            continue;
        }

        let mut out = Vec::new();
        if args.container && l.container.is_some() {
            out.push(format!("{:<34}", l.container.unwrap()));
            out.push("|".to_string());
        }

        if let Some(dt) = l.dt {
            out.push(format!("{}", dt.format(&args.date_format).dimmed()));
        }

        if let Some(level) = l.level {
            let s = match level {
                Level::Span => Style::new(),
                Level::Trace => Style::new(),
                Level::Debug => Style::new().green(),
                Level::Info => Style::new().green(),
                Level::Warn => Style::new().yellow(),
                Level::Error => Style::new().red(),
            };
            out.push(format!("{:<5}", level.style(s)));
        }

        out.push(format!("{}", l.location.join(" ").dimmed()));

        out.push(l.message);

        println!("{}", out.join(" "));
    }

    Ok(())
}

#[derive(Default, Debug)]
struct Log {
    // True if we hit a problem parsing the line. In that case we print the whole line as is.
    has_err: bool,
    container: Option<String>,
    dt: Option<chrono::DateTime<chrono::Utc>>,
    level: Option<Level>,
    location: Vec<String>,
    message: String,
}

fn parse(line: String, is_debug: bool) -> Log {
    let mut l: Log = Default::default();
    let mut parts = line.split_ascii_whitespace();

    // Container
    let container = parts.next();
    let divider = parts.next();
    if divider != Some("|") {
        if is_debug {
            eprintln!("ERR Missing docker compose prefix:");
        }
        l.has_err = true;
        l.message = line;
        return l;
    }
    l.container = container.map(|s| s.to_string());

    // Date-time
    let dt = parts.next().map(|s| s.to_string());
    match dt {
        Some(dt) if dt.starts_with("202") => {
            l.dt = match dt.parse() {
                Ok(datetime) => Some(datetime),
                Err(err) => {
                    if is_debug {
                        eprintln!("ERR parse date: '{dt}'. {err}.");
                    }
                    l.has_err = true;
                    l.message = line;
                    return l;
                }
            }
        }
        Some(other) => {
            l.message = other;
            l.message.push(' ');
            let rest = remainder(parts);
            l.message.push_str(&rest);
            return l;
        }
        None => {
            l.message = remainder(parts);
            return l;
        }
    }

    // Level
    let level = match parts.next().map(|s| s.to_string()) {
        Some(level) => level,
        None => {
            let rest = remainder(parts);
            l.message.push_str(&rest);
            return l;
        }
    };
    l.level = match level.parse() {
        Ok(level) => Some(level),
        Err(err) => {
            if is_debug {
                eprintln!("ERR parsing level: {err}");
            }
            l.has_err = true;
            l.message = line;
            return l;
        }
    };

    // Location
    let next_part = loop {
        let loc = parts.next();
        match loc {
            Some(location) if location.ends_with(':') => {
                l.location
                    .push(location.strip_suffix(':').unwrap().to_string());
            }
            Some(other) => {
                break other;
            }
            None => {
                l.message = remainder(parts);
                return l;
            }
        }
    };

    // Rest of message - the actual message

    l.message = next_part.to_string();
    l.message.push(' ');

    let rest = remainder(parts);
    l.message.push_str(&rest);

    l
}

// Nightly has a `remainder` method that will replace this once it goes stable
fn remainder(parts: SplitAsciiWhitespace) -> String {
    parts.collect::<Vec<&str>>().join(" ")
}

// Very similar to Log::Level (enum) or tracing::Level (struct) plus Span level for open telemetry
#[derive(Debug)]
enum Level {
    Span,
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl FromStr for Level {
    type Err = eyre::Report;
    fn from_str(s: &str) -> Result<Level, Self::Err> {
        match s {
            "SPAN" => Ok(Self::Span),
            "TRACE" => Ok(Self::Trace),
            "DEBUG" => Ok(Self::Debug),
            "INFO" => Ok(Self::Info),
            "WARN" => Ok(Self::Warn),
            "ERROR" => Ok(Self::Error),
            x => Err(eyre::eyre!("Invalid log level '{x}'")),
        }
    }
}

impl fmt::Display for Level {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Span => f.pad("SPAN"),
            Self::Trace => f.pad("TRACE"),
            Self::Debug => f.pad("DEBUG"),
            Self::Info => f.pad("INFO"),
            Self::Warn => f.pad("WARN"),
            Self::Error => f.pad("ERROR"),
        }
    }
}
