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
    collections::HashMap,
    fmt,
    io::{BufRead, Lines, StdinLock},
    str::FromStr,
    time::Duration,
};

use clap::Parser as ClapParser;
use owo_colors::{OwoColorize, Style};

const IGNORED_MSGS: [&str; 3] = [
    "grpc.reflection.v1alpha.ServerReflection",
    "The policy engine denied this request",
    "all auth principals denied by enforcer",
];
const IGNORED_SPANS: &[&str] = &["state_controller_iteration"];

const SPAN_START: &str = "Span:";
const SPAN_END: &str = "----";
const SPAN_ATTRIBUTES: &str = "Attributes:";
const SPAN_EVENTS: &str = "Events:";
const SPAN_LOCATION: &str = "Location:";

const SPAN_ATTR_DATE: &str = "start_time";
const SPAN_ATTR_METHOD: &str = "rpc.method";
const SPAN_ATTR_MACHINE_ID: &str = "forge.machine_id";
const SPAN_ATTR_STATUS_CODE: &str = "rpc.grpc.status_code";
const SPAN_ATTR_STATUS_DESC: &str = "rpc.grpc.status_description";
const SPAN_ATTR_SERVICE: &str = "rpc.service";
const SPAN_ATTR_REQUEST: &str = "request";
const SPAN_ATTR_SQL_QUERIES: &str = "sql_queries";
const SPAN_ATTR_SQL_TIME: &str = "sql_total_query_duration_us";

const NOISE: [&str; 6] = [
    "sql_queries=0 ",
    "sql_total_rows_affected=0 ",
    "sql_total_rows_returned=0 ",
    "sql_max_query_duration_us=0 ",
    "sql_total_query_duration_us=0 ",
    "skipped_iteration=false",
];
const MIN_SQL_DURATION: Duration = Duration::from_millis(10);

#[derive(ClapParser, Debug)]
struct Args {
    /// Print the name of the container?
    #[arg(long, default_value_t = false)]
    container: bool,

    /// Date format
    // This is the input one: "%Y-%m-%dT%H:%M:%S%.6fZ"
    #[arg(long, default_value_t = String::from("%H:%M:%S%.3f"))]
    date_format: String,

    /// Truncate after this many characters
    #[arg(long, default_value_t = 1500)]
    max_length: usize,

    /// Why you no like color?
    #[arg(long, default_value_t = false)]
    nocolor: bool,

    /// Debug - for working on rainbow itself
    #[arg(short, long, default_value_t = false)]
    debug: bool,
}

fn main() -> eyre::Result<()> {
    let args = Args::parse();

    let stdin = std::io::stdin();
    let mut parser = LineParser {
        debug: args.debug,
        lines: stdin.lock().lines(),
        attributes: HashMap::new(),
        in_span: false,
        skip_this_span: false,
        in_attributes: false,
        in_events: false,
    };
    'top: loop {
        let l = parser.next();
        if l.skip {
            continue;
        }
        for st in IGNORED_MSGS {
            if l.message.starts_with(st) || (!l.location.is_empty() && l.location[0] == st) {
                continue 'top;
            }
        }

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
            let mut date = dt.format(&args.date_format).to_string();
            if !args.nocolor {
                date = format!("{}", date.dimmed());
            }
            out.push(date);
        }

        if let Some(level) = l.level {
            let mut s = Style::new();
            if !args.nocolor {
                s = match level {
                    Level::Span => Style::new(),
                    Level::Trace => Style::new(),
                    Level::Debug => Style::new().green(),
                    Level::Info => Style::new().green(),
                    Level::Warn => Style::new().yellow(),
                    Level::Error => Style::new().red(),
                };
            }
            out.push(format!("{:<5}", level.style(s)));
        }

        let mut loc = l.location.join(" ").to_string();
        if !args.nocolor {
            loc = format!("{}", loc.dimmed());
        }
        out.push(loc);

        out.push(truncate(filter(&NOISE, l.message), args.max_length));

        println!("{}", out.join(" "));
    }

    //Ok(())
}

#[derive(Default, Debug)]
struct Log {
    // Skip this line?
    skip: bool,
    // True if we hit a problem parsing the line. In that case we print the whole line as is.
    has_err: bool,
    container: Option<String>,
    dt: Option<chrono::DateTime<chrono::Utc>>,
    level: Option<Level>,
    location: Vec<String>,
    message: String,
}

struct LineParser<'a> {
    debug: bool,
    lines: Lines<StdinLock<'a>>,
    attributes: HashMap<String, String>,
    in_span: bool,
    skip_this_span: bool,
    in_attributes: bool,
    in_events: bool,
}

impl<'a> LineParser<'a> {
    fn next(&mut self) -> Log {
        let Some(Ok(line)) = self.lines.next() else {
            std::process::exit(0); // stdin was closed
        };
        let mut l: Log = Default::default();

        let parts: Vec<&str> = line.split_ascii_whitespace().collect();
        if parts.is_empty() {
            l.skip = true;
            return l;
        }

        let mut idx = 0;

        // Container
        if parts.len() > 2 && parts[1] == "|" {
            l.container = Some(parts[0].to_string());
            idx = 2;
        };

        if parts[idx] == SPAN_START {
            self.skip_this_span = IGNORED_SPANS.contains(&parts[idx + 1]);
            self.in_span = true;
            self.in_attributes = false;
            self.in_events = false;
            l.skip = true;
            return l;
        } else if self.in_span {
            match parts[idx] {
                SPAN_END => {
                    self.in_span = false;
                    self.in_attributes = false;
                    self.in_events = false;

                    if self.skip_this_span {
                        l.skip = true;
                    } else {
                        self.span_to_log(&mut l);
                    }
                    return l;
                }
                SPAN_ATTRIBUTES => {
                    l.skip = true;
                    self.in_attributes = true;
                    self.attributes.clear();
                    return l;
                }
                SPAN_EVENTS | SPAN_LOCATION => {
                    l.skip = true;
                    self.in_attributes = false;
                    self.in_events = true;
                    return l;
                }
                dt if dt.starts_with("202")
                    && parts.len() > idx + 1
                    && parts[idx + 1].parse::<Level>().is_ok() =>
                {
                    // A normal log message that got printed during span printing
                    // Let the rest of the method handle it
                }
                attr => {
                    if self.in_events {
                        // We already printed the event log messages as they appeared
                        l.skip = true;
                    } else if self.in_attributes {
                        // Collect attributes into a map to fold them onto one line
                        let attr_kv: Vec<&str> = attr.split('=').collect();
                        if attr_kv.len() == 1 {
                            if self.debug {
                                eprintln!("ERR parse span attribute: '{attr}'");
                            }
                            l.has_err = true;
                            l.message = line;
                            return l;
                        }
                        l.skip = true;
                        let key = attr_kv[0].to_string();
                        let mut value = attr_kv[1..].join(" ");
                        let rest = remainder(idx + 1, &parts);
                        if !rest.is_empty() {
                            value.push(' ');
                            value += &rest;
                        }
                        self.attributes.insert(key, value);
                    } else {
                        if self.debug {
                            eprintln!("ERR In Span but not in Attributes or Events");
                        }
                        l.has_err = true;
                        l.message = line;
                    }
                    return l;
                }
            }
        }

        if [SPAN_END, SPAN_ATTRIBUTES, SPAN_EVENTS].contains(&parts[idx]) {
            // partial span
            l.skip = true;
            return l;
        }

        self.parse_into(&line, &parts, idx, &mut l);

        l
    }

    fn parse_into(&self, original_line: &str, parts: &[&str], mut idx: usize, l: &mut Log) {
        l.skip = false;

        // Date-time
        let dt = parts[idx].to_string();
        if dt.starts_with("202") {
            l.dt = match dt.parse() {
                Ok(datetime) => Some(datetime),
                Err(err) => {
                    if self.debug {
                        eprintln!("ERR parse date: '{dt}'. {err}.");
                    }
                    l.has_err = true;
                    l.message = original_line.to_string();
                    return;
                }
            };
        } else {
            l.message = dt;
            l.message.push(' ');
            let rest = remainder(idx + 1, parts);
            l.message.push_str(&rest);
            return;
        }
        idx += 1;

        // Level
        let level = if parts.len() > idx {
            parts[idx].to_string()
        } else {
            return;
        };
        l.level = match level.parse() {
            Ok(level) => Some(level),
            Err(err) => {
                if self.debug {
                    eprintln!("ERR parsing level: {err}");
                }
                l.has_err = true;
                l.message = original_line.to_string();
                return;
            }
        };
        idx += 1;

        // Location
        loop {
            if parts.len() <= idx {
                return;
            }
            let location = parts[idx];
            // If we just look for an ending ':', then this all looks like location, when the last part is
            // actually part of the message. So check if something is unlikely to be a location.
            // The log format is not really machine parseable.
            //
            // > forge_host_support::hardware_enumeration: host-support/src/hardware_enumeration.rs:307: Some({"vendor_id":
            //
            if location.ends_with(':') && !location.contains(['(', '{', '"']) {
                l.location
                    .push(location.strip_suffix(':').unwrap().to_string());
                idx += 1;
            } else {
                break;
            }
        }

        // The actual message
        l.message = remainder(idx, parts);
    }

    // Convert a collected span to a displayable log entry
    fn span_to_log(&mut self, l: &mut Log) {
        l.skip = false;

        if let Some(dt) = self.attributes.remove(SPAN_ATTR_DATE) {
            l.dt = Some(dt.parse().unwrap());
        }

        l.location = vec![];
        if let Some(service) = self.attributes.remove(SPAN_ATTR_SERVICE) {
            if service != "forge.Forge" {
                l.location.push(service);
            }
        }
        if let Some(location) = self.attributes.remove(SPAN_ATTR_METHOD) {
            l.location.push(location);
        }
        if let Some(machine_id) = self.attributes.remove(SPAN_ATTR_MACHINE_ID) {
            l.location.push(machine_id);
        }

        if let Some(request) = self.attributes.remove(SPAN_ATTR_REQUEST) {
            l.message = request;
        }

        l.level = Some(Level::Span);
        if let Some(status_code) = self.attributes.remove(SPAN_ATTR_STATUS_CODE) {
            if status_code != "0" {
                l.level = Some(Level::Warn);
                l.message += &format!(
                    " grpc.status_code:{} {}",
                    status_code,
                    self.attributes
                        .remove(SPAN_ATTR_STATUS_DESC)
                        .unwrap_or_default()
                );
            }
        }

        if let Some(sql_queries) = self.attributes.remove(SPAN_ATTR_SQL_QUERIES) {
            let count: usize = sql_queries.parse().unwrap();
            if count > 10 {
                l.message += &format!(" {SPAN_ATTR_SQL_QUERIES}={count}");
            }
        }
        if let Some(sql_time) = self.attributes.remove(SPAN_ATTR_SQL_TIME) {
            let d: Duration = Duration::from_nanos(sql_time.parse::<u64>().unwrap());
            if d > MIN_SQL_DURATION {
                l.message += &format!(" sql_time={d:?}");
            }
        }
    }
}

fn remainder(idx: usize, parts: &[&str]) -> String {
    if parts.len() > idx {
        parts[idx..].join(" ")
    } else {
        "".to_string()
    }
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

fn truncate(mut s: String, max_chars: usize) -> String {
    if s.len() <= max_chars {
        // shortcut for ascii that's already short enough - 99%+ of calls
        return s;
    }
    let (idx, _) = s.char_indices().nth(max_chars).unwrap();
    s.truncate(idx);
    s += "...";
    s
}

fn filter(remove: &[&str], mut s: String) -> String {
    for n in remove {
        s = s.replace(n, "");
    }
    s
}
