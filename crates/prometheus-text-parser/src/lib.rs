/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
use std::collections::BTreeMap;
use std::str::FromStr;

static HELP_PREFIX: &str = "# HELP ";
static TYPE_PREFIX: &str = "# TYPE ";

/// [`ParsedPrometheusMetrics`] provides a way to read in the output from prometheus's TextEncoder
/// and get a strongly-typed value representing its contents. It also has a [`PartialEq`]
/// implementation which ignores fields which are likely to change between test runs, suitable for
/// using [`assert_eq!`] to compare with the result of a fixture.
#[derive(PartialEq, Debug, Clone)]
pub struct ParsedPrometheusMetrics {
    pub metrics: BTreeMap<String, Metric>,
}

impl ParsedPrometheusMetrics {
    /// Call this to rewrite the values of any attributes seen in these metrics
    pub fn rewriting_attribute_values<F: Fn(&String, &String) -> Option<String>>(
        mut self,
        f: F,
    ) -> Self {
        for metric in self.metrics.values_mut() {
            if let MetricKind::Gauge(g) | MetricKind::Counter(g) = &mut metric.kind {
                for observation in &mut g.observations {
                    for (attr_key, attr_value) in observation.attributes.0.iter_mut() {
                        if let Some(new_val) = f(attr_key, attr_value) {
                            *attr_value = new_val
                        }
                    }
                }
            }
        }

        self
    }

    /// Convenience function this to rewrite any known build attributes to known values, like
    /// build_date, build_hostname, etc.
    pub fn scrub_build_attributes(self) -> Self {
        self.rewriting_attribute_values(|key, _| match key.as_str() {
            "build_date" => Some("DATE".to_string()),
            "build_hostname" => Some("HOSTNAME".to_string()),
            "build_user" => Some("USER".to_string()),
            "build_version" => Some("VERSION".to_string()),
            "git_sha" => Some("SHA".to_string()),
            "rust_version" => Some("RUST_VERSION".to_string()),
            _ => None,
        })
    }
}

impl FromStr for ParsedPrometheusMetrics {
    type Err = MetricsParsingError;

    fn from_str(s: &str) -> Result<Self> {
        enum ParseState {
            Init,
            MetricHeader(UnknownMetric),
        }

        let mut metrics = BTreeMap::new();
        let mut parse_state = ParseState::Init;

        for line in s.lines() {
            if line.starts_with(HELP_PREFIX) {
                parse_state = ParseState::MetricHeader(UnknownMetric::from_help_line(line)?);
            } else if line.starts_with(TYPE_PREFIX) {
                let ParseState::MetricHeader(unknown_metric) = parse_state else {
                    return Err(MetricsParsingError::UnexpectedTypeLine(line.to_string()));
                };
                let metric = unknown_metric.promote(line)?;
                metrics.insert(metric.name.clone(), metric);
                parse_state = ParseState::Init;
            } else if line.starts_with("# ") {
                continue;
            } else if !line.is_empty() {
                parse_metric_line(line, &mut metrics)?;
            }
        }

        Ok(Self { metrics })
    }
}

#[derive(thiserror::Error, Debug)]
pub enum MetricsParsingError {
    #[error("Invalid HELP line: {0}")]
    InvalidHelpLine(String),
    #[error("Unexpected TYPE line: {0}")]
    UnexpectedTypeLine(String),
    #[error("Unexpected metric definition with no preceding TYPE/HELP line: {0}")]
    UnexpectedDefLine(String),
    #[error("Metric definition wrong name from TYPE line: {0}")]
    DefLineMismatch(String),
    #[error(
        "Metric name mismatch: HELP line is for metric {help_name} but TYPE line is for {type_name}"
    )]
    NameMismatch {
        help_name: String,
        type_name: String,
    },
    #[error("Unknown metric type {metric_type} for metric {metric_name}")]
    UnknownMetricType {
        metric_name: String,
        metric_type: String,
    },
    #[error("Invalid bucket line {0}")]
    InvalidBucketLine(String),
    #[error("Invalid value {0}")]
    InvalidValue(String),
    #[error("Invalid attributes string: {0}")]
    InvalidAttributes(String),
    #[error("Invalid metric line: {0}")]
    InvalidMetricLine(String),
    #[error("Metric line is for metric we have not seen a HELP or TYPE for yet: {0}")]
    UnknownMetricLine(String),
}

type Result<T> = std::result::Result<T, MetricsParsingError>;

struct UnknownMetric {
    name: String,
    help: String,
}

impl UnknownMetric {
    fn from_help_line(s: &str) -> Result<Self> {
        let (name, help) = s
            .strip_prefix(HELP_PREFIX)
            .unwrap()
            .split_once(" ")
            .ok_or(MetricsParsingError::InvalidHelpLine(s.to_string()))?;

        Ok(Self {
            name: name.to_string(),
            help: help.to_string(),
        })
    }
}

impl UnknownMetric {
    fn promote(self, type_line: &str) -> Result<Metric> {
        let (name, type_str) = {
            let parts = type_line
                .strip_prefix(TYPE_PREFIX)
                .unwrap()
                .splitn(2, " ")
                .collect::<Vec<&str>>();
            (parts[0], parts[1])
        };
        if name != self.name {
            return Err(MetricsParsingError::NameMismatch {
                help_name: self.name,
                type_name: type_str.to_string(),
            });
        }

        let kind = match type_str {
            "histogram" => Ok(MetricKind::Histogram(Histogram {
                name: name.to_string(),
                ..Default::default()
            })),
            "gauge" => Ok(MetricKind::Gauge(CounterOrGauge {
                name: name.to_string(),
                ..Default::default()
            })),
            "counter" => Ok(MetricKind::Counter(CounterOrGauge {
                name: name.to_string(),
                ..Default::default()
            })),
            unknown => Err(MetricsParsingError::UnknownMetricType {
                metric_name: name.to_string(),
                metric_type: unknown.to_string(),
            }),
        }?;

        Ok(Metric {
            name: self.name,
            help: self.help,
            kind,
        })
    }
}

#[derive(PartialEq, Debug, Clone)]
pub struct Metric {
    pub name: String,
    pub help: String,
    pub kind: MetricKind,
}

fn parse_metric_line(line: &str, metrics: &mut BTreeMap<String, Metric>) -> Result<()> {
    let metric_name = if line.contains('{') {
        &line[..line.find('{').unwrap()]
    } else if let Some(idx) = line.find(' ') {
        &line[..idx]
    } else {
        return Err(MetricsParsingError::InvalidMetricLine(line.to_string()));
    };

    let metric = if let Some(metric) = metrics.get_mut(metric_name) {
        metric
    } else {
        // Prometheus uses _bucket, _count, and _sum suffexes for histograms, find the actual metric name
        let without_suffix = if let Some(stripped) = metric_name.strip_suffix("_bucket") {
            stripped
        } else if let Some(stripped) = metric_name.strip_suffix("_count") {
            stripped
        } else if let Some(stripped) = metric_name.strip_suffix("_sum") {
            stripped
        } else {
            metric_name
        };

        if let Some(metric) = metrics.get_mut(without_suffix) {
            metric
        } else {
            return Err(MetricsParsingError::UnknownMetricLine(line.to_string()));
        }
    };
    metric.parse_line(line)?;
    Ok(())
}

impl Metric {
    fn parse_line(&mut self, line: &str) -> Result<()> {
        self.kind.parse_line(line, &self.name)?;

        Ok(())
    }

    pub fn observations(&self) -> Option<&[Observation<u64>]> {
        match &self.kind {
            MetricKind::Histogram(_) => None,
            MetricKind::Gauge(c) | MetricKind::Counter(c) => Some(c.observations.as_slice()),
        }
    }
}

#[derive(PartialEq, Debug, Clone)]
pub enum MetricKind {
    Histogram(Histogram),
    Gauge(CounterOrGauge),
    Counter(CounterOrGauge),
}

impl MetricKind {
    fn parse_line(&mut self, line: &str, metric_name: &str) -> Result<()> {
        match self {
            MetricKind::Histogram(histogram) => {
                let hist_def = line
                    .strip_prefix(&format!("{metric_name}_"))
                    .ok_or(MetricsParsingError::DefLineMismatch(line.to_string()))?;
                if let Some(bucket_def) = hist_def.strip_prefix("bucket") {
                    histogram.parse_bucket_def(bucket_def)?
                } else if let Some(sum) = hist_def.strip_prefix("sum ") {
                    histogram.sum = sum
                        .parse()
                        .map_err(|_| MetricsParsingError::InvalidValue(line.to_string()))?;
                } else if let Some(count) = hist_def.strip_prefix("count ") {
                    histogram.count = count
                        .parse()
                        .map_err(|_| MetricsParsingError::InvalidValue(line.to_string()))?;
                }
            }
            MetricKind::Gauge(gauge) | MetricKind::Counter(gauge) => {
                let gauge_def = line
                    .strip_prefix(metric_name)
                    .ok_or(MetricsParsingError::DefLineMismatch(line.to_string()))?;

                gauge.parse_gauge_def(gauge_def)?
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct Histogram {
    name: String,
    buckets: Vec<Bucket>,
    sum: f64,
    count: u64,
}

impl PartialEq for Histogram {
    fn eq(&self, other: &Histogram) -> bool {
        // Ignore sum when comparing to expected metrics
        self.name == other.name && self.buckets == other.buckets && self.count == other.count
    }
}

impl Histogram {
    /// Parses a bucket definition substring, e.g: `{le="100"} 5`
    fn parse_bucket_def(&mut self, bucket_def: &str) -> Result<()> {
        let (attrs, val) =
            bucket_def
                .split_once(" ")
                .ok_or(MetricsParsingError::InvalidBucketLine(
                    bucket_def.to_string(),
                ))?;
        let attributes: Attributes = attrs.parse()?;
        let count: u64 = val
            .parse()
            .map_err(|_| MetricsParsingError::InvalidValue(val.to_string()))?;
        self.buckets.push(Bucket { count, attributes });
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct Bucket {
    pub count: u64,
    pub attributes: Attributes,
}

impl PartialEq for Bucket {
    fn eq(&self, other: &Self) -> bool {
        // Ignore count when comparing to expected metrics
        self.attributes == other.attributes
    }
}

#[derive(PartialEq, Debug, Clone)]
pub struct Attributes(pub BTreeMap<String, String>);

impl FromStr for Attributes {
    type Err = MetricsParsingError;

    /// Parse an attributes substring, e.g. `{le="100"}`
    fn from_str(s: &str) -> Result<Self> {
        // strip '{' and '}'
        let stripped = s
            .strip_prefix('{')
            .ok_or(MetricsParsingError::InvalidAttributes(s.to_string()))?
            .strip_suffix('}')
            .ok_or(MetricsParsingError::InvalidAttributes(s.to_string()))?;

        let attrs: BTreeMap<String, String> = stripped
            .split(",")
            .map(|attr| {
                let (key, value) = attr
                    .split_once("=")
                    .ok_or(MetricsParsingError::InvalidAttributes(s.to_string()))?;
                Ok((key.to_string(), value.to_string()))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;

        Ok(Attributes(attrs))
    }
}

#[derive(PartialEq, Debug, Clone, Default)]
pub struct CounterOrGauge {
    pub name: String,
    pub observations: Vec<Observation<u64>>,
}

impl CounterOrGauge {
    fn parse_gauge_def(&mut self, gauge_def: &str) -> Result<()> {
        let (attributes, val) = if gauge_def.starts_with("{") {
            let mut components = gauge_def.strip_prefix("{").unwrap().splitn(2, "} ");
            (
                format!("{{{}}}", components.next().unwrap()).parse()?,
                components.next().unwrap(),
            )
        } else {
            (
                Attributes(BTreeMap::new()),
                gauge_def
                    .strip_prefix(" ")
                    .ok_or(MetricsParsingError::InvalidValue(gauge_def.to_string()))?,
            )
        };

        let value: u64 = val
            .parse()
            .map_err(|_| MetricsParsingError::InvalidValue(val.to_string()))?;

        self.observations.push(Observation { value, attributes });
        Ok(())
    }
}

#[derive(PartialEq, Debug, Clone)]
pub struct Observation<T> {
    pub value: T,
    pub attributes: Attributes,
}
