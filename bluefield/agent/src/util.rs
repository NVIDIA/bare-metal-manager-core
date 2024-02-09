#![allow(dead_code)]
// this stuff is used in tests and isn't actually dead

use std::{
    fmt::Write,
    net::{IpAddr, Ipv4Addr},
    str::FromStr,
    time::Duration,
};

use diff::Result as DiffResult;
use forge_http_connector::resolver::{ForgeResolver, ForgeResolverOpts};
use hickory_resolver::{config::ResolverConfig, Name};
use resolv_conf::Config;
use rpc::forge_resolver::{self};
use tower::Service;

pub fn compare_lines(left: &str, right: &str, strip_behavior: Option<StripType>) -> CompareResult {
    let (left, right) = match strip_behavior {
        None => (left, right),
        Some(_) => unreachable!(),
    };
    let results = diff::lines(left, right);
    let identical = results
        .iter()
        .all(|r| matches!(r, diff::Result::Both(_, _)));
    match identical {
        true => CompareResult::Identical,
        false => {
            let mut report = String::new();
            results.into_iter().for_each(|r| {
                let (col1, linecontent) = match r {
                    DiffResult::Both(line, _) => (' ', line),
                    DiffResult::Left(line) => ('-', line),
                    DiffResult::Right(line) => ('+', line),
                };
                writeln!(&mut report, "{col1}{linecontent}").expect("can't write line to results?");
            });
            CompareResult::Different(report)
        }
    }
}

pub enum CompareResult {
    Identical,
    Different(String),
}

impl CompareResult {
    pub fn report(&self) -> &str {
        match self {
            CompareResult::Identical => "",
            CompareResult::Different(s) => s.as_str(),
        }
    }

    pub fn is_identical(&self) -> bool {
        matches!(self, CompareResult::Identical)
    }
}

pub enum StripType {}

pub struct UrlResolver {
    nameservers: Vec<IpAddr>,
    resolver: ForgeResolver,
}

impl UrlResolver {
    pub fn try_new() -> Result<Self, eyre::Report> {
        let config = Self::try_get_resolver_config()?;
        let nameservers = config
            .nameservers
            .iter()
            .map(|x| x.into())
            .collect::<Vec<IpAddr>>();

        let resolver = Self::try_get_resolver(config)?;
        Ok(Self {
            nameservers,
            resolver,
        })
    }
    pub fn nameservers(&self) -> Vec<IpAddr> {
        self.nameservers.clone()
    }

    fn try_get_resolver_config() -> Result<Config, eyre::Report> {
        let forge_resolv_config =
            forge_resolver::resolver::ForgeResolveConf::with_system_resolv_conf()?;
        let parsed_config = forge_resolv_config.parsed_configuration();
        Ok(parsed_config)
    }

    fn try_get_resolver(resolver_config: Config) -> Result<ForgeResolver, eyre::Report> {
        let forge_resolver_config =
            forge_resolver::resolver::into_forge_resolver_config(resolver_config)?;

        let hickory_resolver_config = ResolverConfig::from_parts(
            forge_resolver_config.0.domain,
            forge_resolver_config.0.search_domain,
            forge_resolver_config.0.inner.into_inner(),
        );

        let updated_opts = ForgeResolverOpts::new()
            .use_mgmt_vrf()
            .timeout(Duration::from_secs(5));
        let resolver_cfg =
            ForgeResolver::with_config_and_options(hickory_resolver_config, updated_opts);

        Ok(resolver_cfg)
    }

    /// Input name should be hostname, not url.
    /// valid: carbide-pxe.forge, nvidia.com, www.nvidia.com
    /// Invalid: https://www.nvidia.com/extra/uri
    pub async fn resolve(&mut self, name: &str) -> Result<Vec<Ipv4Addr>, eyre::Report> {
        let ip = self
            .resolver
            .call(Name::from_str(name)?)
            .await?
            .filter_map(|x| match x.ip() {
                IpAddr::V4(x) => Some(x),
                _ => None,
            })
            .collect::<Vec<Ipv4Addr>>();

        Ok(ip)
    }
}
