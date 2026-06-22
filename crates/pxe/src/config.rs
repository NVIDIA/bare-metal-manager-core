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
use std::env;
use std::net::IpAddr;

#[derive(Clone, Debug)]
pub(crate) struct RuntimeConfig {
    pub internal_api_url: String,
    pub client_facing_api_url: String,
    pub pxe_url: String,
    pub static_pxe_url: String,
    pub forge_root_ca_path: String,
    pub server_cert_path: String,
    pub server_key_path: String,
    pub bind_address: IpAddr,
    pub bind_port: u16,
    pub template_directory: String,
}

impl RuntimeConfig {
    pub(crate) fn from_env() -> Result<Self, String> {
        let carbide_pxe_url =
            env::var("CARBIDE_PXE_URL").unwrap_or_else(|_| "http://carbide-pxe.forge".to_string());
        let this = Self {
            internal_api_url: env::var("CARBIDE_API_INTERNAL_URL").unwrap_or_else(|_| {
                "https://carbide-api.forge-system.svc.cluster.local:1079".to_string()
            }),
            client_facing_api_url: env::var("CARBIDE_API_URL")
                .unwrap_or_else(|_| "https://carbide-api.forge".to_string()),
            pxe_url: carbide_pxe_url.clone(),
            static_pxe_url: env::var("CARBIDE_STATIC_PXE_URL").unwrap_or(carbide_pxe_url),
            forge_root_ca_path: env::var("FORGE_ROOT_CAFILE_PATH").map_err(|_| {
                "Could not extract FORGE_ROOT_CAFILE_PATH from environment".to_string()
            })?,
            server_cert_path: env::var("FORGE_CLIENT_CERT_PATH").map_err(|_| {
                "Could not extract FORGE_CLIENT_CERT_PATH from environment".to_string()
            })?,
            server_key_path: env::var("FORGE_CLIENT_KEY_PATH").map_err(|_| {
                "Could not extract FORGE_CLIENT_KEY_PATH from environment".to_string()
            })?,
            bind_address: env::var("PXE_BIND_ADDRESS")
                .unwrap_or_else(|_| "0.0.0.0".to_string())
                .parse()
                .map_err(|_| "not a parsable bind address for runtime config?".to_string())?,
            bind_port: env::var("PXE_BIND_PORT")
                .unwrap_or_else(|_| "8080".to_string())
                .parse::<u16>()
                .map_err(|_| "not a parsable bind port for runtime config?".to_string())?,
            template_directory: env::var("CARBIDE_PXE_TEMPLATE_DIRECTORY")
                .unwrap_or_else(|_| "/opt/carbide/pxe/templates".to_string()),
        };

        Ok(this)
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::sync::Mutex;

    use carbide_test_support::Outcome::*;
    use carbide_test_support::scenarios;

    use super::*;

    static ENV_LOCK: Mutex<()> = Mutex::new(());
    const RUNTIME_CONFIG_ENV_KEYS: &[&str] = &[
        "CARBIDE_PXE_URL",
        "CARBIDE_API_INTERNAL_URL",
        "CARBIDE_API_URL",
        "CARBIDE_STATIC_PXE_URL",
        "FORGE_ROOT_CAFILE_PATH",
        "FORGE_CLIENT_CERT_PATH",
        "FORGE_CLIENT_KEY_PATH",
        "PXE_BIND_ADDRESS",
        "PXE_BIND_PORT",
        "CARBIDE_PXE_TEMPLATE_DIRECTORY",
    ];

    #[derive(Debug)]
    struct ConfigEnv {
        vars: &'static [(&'static str, &'static str)],
    }

    #[derive(Debug, PartialEq)]
    struct RuntimeConfigSummary {
        internal_api_url: String,
        client_facing_api_url: String,
        pxe_url: String,
        static_pxe_url: String,
        forge_root_ca_path: String,
        server_cert_path: String,
        server_key_path: String,
        bind_address: IpAddr,
        bind_port: u16,
        template_directory: String,
    }

    struct EnvSnapshot {
        values: Vec<(&'static str, Option<String>)>,
    }

    impl EnvSnapshot {
        fn capture(keys: &[&'static str]) -> Self {
            Self {
                values: keys.iter().map(|key| (*key, env::var(key).ok())).collect(),
            }
        }
    }

    impl Drop for EnvSnapshot {
        fn drop(&mut self) {
            for (key, value) in &self.values {
                match value {
                    Some(value) => set_env(key, value),
                    None => remove_env(key),
                }
            }
        }
    }

    fn set_env(key: &str, value: &str) {
        // SAFETY: these tests hold ENV_LOCK while mutating process environment.
        unsafe { env::set_var(key, value) }
    }

    fn remove_env(key: &str) {
        // SAFETY: these tests hold ENV_LOCK while mutating process environment.
        unsafe { env::remove_var(key) }
    }

    fn clear_env(keys: &[&str]) {
        for key in keys {
            remove_env(key);
        }
    }

    fn summarize_config(config: RuntimeConfig) -> RuntimeConfigSummary {
        RuntimeConfigSummary {
            internal_api_url: config.internal_api_url,
            client_facing_api_url: config.client_facing_api_url,
            pxe_url: config.pxe_url,
            static_pxe_url: config.static_pxe_url,
            forge_root_ca_path: config.forge_root_ca_path,
            server_cert_path: config.server_cert_path,
            server_key_path: config.server_key_path,
            bind_address: config.bind_address,
            bind_port: config.bind_port,
            template_directory: config.template_directory,
        }
    }

    /// Caller must hold `ENV_LOCK` before invoking this function.
    fn runtime_config_from_env(input: ConfigEnv) -> Result<RuntimeConfigSummary, &'static str> {
        clear_env(RUNTIME_CONFIG_ENV_KEYS);
        for (key, value) in input.vars {
            set_env(key, value);
        }
        RuntimeConfig::from_env()
            .map(summarize_config)
            .map_err(config_error_kind)
    }

    fn config_error_kind(error: String) -> &'static str {
        match error.as_str() {
            "Could not extract FORGE_ROOT_CAFILE_PATH from environment" => "missing-root-ca",
            "Could not extract FORGE_CLIENT_CERT_PATH from environment" => "missing-client-cert",
            "Could not extract FORGE_CLIENT_KEY_PATH from environment" => "missing-client-key",
            "not a parsable bind address for runtime config?" => "bad-bind-address",
            "not a parsable bind port for runtime config?" => "bad-bind-port",
            other => panic!("unmapped runtime config error: {other:?}"),
        }
    }

    #[test]
    fn builds_runtime_config_from_environment() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let _snapshot = EnvSnapshot::capture(RUNTIME_CONFIG_ENV_KEYS);

        scenarios!(
            run = runtime_config_from_env;
            "required values with defaults" {
                ConfigEnv {
                    vars: &[
                        ("FORGE_ROOT_CAFILE_PATH", "/certs/root.pem"),
                        ("FORGE_CLIENT_CERT_PATH", "/certs/client.pem"),
                        ("FORGE_CLIENT_KEY_PATH", "/certs/client.key"),
                    ],
                } => Yields(RuntimeConfigSummary {
                    internal_api_url: "https://carbide-api.forge-system.svc.cluster.local:1079".to_string(),
                    client_facing_api_url: "https://carbide-api.forge".to_string(),
                    pxe_url: "http://carbide-pxe.forge".to_string(),
                    static_pxe_url: "http://carbide-pxe.forge".to_string(),
                    forge_root_ca_path: "/certs/root.pem".to_string(),
                    server_cert_path: "/certs/client.pem".to_string(),
                    server_key_path: "/certs/client.key".to_string(),
                    bind_address: "0.0.0.0".parse().unwrap(),
                    bind_port: 8080,
                    template_directory: "/opt/carbide/pxe/templates".to_string(),
                }),
            }

            "explicit values" {
                ConfigEnv {
                    vars: &[
                        ("CARBIDE_API_INTERNAL_URL", "https://internal.example.com"),
                        ("CARBIDE_API_URL", "https://client.example.com"),
                        ("CARBIDE_PXE_URL", "http://pxe.example.com"),
                        ("CARBIDE_STATIC_PXE_URL", "http://static-pxe.example.com"),
                        ("FORGE_ROOT_CAFILE_PATH", "/explicit/root.pem"),
                        ("FORGE_CLIENT_CERT_PATH", "/explicit/client.pem"),
                        ("FORGE_CLIENT_KEY_PATH", "/explicit/client.key"),
                        ("PXE_BIND_ADDRESS", "127.0.0.1"),
                        ("PXE_BIND_PORT", "9090"),
                        ("CARBIDE_PXE_TEMPLATE_DIRECTORY", "/templates"),
                    ],
                } => Yields(RuntimeConfigSummary {
                    internal_api_url: "https://internal.example.com".to_string(),
                    client_facing_api_url: "https://client.example.com".to_string(),
                    pxe_url: "http://pxe.example.com".to_string(),
                    static_pxe_url: "http://static-pxe.example.com".to_string(),
                    forge_root_ca_path: "/explicit/root.pem".to_string(),
                    server_cert_path: "/explicit/client.pem".to_string(),
                    server_key_path: "/explicit/client.key".to_string(),
                    bind_address: "127.0.0.1".parse().unwrap(),
                    bind_port: 9090,
                    template_directory: "/templates".to_string(),
                }),
            }

            "missing required values" {
                ConfigEnv { vars: &[] } => FailsWith("missing-root-ca"),
                ConfigEnv {
                    vars: &[("FORGE_ROOT_CAFILE_PATH", "/certs/root.pem")],
                } => FailsWith("missing-client-cert"),
                ConfigEnv {
                    vars: &[
                        ("FORGE_ROOT_CAFILE_PATH", "/certs/root.pem"),
                        ("FORGE_CLIENT_CERT_PATH", "/certs/client.pem"),
                    ],
                } => FailsWith("missing-client-key"),
            }

            "invalid bind settings" {
                ConfigEnv {
                    vars: &[
                        ("FORGE_ROOT_CAFILE_PATH", "/certs/root.pem"),
                        ("FORGE_CLIENT_CERT_PATH", "/certs/client.pem"),
                        ("FORGE_CLIENT_KEY_PATH", "/certs/client.key"),
                        ("PXE_BIND_ADDRESS", "not an ip"),
                    ],
                } => FailsWith("bad-bind-address"),
                ConfigEnv {
                    vars: &[
                        ("FORGE_ROOT_CAFILE_PATH", "/certs/root.pem"),
                        ("FORGE_CLIENT_CERT_PATH", "/certs/client.pem"),
                        ("FORGE_CLIENT_KEY_PATH", "/certs/client.key"),
                        ("PXE_BIND_PORT", "not a port"),
                    ],
                } => FailsWith("bad-bind-port"),
            }
        );
    }
}
