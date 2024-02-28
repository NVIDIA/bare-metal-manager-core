use std::io::ErrorKind;
use std::str::FromStr;
use std::time::Duration;
use std::time::SystemTime;

use eyre::Result;
use forge_http_connector::connector::ForgeHttpConnector;
use forge_http_connector::resolver::ForgeResolver;
use forge_http_connector::resolver::ForgeResolverOpts;
use hickory_resolver::config::ResolverConfig;
use hyper::http::uri::Scheme;
use hyper::Uri;
use hyper_rustls::HttpsConnector;
use tokio_rustls::rustls;
use tokio_rustls::rustls::client::{ServerCertVerified, ServerCertVerifier};
use tokio_rustls::rustls::{Certificate, ClientConfig, PrivateKey, RootCertStore, ServerName};
use tonic::body::BoxBody;
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::forge_resolver;
use crate::protos::forge::forge_client::ForgeClient;

pub type ForgeClientT = ForgeClient<hyper::Client<HttpsConnector<ForgeHttpConnector>, BoxBody>>;

//this code was copy and pasted from the implementation of the same struct in sqlx::core,
//and is only necessary for as long as we're optionally validating TLS
struct DummyTlsVerifier {
    print_warning: bool,
}

impl DummyTlsVerifier {
    pub fn new() -> Self {
        Self {
            // Warnings are suppressed if this is running in a unit-test
            print_warning: std::env::var_os("CARGO_MANIFEST_DIR").is_none(),
        }
    }
}

pub const DEFAULT_DOMAIN: &str = "forge.local";

const VRF_NAME: &str = "mgmt";

impl ServerCertVerifier for DummyTlsVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: SystemTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if self.print_warning {
            eprintln!(
                "IGNORING SERVER CERT, Please ensure that I am removed to actually validate TLS."
            );
        }
        Ok(ServerCertVerified::assertion())
    }
}

#[derive(Clone, Debug)]
pub struct ForgeClientCert {
    pub cert_path: String,
    pub key_path: String,
}

#[derive(Clone, Debug, Default)]
pub struct ForgeClientConfig {
    pub root_ca_path: String,
    pub client_cert: Option<ForgeClientCert>,
    pub enforce_tls: bool,
    pub use_mgmt_vrf: bool,
    pub max_decoding_message_size: Option<usize>,
    pub socks_proxy: Option<String>,
}

impl ForgeClientConfig {
    pub fn new(root_ca_path: String, client_cert: Option<ForgeClientCert>) -> Self {
        let disabled = std::env::var("DISABLE_TLS_ENFORCEMENT").is_ok();
        let max_decoding_message_size = std::env::var("TONIC_MAX_DECODING_MESSAGE_SIZE")
            .ok()
            .and_then(|ms| ms.parse::<usize>().ok());

        Self {
            root_ca_path,
            client_cert,
            enforce_tls: !disabled,
            use_mgmt_vrf: false,
            max_decoding_message_size,
            socks_proxy: None,
        }
    }

    /// This is required when using `ForgeTlsConfig` on a DPU to communicate with site-controller.
    /// The mgmt interface exists in the mgmt VRF. `use_mgmt_vrf` sets the
    /// `SO_BINDTODEVICE` socket option on the client socket used when performing DNS queries
    /// and establishing a TCP connection with site-controller.
    pub fn use_mgmt_vrf(self) -> Result<Self, eyre::Report> {
        let ignore_mgmt_vrf = std::env::var("IGNORE_MGMT_VRF").is_ok();

        let use_mgmt_vrf = match ignore_mgmt_vrf {
            true => {
                log::debug!(
                    "ignore_mgmt_vrf is {} not using mgmt vrf: {}",
                    ignore_mgmt_vrf,
                    VRF_NAME
                );
                false
            }

            false => {
                log::debug!(
                    "ignore_mgmt_vrf is {} using mgmt vrf: {}",
                    ignore_mgmt_vrf,
                    VRF_NAME
                );
                true
            }
        };

        let max_decoding_message_size = std::env::var("TONIC_MAX_DECODING_MESSAGE_SIZE")
            .ok()
            .and_then(|ms| ms.parse::<usize>().ok());

        let res = Self {
            use_mgmt_vrf,
            max_decoding_message_size,
            ..self
        };

        log::debug!("ForgeClientConfig {:?}", res);

        Ok(res)
    }

    pub async fn client_cert_expiry(&self) -> Option<i64> {
        if let Some((client_certs, _key)) = self.read_client_cert().await {
            if let Some(client_public_key) = client_certs.first() {
                if let Ok((_rem, cert)) = X509Certificate::from_der(client_public_key.0.as_slice())
                {
                    Some(cert.validity.not_after.timestamp())
                } else {
                    None // couldn't parse certificate to x509
                }
            } else {
                None // no cert in client certs vec
            }
        } else {
            None // no certs parsed from disk
        }
    }

    pub async fn read_client_cert(&self) -> Option<(Vec<Certificate>, PrivateKey)> {
        if let Some(client_cert) = self.client_cert.as_ref() {
            let cert_path = client_cert.cert_path.clone();
            let key_path = client_cert.key_path.clone();
            tokio::task::spawn_blocking(move || {
                let certs = {
                    let fd = match std::fs::File::open(cert_path) {
                        Ok(fd) => fd,
                        Err(_) => return None,
                    };
                    let mut buf = std::io::BufReader::new(&fd);
                    match rustls_pemfile::certs(&mut buf) {
                        Ok(certs) => certs.into_iter().map(Certificate).collect::<Vec<_>>(),
                        Err(_error) => {
                            // tracing::error!("Rustls error reading certs: {:?}", error);
                            return None;
                        }
                    }
                };

                let key = {
                    let fd = match std::fs::File::open(key_path) {
                        Ok(fd) => fd,
                        Err(_) => return None,
                    };
                    let mut buf = std::io::BufReader::new(&fd);

                    use rustls_pemfile::Item;
                    match rustls_pemfile::read_one(&mut buf) {
                        Ok(Some(item)) => match item {
                            Item::RSAKey(rsa_key) => Some(PrivateKey(rsa_key)),
                            Item::PKCS8Key(pkcs8_key) => Some(PrivateKey(pkcs8_key)),
                            Item::ECKey(ec_key) => Some(PrivateKey(ec_key)),
                            Item::X509Certificate(_) => {
                                // expected a private key, found a certificate.
                                None
                            }
                            Item::Crl(_) => {
                                // expected a private key, found a certificate revocation list.
                                None
                            }
                            _ => None,
                        },
                        _ => None,
                    }
                };

                let key = match key {
                    Some(key) => key,
                    None => {
                        // tracing::error!("Rustls error: no keys?");
                        return None;
                    }
                };

                Some((certs, key))
            })
            .await
            .unwrap_or(None)
        } else {
            None
        }
    }

    pub fn socks_proxy(&mut self, socks_proxy: Option<String>) {
        self.socks_proxy = socks_proxy;
    }
}

pub struct ForgeTlsClient {
    forge_client_config: ForgeClientConfig,
}

impl ForgeTlsClient {
    pub fn new(forge_client_config: ForgeClientConfig) -> Self {
        Self {
            forge_client_config,
        }
    }

    pub async fn connect<S: AsRef<str>>(&self, url: S) -> Result<ForgeClientT, eyre::Report> {
        let mut roots = RootCertStore::empty();
        let uri = Uri::from_str(url.as_ref())?;

        // only check for the root cert if the uri we were given is actually HTTPS.  That lets tests function properly.
        if let Some(scheme) = uri.scheme() {
            if scheme == &Scheme::HTTPS {
                // TODO: by reading the pemfile every time, we're automatically getting hot-reload
                // TODO: -- but we could use inotify in order to make this more performant.
                match tokio::fs::read(&self.forge_client_config.root_ca_path).await {
                    Ok(pem_file) => {
                        let mut cert_cursor = std::io::Cursor::new(&pem_file[..]);
                        let (_added, _ignored) = roots
                            .add_parsable_certificates(&rustls_pemfile::certs(&mut cert_cursor)?);
                    }
                    Err(error) => match error.kind() {
                        ErrorKind::NotFound => {
                            return Err(eyre::eyre!(
                                "Root CA file not found at '{}'",
                                self.forge_client_config.root_ca_path,
                            ));
                        }
                        _ => {
                            return Err(error.into());
                        }
                    },
                }
            }
        }

        let tls = if self.forge_client_config.enforce_tls {
            let roots_clone = roots.clone();
            let build_no_client_auth_config = || {
                ClientConfig::builder()
                    .with_safe_defaults()
                    .with_root_certificates(roots_clone)
                    .with_no_client_auth()
            };

            if let Some((certs, key)) = self.forge_client_config.read_client_cert().await {
                if let Ok(config) = ClientConfig::builder()
                    .with_safe_defaults()
                    .with_root_certificates(roots)
                    .with_client_auth_cert(certs, key)
                {
                    config // happy path, full valid TLS client config with client cert
                } else {
                    build_no_client_auth_config() // error building client config from cert/key
                }
            } else {
                build_no_client_auth_config() // unable to parse client cert/key from file, or no client cert provided in tls config
            }
        } else {
            // tls disabled by environment variable
            ClientConfig::builder()
                .with_safe_defaults()
                .with_custom_certificate_verifier(std::sync::Arc::new(DummyTlsVerifier::new()))
                .with_no_client_auth()
        };

        let forge_resolv_config =
            forge_resolver::resolver::ForgeResolveConf::with_system_resolv_conf()?;
        let forge_resolver_config = forge_resolver::resolver::into_forge_resolver_config(
            forge_resolv_config.parsed_configuration(),
        )?;

        let resolver_config = ResolverConfig::from_parts(
            forge_resolver_config.0.domain,
            forge_resolver_config.0.search_domain,
            forge_resolver_config.0.inner.into_inner(),
        );
        // Five seconds is the default, but setting anyway for documentation and future proofing
        let mut resolver_opts = ForgeResolverOpts::default().timeout(Duration::from_secs(5));
        if self.forge_client_config.use_mgmt_vrf {
            resolver_opts = resolver_opts.use_mgmt_vrf();
        }
        let resolver = ForgeResolver::with_config_and_options(resolver_config, resolver_opts);
        let mut http = ForgeHttpConnector::new_with_resolver(resolver);
        if self.forge_client_config.use_mgmt_vrf {
            http.set_interface("mgmt".to_string());
        }
        http.set_socks5_proxy(self.forge_client_config.socks_proxy.clone());
        http.enforce_http(false);

        // Wait this long for `connect` syscall to return.
        // Hyper implements this by wrapping the call in `tokio::time::timeout`.
        http.set_connect_timeout(Some(Duration::from_secs(5)));

        // Set TCP timeouts. The interactions are non-obvious, but here are the basics:
        // - An established socket with in-flight data will timeout exactly TCP_USER_TIMEOUT
        // after data is first lost.
        // - An idle socket will send it's first probe when it's been idle for TCP_KEEPIDLE. If
        // the probe is not ACKed, it will timeout about TCP_USER_TIMEOUT after first data loss.
        // - This formula should be maintained: TCP_USER_TIMEOUT < TCP_KEEPIDLE + TCP_KEEPINTVL * TCP_KEEPCNT
        // where `<` means "just slightly lower than".
        //
        // The values below mean:
        // - Disconnect broken active sockets after 30s
        // - Disconnect broken idle sockets after 32s (first retry wakeup that's > tcp_user_time)
        //
        // If HTTP/2 PING (further down) is working the keepalive should never trigger, but if tokio borks the
        // kernel should unwedge the socket.
        //
        // All the details: https://blog.cloudflare.com/when-tcp-sockets-refuse-to-die/
        http.set_tcp_user_timeout(Some(Duration::from_secs(30)));
        http.set_keepalive_time(Some(Duration::from_secs(20))); // TCP_KEEPIDLE
        http.set_keepalive_interval(Some(Duration::from_secs(4)));
        http.set_keepalive_retries(Some(3)); // initial probe at 20s, then 24s, 28s and 32s

        let connector = tower::ServiceBuilder::new()
            .layer_fn(move |s| {
                let tls = tls.clone();

                hyper_rustls::HttpsConnectorBuilder::new()
                    .with_tls_config(tls)
                    .https_or_http()
                    .enable_http2()
                    .wrap_connector(s)
            })
            .service(http);

        // ping interval + ping timeout should add up to less than tcp_user_timeout,
        // so that the application gets a chance to fix things before the kernel.
        let hyper_client = hyper::client::Client::builder()
            .http2_only(true)
            // Send a PING frame every this
            .http2_keep_alive_interval(Some(Duration::from_secs(10)))
            // The server will have this much time to respond with a PONG
            .http2_keep_alive_timeout(Duration::from_secs(15))
            // Send PING even when no active http2 streams
            .http2_keep_alive_while_idle(true)
            // How many connections will be kept open, per host.
            // We never make more than a single connection to carbide at a time.
            .pool_max_idle_per_host(2)
            .build(connector);

        let mut forge_client = ForgeClient::with_origin(hyper_client, uri);

        if let Some(max_decoding_message_size) = self.forge_client_config.max_decoding_message_size
        {
            forge_client = forge_client.max_decoding_message_size(max_decoding_message_size);
        }

        Ok(forge_client)
    }
}
