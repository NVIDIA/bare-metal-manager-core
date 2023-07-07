use std::io::ErrorKind;
use std::str::FromStr;
use std::time::SystemTime;

use hyper::http::uri::Scheme;
use hyper::{client::HttpConnector, Uri};
use hyper_rustls::HttpsConnector;
use tokio_rustls::rustls;
use tokio_rustls::rustls::client::{ServerCertVerified, ServerCertVerifier};
use tokio_rustls::rustls::{Certificate, ClientConfig, PrivateKey, RootCertStore, ServerName};
use tonic::body::BoxBody;

use crate::protos::forge::forge_client::ForgeClient;

pub type ForgeClientT = ForgeClient<hyper::Client<HttpsConnector<HttpConnector>, BoxBody>>;

//this code was copy and pasted from the implementation of the same struct in sqlx::core,
//and is only necessary for as long as we're optionally validating TLS
struct DummyTlsVerifier;

/// Where we bake the root CA in our containers
pub const DEFAULT_ROOT_CA: &str = "/opt/forge/forge_root.pem";

pub fn default_root_ca() -> &'static str {
    DEFAULT_ROOT_CA
}

/// Where we write the client cert in our clients
pub const DEFAULT_CLIENT_CERT: &str = "/opt/forge/machine_cert.pem";

pub fn default_client_cert() -> &'static str {
    DEFAULT_CLIENT_CERT
}

/// Where we write the client key in our clients
pub const DEFAULT_CLIENT_KEY: &str = "/opt/forge/machine_cert.key";

pub fn default_client_key() -> &'static str {
    DEFAULT_CLIENT_KEY
}

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
        println!("IGNORING SERVER CERT, Please ensure that I am removed to actually validate TLS.");
        Ok(ServerCertVerified::assertion())
    }
}

#[derive(Clone, Debug)]
pub struct ForgeClientCert {
    pub cert_path: String,
    pub key_path: String,
}

#[derive(Clone, Debug, Default)]
pub struct ForgeTlsConfig {
    pub root_ca_path: String,
    pub client_cert: Option<ForgeClientCert>,
}

pub struct ForgeTlsClient {
    forge_tls_config: ForgeTlsConfig,
    enforce_tls: bool,
}

impl ForgeTlsClient {
    pub fn new(forge_tls_config: ForgeTlsConfig) -> Self {
        let disabled = std::env::var("DISABLE_TLS_ENFORCEMENT").is_ok();
        Self {
            forge_tls_config,
            enforce_tls: !disabled,
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
                match tokio::fs::read(&self.forge_tls_config.root_ca_path).await {
                    Ok(pem_file) => {
                        let mut cert_cursor = std::io::Cursor::new(&pem_file[..]);
                        let (_added, _ignored) = roots
                            .add_parsable_certificates(&rustls_pemfile::certs(&mut cert_cursor)?);
                    }
                    Err(error) => match error.kind() {
                        ErrorKind::NotFound => {
                            return Err(eyre::eyre!(
                                "Root CA file not found at '{}'",
                                self.forge_tls_config.root_ca_path,
                            ));
                        }
                        _ => {
                            return Err(error.into());
                        }
                    },
                }
            }
        }

        let tls = if self.enforce_tls {
            let roots_clone = roots.clone();
            let build_no_client_auth_config = || {
                ClientConfig::builder()
                    .with_safe_defaults()
                    .with_root_certificates(roots_clone)
                    .with_no_client_auth()
            };

            if let Some(client_cert) = self.forge_tls_config.client_cert.as_ref() {
                let cert_path = client_cert.cert_path.clone();
                let key_path = client_cert.key_path.clone();
                if let Ok(Some((certs, key))) = tokio::task::spawn_blocking(move || {
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

                        match rustls_pemfile::ec_private_keys(&mut buf) {
                            Ok(keys) => keys.into_iter().map(PrivateKey).next(),
                            Err(_error) => {
                                // tracing::error!("Rustls error reading key: {:?}", error);
                                None
                            }
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
                {
                    if let Ok(config) = ClientConfig::builder()
                        .with_safe_defaults()
                        .with_root_certificates(roots)
                        .with_single_cert(certs, key)
                    {
                        config // happy path, full valid TLS client config with client cert
                    } else {
                        build_no_client_auth_config() // error building client config from cert/key
                    }
                } else {
                    build_no_client_auth_config() // unable to parse client cert/key from file
                }
            } else {
                build_no_client_auth_config() // no client cert provided in tls config
            }
        } else {
            // tls disabled by environment variable
            ClientConfig::builder()
                .with_safe_defaults()
                .with_custom_certificate_verifier(std::sync::Arc::new(DummyTlsVerifier))
                .with_no_client_auth()
        };

        let mut http = HttpConnector::new();
        http.enforce_http(false);

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

        let hyper_client = hyper::Client::builder().http2_only(true).build(connector);
        let forge_client = ForgeClient::with_origin(hyper_client, uri);

        Ok(forge_client)
    }
}
