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

//! TLS helpers for outbound health collector connections.
//!
//! The current profile is used by switch collectors through `[tls.switch]`.
//! This module owns HTTP and gRPC TLS construction inside the health crate so
//! collector transport security does not depend on NICo API certificate
//! settings. Each client build reads and validates the configured certificate
//! files. Periodic HTTP collectors rebuild their mTLS clients once per poll
//! iteration so they adopt changed certificate files on the next scrape.
//! Streaming collectors build a new TLS config when they reconnect.

use std::fmt;
use std::io::BufReader;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Once};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use thiserror::Error;
use tokio::fs;
use tonic::transport::{
    Certificate as TonicCertificate, ClientTlsConfig, Identity as TonicIdentity,
};
use x509_parser::prelude::*;

use crate::config::MtlsProfileConfig;

/// Role for one mTLS profile material file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TlsMaterialKind {
    CaBundle,
    ClientCertificate,
    ClientKey,
}

impl fmt::Display for TlsMaterialKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CaBundle => f.write_str("CA bundle"),
            Self::ClientCertificate => f.write_str("client certificate"),
            Self::ClientKey => f.write_str("client key"),
        }
    }
}

#[derive(Debug, Error)]
pub(crate) enum TlsError {
    #[error("failed to read mTLS profile {kind} at {path}: {source}")]
    Read {
        kind: TlsMaterialKind,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("mTLS profile {kind} at {path} is empty")]
    Empty {
        kind: TlsMaterialKind,
        path: PathBuf,
    },

    #[error("failed to parse mTLS profile {kind} at {path}: {message}")]
    Parse {
        kind: TlsMaterialKind,
        path: PathBuf,
        message: String,
    },

    #[error(
        "mTLS profile {kind} certificate at {path} is not valid before unix timestamp {not_before}"
    )]
    NotYetValid {
        kind: TlsMaterialKind,
        path: PathBuf,
        not_before: i64,
    },

    #[error("mTLS profile {kind} certificate at {path} expired at unix timestamp {not_after}")]
    Expired {
        kind: TlsMaterialKind,
        path: PathBuf,
        not_after: i64,
    },

    #[error("mTLS profile CA bundle at {path} contains no usable trust anchors")]
    NoTrustedCa { path: PathBuf },

    #[error("mTLS profile client certificate and key are invalid or do not match: {source}")]
    InvalidIdentity {
        #[source]
        source: rustls::Error,
    },

    #[error("failed to create mTLS profile HTTP CA bundle: {source}")]
    HttpCaBundle {
        #[source]
        source: reqwest::Error,
    },

    #[error("failed to create mTLS profile HTTP client identity: {source}")]
    HttpIdentity {
        #[source]
        source: reqwest::Error,
    },

    #[error("failed to create mTLS profile HTTP client: {source}")]
    HttpClient {
        #[source]
        source: reqwest::Error,
    },
}

struct TlsMaterial {
    ca_pem: Vec<u8>,
    client_cert_pem: Vec<u8>,
    client_key_pem: Vec<u8>,
}

pub(crate) async fn preflight(config: &MtlsProfileConfig) -> Result<(), TlsError> {
    read_validated_material(config).await.map(|_| ())
}

/// Builds an HTTP client from the current mTLS profile material.
///
/// The DNS name in `[tls.switch].tls_server_name` is used only for SNI and
/// certificate verification. When it is set, callers pass the discovered switch
/// socket address so reqwest still connects to the intended switch endpoint.
pub(crate) async fn reqwest_client(
    config: &MtlsProfileConfig,
    timeout: Duration,
    resolve_addr: Option<SocketAddr>,
) -> Result<reqwest::Client, TlsError> {
    let material = read_validated_material(config).await?;
    let ca_certs = reqwest::Certificate::from_pem_bundle(&material.ca_pem)
        .map_err(|source| TlsError::HttpCaBundle { source })?;

    let mut identity_pem =
        Vec::with_capacity(material.client_cert_pem.len() + material.client_key_pem.len() + 1);

    identity_pem.extend_from_slice(&material.client_cert_pem);
    identity_pem.push(b'\n');
    identity_pem.extend_from_slice(&material.client_key_pem);

    let identity = reqwest::Identity::from_pem(&identity_pem)
        .map_err(|source| TlsError::HttpIdentity { source })?;

    let mut builder = reqwest::Client::builder()
        .timeout(timeout)
        .tls_backend_rustls()
        .tls_certs_only(ca_certs)
        .identity(identity);

    if let (Some(tls_server_name), Some(resolve_addr)) =
        (config.tls_server_name.as_deref(), resolve_addr)
    {
        // The DNS name is for SNI and certificate verification only. Override
        // resolution so HTTP still connects to the discovered switch IP.
        builder = builder.resolve(tls_server_name, resolve_addr);
    }

    builder
        .build()
        .map_err(|source| TlsError::HttpClient { source })
}

/// Builds a tonic client TLS configuration from the current mTLS profile material.
///
/// Existing gRPC channels keep their current TLS session. Streaming collectors
/// use refreshed files when they reconnect and build a new channel.
pub(crate) async fn tonic_tls_config(
    config: &MtlsProfileConfig,
) -> Result<ClientTlsConfig, TlsError> {
    let material = read_validated_material(config).await?;

    let mut tls_config = ClientTlsConfig::new()
        .ca_certificate(TonicCertificate::from_pem(&material.ca_pem))
        .identity(TonicIdentity::from_pem(
            &material.client_cert_pem,
            &material.client_key_pem,
        ));

    if let Some(tls_server_name) = &config.tls_server_name {
        // gRPC endpoints still use the discovered switch IP in their URI. This
        // override changes only TLS SNI and certificate name verification.
        tls_config = tls_config.domain_name(tls_server_name.clone());
    }

    Ok(tls_config)
}

async fn read_validated_material(config: &MtlsProfileConfig) -> Result<TlsMaterial, TlsError> {
    ensure_rustls_provider();

    let (ca_pem, client_cert_pem, client_key_pem) = tokio::try_join!(
        read_material(TlsMaterialKind::CaBundle, &config.ca_cert_path),
        read_material(TlsMaterialKind::ClientCertificate, &config.client_cert_path,),
        read_material(TlsMaterialKind::ClientKey, &config.client_key_path),
    )?;

    let ca_certs = parse_certificates(TlsMaterialKind::CaBundle, &config.ca_cert_path, &ca_pem)?;

    let client_certs = parse_certificates(
        TlsMaterialKind::ClientCertificate,
        &config.client_cert_path,
        &client_cert_pem,
    )?;

    let client_key = parse_private_key(&config.client_key_path, &client_key_pem)?;
    let now = unix_timestamp_now();

    validate_certificate_times(
        TlsMaterialKind::CaBundle,
        &config.ca_cert_path,
        &ca_certs,
        now,
    )?;

    validate_certificate_times(
        TlsMaterialKind::ClientCertificate,
        &config.client_cert_path,
        &client_certs,
        now,
    )?;

    validate_root_store(&config.ca_cert_path, ca_certs)?;
    validate_client_identity(client_certs, client_key)?;

    Ok(TlsMaterial {
        ca_pem,
        client_cert_pem,
        client_key_pem,
    })
}

async fn read_material(kind: TlsMaterialKind, path: &Path) -> Result<Vec<u8>, TlsError> {
    let data = fs::read(path).await.map_err(|source| TlsError::Read {
        kind,
        path: path.to_path_buf(),
        source,
    })?;

    if data.iter().all(u8::is_ascii_whitespace) {
        return Err(TlsError::Empty {
            kind,
            path: path.to_path_buf(),
        });
    }

    Ok(data)
}

fn parse_certificates(
    kind: TlsMaterialKind,
    path: &Path,
    pem: &[u8],
) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    let mut reader = BufReader::new(pem);
    let certificates = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| TlsError::Parse {
            kind,
            path: path.to_path_buf(),
            message: source.to_string(),
        })?;

    if certificates.is_empty() {
        return Err(TlsError::Parse {
            kind,
            path: path.to_path_buf(),
            message: "no certificate PEM blocks found".to_string(),
        });
    }

    Ok(certificates)
}

fn parse_private_key(path: &Path, pem: &[u8]) -> Result<PrivateKeyDer<'static>, TlsError> {
    let mut reader = BufReader::new(pem);
    rustls_pemfile::private_key(&mut reader)
        .map_err(|source| TlsError::Parse {
            kind: TlsMaterialKind::ClientKey,
            path: path.to_path_buf(),
            message: source.to_string(),
        })?
        .ok_or_else(|| TlsError::Parse {
            kind: TlsMaterialKind::ClientKey,
            path: path.to_path_buf(),
            message: "no supported private key PEM block found".to_string(),
        })
}

fn validate_certificate_times(
    kind: TlsMaterialKind,
    path: &Path,
    certificates: &[CertificateDer<'static>],
    now: i64,
) -> Result<(), TlsError> {
    for certificate in certificates {
        let (_, x509) =
            X509Certificate::from_der(certificate.as_ref()).map_err(|source| TlsError::Parse {
                kind,
                path: path.to_path_buf(),
                message: format!("invalid X.509 certificate: {source}"),
            })?;

        let validity = x509.validity();
        let not_before = validity.not_before.timestamp();
        let not_after = validity.not_after.timestamp();

        if now < not_before {
            return Err(TlsError::NotYetValid {
                kind,
                path: path.to_path_buf(),
                not_before,
            });
        }

        if now > not_after {
            return Err(TlsError::Expired {
                kind,
                path: path.to_path_buf(),
                not_after,
            });
        }
    }

    Ok(())
}

fn validate_root_store(
    path: &Path,
    certificates: Vec<CertificateDer<'static>>,
) -> Result<(), TlsError> {
    let mut root_store = RootCertStore::empty();
    let (accepted, ignored) = root_store.add_parsable_certificates(certificates);

    if accepted == 0 {
        return Err(TlsError::NoTrustedCa {
            path: path.to_path_buf(),
        });
    }

    if ignored != 0 {
        return Err(TlsError::Parse {
            kind: TlsMaterialKind::CaBundle,
            path: path.to_path_buf(),
            message: format!("{ignored} certificate(s) could not be used as trust anchors"),
        });
    }

    Ok(())
}

fn validate_client_identity(
    certificates: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<(), TlsError> {
    let root_store = RootCertStore::empty();

    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|source| TlsError::InvalidIdentity { source })?
    .with_root_certificates(root_store);

    builder
        .with_client_auth_cert(certificates, key)
        .map(|_| ())
        .map_err(|source| TlsError::InvalidIdentity { source })
}

fn ensure_rustls_provider() {
    static INSTALL_PROVIDER: Once = Once::new();

    INSTALL_PROVIDER.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

fn unix_timestamp_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use carbide_test_support::Outcome::*;
    use carbide_test_support::{Case, check_cases_async};
    use rcgen::{
        BasicConstraints, Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa,
        Issuer, KeyPair, KeyUsagePurpose, date_time_ymd,
    };
    use tempfile::TempDir;

    use super::*;

    struct GeneratedMaterial {
        ca_pem: Vec<u8>,
        client_cert_pem: Vec<u8>,
        client_key_pem: Vec<u8>,
        alternate_client_key_pem: Vec<u8>,
    }

    #[derive(Debug, Eq, PartialEq)]
    enum ExpectedTlsError {
        Empty(TlsMaterialKind),
        Parse(TlsMaterialKind),
        InvalidIdentity,
        Expired(TlsMaterialKind),
        NotYetValid(TlsMaterialKind),
    }

    fn valid_material() -> GeneratedMaterial {
        material_with_validity(
            date_time_ymd(1975, 1, 1),
            date_time_ymd(4096, 1, 1),
            date_time_ymd(1975, 1, 1),
            date_time_ymd(4096, 1, 1),
        )
    }

    fn material_with_validity(
        ca_not_before: ::time::OffsetDateTime,
        ca_not_after: ::time::OffsetDateTime,
        client_not_before: ::time::OffsetDateTime,
        client_not_after: ::time::OffsetDateTime,
    ) -> GeneratedMaterial {
        let (ca, issuer) = ca_with_validity(ca_not_before, ca_not_after);
        let (client_cert, client_key) =
            client_cert_with_validity(&issuer, client_not_before, client_not_after);

        let alternate_key = KeyPair::generate().expect("alternate client key should generate");

        GeneratedMaterial {
            ca_pem: ca.pem().into_bytes(),
            client_cert_pem: client_cert.pem().into_bytes(),
            client_key_pem: client_key.serialize_pem().into_bytes(),
            alternate_client_key_pem: alternate_key.serialize_pem().into_bytes(),
        }
    }

    fn ca_with_validity(
        not_before: ::time::OffsetDateTime,
        not_after: ::time::OffsetDateTime,
    ) -> (Certificate, Issuer<'static, KeyPair>) {
        let mut params =
            CertificateParams::new(Vec::new()).expect("empty subject alt names should be valid");

        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(DnType::CommonName, "switch test ca");

        params.key_usages.push(KeyUsagePurpose::DigitalSignature);
        params.key_usages.push(KeyUsagePurpose::KeyCertSign);
        params.key_usages.push(KeyUsagePurpose::CrlSign);

        params.not_before = not_before;
        params.not_after = not_after;

        let key_pair = KeyPair::generate().expect("CA key should generate");
        let cert = params
            .self_signed(&key_pair)
            .expect("CA certificate should sign");

        (cert, Issuer::new(params, key_pair))
    }

    fn client_cert_with_validity(
        issuer: &Issuer<'static, KeyPair>,
        not_before: ::time::OffsetDateTime,
        not_after: ::time::OffsetDateTime,
    ) -> (Certificate, KeyPair) {
        let mut params =
            CertificateParams::new(Vec::new()).expect("empty subject alt names should be valid");

        params
            .distinguished_name
            .push(DnType::CommonName, "switch test client");

        params.key_usages.push(KeyUsagePurpose::DigitalSignature);
        params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ClientAuth);

        params.not_before = not_before;
        params.not_after = not_after;

        let key_pair = KeyPair::generate().expect("client key should generate");
        let cert = params
            .signed_by(&key_pair, issuer)
            .expect("client certificate should sign");

        (cert, key_pair)
    }

    async fn write_material(
        dir: &TempDir,
        material: &GeneratedMaterial,
    ) -> Result<MtlsProfileConfig, std::io::Error> {
        let ca_cert_path = dir.path().join("ca.crt");
        let client_cert_path = dir.path().join("tls.crt");
        let client_key_path = dir.path().join("tls.key");

        tokio::fs::write(&ca_cert_path, &material.ca_pem).await?;
        tokio::fs::write(&client_cert_path, &material.client_cert_pem).await?;
        tokio::fs::write(&client_key_path, &material.client_key_pem).await?;

        Ok(MtlsProfileConfig {
            ca_cert_path,
            client_cert_path,
            client_key_path,
            tls_server_name: None,
        })
    }

    fn expected_tls_error(error: TlsError) -> ExpectedTlsError {
        match error {
            TlsError::Empty { kind, .. } => ExpectedTlsError::Empty(kind),
            TlsError::Parse { kind, .. } => ExpectedTlsError::Parse(kind),
            TlsError::InvalidIdentity { .. } => ExpectedTlsError::InvalidIdentity,
            TlsError::Expired { kind, .. } => ExpectedTlsError::Expired(kind),
            TlsError::NotYetValid { kind, .. } => ExpectedTlsError::NotYetValid(kind),
            error => panic!("unexpected mTLS profile error: {error}"),
        }
    }

    #[tokio::test]
    async fn valid_tls_material_builds_http_and_grpc_clients()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = TempDir::new()?;
        let material = valid_material();
        let config = write_material(&dir, &material).await?;

        preflight(&config).await?;
        let _http_client = reqwest_client(&config, Duration::from_secs(1), None).await?;

        let _grpc_tls = tonic_tls_config(&config).await?;

        Ok(())
    }

    #[tokio::test]
    async fn http_client_build_reads_changed_tls_material() -> Result<(), Box<dyn std::error::Error>>
    {
        let dir = TempDir::new()?;
        let material = valid_material();
        let config = write_material(&dir, &material).await?;

        preflight(&config).await?;

        let rotated = valid_material();
        tokio::fs::write(&config.ca_cert_path, &rotated.ca_pem).await?;
        tokio::fs::write(&config.client_cert_path, &rotated.client_cert_pem).await?;
        tokio::fs::write(&config.client_key_path, &rotated.client_key_pem).await?;

        let _http_client = reqwest_client(&config, Duration::from_secs(1), None).await?;

        Ok(())
    }

    #[tokio::test]
    async fn http_client_build_reports_invalid_changed_tls_material()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = TempDir::new()?;
        let material = valid_material();
        let config = write_material(&dir, &material).await?;

        preflight(&config).await?;

        tokio::fs::write(&config.client_key_path, &material.alternate_client_key_pem).await?;

        let result = reqwest_client(&config, Duration::from_secs(1), None).await;

        assert!(matches!(result, Err(TlsError::InvalidIdentity { .. })));

        Ok(())
    }

    #[tokio::test]
    async fn missing_tls_material_returns_path_and_role() -> Result<(), Box<dyn std::error::Error>>
    {
        let dir = TempDir::new()?;
        let material = valid_material();
        let config = write_material(&dir, &material).await?;

        tokio::fs::remove_file(&config.client_key_path).await?;

        let result = preflight(&config).await;

        let Err(TlsError::Read { kind, path, .. }) = result else {
            panic!("expected read error for missing key");
        };

        assert_eq!(kind, TlsMaterialKind::ClientKey);
        assert_eq!(path, config.client_key_path);

        Ok(())
    }

    #[tokio::test]
    async fn invalid_tls_material_returns_clear_errors() -> Result<(), Box<dyn std::error::Error>> {
        check_cases_async(
            [
                Case {
                    scenario: "empty CA bundle",
                    input: {
                        let mut material = valid_material();
                        material.ca_pem = Vec::new();
                        material
                    },
                    expect: FailsWith(ExpectedTlsError::Empty(TlsMaterialKind::CaBundle)),
                },
                Case {
                    scenario: "malformed client certificate",
                    input: {
                        let mut material = valid_material();
                        material.client_cert_pem = b"not pem".to_vec();
                        material
                    },
                    expect: FailsWith(ExpectedTlsError::Parse(TlsMaterialKind::ClientCertificate)),
                },
                Case {
                    scenario: "malformed client key",
                    input: {
                        let mut material = valid_material();
                        material.client_key_pem = b"not pem".to_vec();
                        material
                    },
                    expect: FailsWith(ExpectedTlsError::Parse(TlsMaterialKind::ClientKey)),
                },
                Case {
                    scenario: "mismatched client key",
                    input: {
                        let mut material = valid_material();
                        material.client_key_pem = material.alternate_client_key_pem.clone();
                        material
                    },
                    expect: FailsWith(ExpectedTlsError::InvalidIdentity),
                },
            ],
            |material| async move {
                let dir = TempDir::new().expect("temp dir should create");

                let config = write_material(&dir, &material)
                    .await
                    .expect("mTLS profile material should write");

                preflight(&config).await.map_err(expected_tls_error)
            },
        )
        .await;

        Ok(())
    }

    #[tokio::test]
    async fn tls_material_rejects_expired_and_future_certificates()
    -> Result<(), Box<dyn std::error::Error>> {
        check_cases_async(
            [
                Case {
                    scenario: "expired client certificate",
                    input: material_with_validity(
                        date_time_ymd(1975, 1, 1),
                        date_time_ymd(4096, 1, 1),
                        date_time_ymd(2020, 1, 1),
                        date_time_ymd(2021, 1, 1),
                    ),
                    expect: FailsWith(ExpectedTlsError::Expired(
                        TlsMaterialKind::ClientCertificate,
                    )),
                },
                Case {
                    scenario: "future CA certificate",
                    input: material_with_validity(
                        date_time_ymd(4097, 1, 1),
                        date_time_ymd(4098, 1, 1),
                        date_time_ymd(1975, 1, 1),
                        date_time_ymd(4096, 1, 1),
                    ),
                    expect: FailsWith(ExpectedTlsError::NotYetValid(TlsMaterialKind::CaBundle)),
                },
            ],
            |material| async move {
                let dir = TempDir::new().expect("temp dir should create");

                let config = write_material(&dir, &material)
                    .await
                    .expect("mTLS profile material should write");

                preflight(&config).await.map_err(expected_tls_error)
            },
        )
        .await;

        Ok(())
    }
}
