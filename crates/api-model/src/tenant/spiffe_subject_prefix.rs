/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

//! SPIFFE `subject_prefix` validation and defaulting against JWT `issuer` trust domain.

use std::net::IpAddr;

use lazy_static::lazy_static;
use regex::Regex;
use url::Url;

lazy_static! {
    static ref TRUST_DOMAIN_DNS: Regex = Regex::new(
        r"(?i)^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$"
    )
    .unwrap();
    static ref PATH_SEGMENT: Regex = Regex::new(r"^[a-zA-Z0-9._-]+$").unwrap();
}

fn normalize_trust_domain_token(host: &str) -> String {
    if host.parse::<IpAddr>().is_ok() {
        host.to_string()
    } else {
        host.to_ascii_lowercase()
    }
}

fn validate_trust_domain_structure(td: &str) -> Result<(), String> {
    if td.is_empty() {
        return Err("trust domain must be non-empty".into());
    }
    if td.parse::<IpAddr>().is_ok() {
        return Ok(());
    }
    if !TRUST_DOMAIN_DNS.is_match(td) {
        return Err(format!(
            "trust domain {td:?} is not a valid DNS hostname or IP address"
        ));
    }
    Ok(())
}

/// SPIFFE trust domain string derived from `issuer` (HTTPS URL host, `spiffe://` URI, or bare hostname).
pub(super) fn trust_domain_from_issuer(issuer: &str) -> Result<String, String> {
    let issuer = issuer.trim();
    if issuer.is_empty() {
        return Err("issuer is required".into());
    }
    if issuer.contains('%') || issuer.contains('#') {
        return Err("issuer must not contain percent-encoding or fragments".into());
    }

    if let Some(rest) = issuer.strip_prefix("spiffe://") {
        if rest.contains('@') {
            return Err("issuer: invalid SPIFFE URI (userinfo not allowed)".into());
        }
        let td = rest
            .split('/')
            .next()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| "issuer: SPIFFE URI must include a trust domain".to_string())?;
        validate_trust_domain_structure(td)?;
        return Ok(normalize_trust_domain_token(td));
    }

    if issuer.contains("://") {
        let u = Url::parse(issuer).map_err(|e| format!("issuer: invalid URL ({e})"))?;
        let host = u
            .host_str()
            .ok_or_else(|| "issuer: URL must have a host".to_string())?;
        validate_trust_domain_structure(host)?;
        return Ok(normalize_trust_domain_token(host));
    }

    validate_trust_domain_structure(issuer)?;
    Ok(normalize_trust_domain_token(issuer))
}

fn default_subject_prefix(expected_td: &str) -> String {
    format!("spiffe://{expected_td}/")
}

fn validate_path_segments(path_raw: &str) -> Result<Vec<&str>, String> {
    if path_raw.is_empty() {
        return Ok(Vec::new());
    }
    if path_raw.ends_with('/') {
        return Err(
            "subject_prefix path must not end with '/' (except the root form spiffe://<td>/)"
                .into(),
        );
    }
    let mut out = Vec::new();
    for seg in path_raw.split('/') {
        if seg.is_empty() {
            return Err("subject_prefix path must not contain empty segments".into());
        }
        if seg == "." || seg == ".." {
            return Err("subject_prefix path must not use '.' or '..' segments".into());
        }
        if !PATH_SEGMENT.is_match(seg) {
            return Err(format!(
                "subject_prefix path segment {seg:?} must match [a-zA-Z0-9._-]+"
            ));
        }
        out.push(seg);
    }
    Ok(out)
}

fn validate_and_canonicalize_subject_prefix(
    raw: &str,
    expected_td: &str,
) -> Result<String, String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(default_subject_prefix(expected_td));
    }
    if raw.contains('%') || raw.contains('?') || raw.contains('#') {
        return Err("subject_prefix must not contain percent-encoding, query, or fragment".into());
    }
    let body = raw
        .strip_prefix("spiffe://")
        .ok_or_else(|| "subject_prefix must use the spiffe:// scheme".to_string())?;

    if body.contains('@') {
        return Err("subject_prefix must not include userinfo".into());
    }

    let (td_raw, path_raw) = match body.find('/') {
        None => (body, ""),
        Some(0) => return Err("subject_prefix is missing a trust domain after spiffe://".into()),
        Some(i) => (&body[..i], &body[i + 1..]),
    };

    validate_trust_domain_structure(td_raw)?;
    let td_norm = normalize_trust_domain_token(td_raw);
    if td_norm != expected_td {
        return Err(format!(
            "subject_prefix trust domain {td_raw:?} does not match issuer trust domain (expected {expected_td:?})"
        ));
    }

    let segments = validate_path_segments(path_raw)?;
    if segments.is_empty() {
        Ok(default_subject_prefix(expected_td))
    } else {
        Ok(format!("spiffe://{expected_td}/{}", segments.join("/")))
    }
}

/// Resolves optional proto `subject_prefix`: default `spiffe://<expected_td>/` or validated user value.
pub(super) fn resolve_subject_prefix(
    expected_td: &str,
    proto_subject_prefix: Option<&str>,
) -> Result<String, String> {
    match proto_subject_prefix {
        None | Some("") => Ok(default_subject_prefix(expected_td)),
        Some(s) => validate_and_canonicalize_subject_prefix(s, expected_td),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resolve_identity(issuer: &str, proto: Option<&str>) -> Result<String, String> {
        let td = trust_domain_from_issuer(issuer)?;
        resolve_subject_prefix(&td, proto)
    }

    #[test]
    fn trust_domain_https_issuer() {
        assert_eq!(
            trust_domain_from_issuer("https://Issuer.EXAMPLE/path").unwrap(),
            "issuer.example"
        );
    }

    #[test]
    fn trust_domain_spiffe_issuer() {
        assert_eq!(
            trust_domain_from_issuer("spiffe://Issuer.EXAMPLE/bundle").unwrap(),
            "issuer.example"
        );
    }

    #[test]
    fn resolve_identity_defaults_prefix() {
        assert_eq!(
            resolve_identity("https://my.idp.example", None).unwrap(),
            "spiffe://my.idp.example/"
        );
    }

    #[test]
    fn explicit_prefix_canonicalizes_td_case() {
        let p =
            resolve_identity("https://issuer.example", Some("spiffe://ISSUER.EXAMPLE/wl")).unwrap();
        assert_eq!(p, "spiffe://issuer.example/wl");
    }

    #[test]
    fn wrong_td_rejected() {
        let err = resolve_identity("https://issuer.example", Some("spiffe://other.example/"))
            .unwrap_err();
        assert!(err.contains("does not match"));
    }

    #[test]
    fn percent_encoding_rejected() {
        let err = resolve_identity(
            "https://issuer.example",
            Some("spiffe://issuer.example/a%2Fb"),
        )
        .unwrap_err();
        assert!(err.contains("percent-encoding"));
    }

    #[test]
    fn https_scheme_subject_prefix_rejected() {
        let err = resolve_identity("https://issuer.example", Some("https://issuer.example/p"))
            .unwrap_err();
        assert!(err.contains("spiffe://"));
    }
}
