/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

//! Identity configuration policy (driven by site `[machine_identity]` config): JWT issuer normalization,
//! SPIFFE `subject_prefix` resolution, OAuth token-endpoint host extraction, and hostname allowlists.
//!
//! Issuers must be `http://`, `https://`, or `spiffe://` URLs parsed with [`Url::parse`], with no
//! userinfo, query, or fragment. The trust domain is the registered (non-IP) host, lowercased for a
//! stable `iss` and SPIFFE comparisons. Ports do not affect the trust-domain string;
//! [`normalize_issuer_and_trust_domain`] builds the normalized `iss`, keeps explicit port and non-empty
//! paths, and omits a lone default `/` path. Application code should prefer
//! [`super::identity_config::Issuer::parse`], which wraps this helper.

use lazy_static::lazy_static;
use regex::Regex;
use url::{Host, Url};

/// Upper bound for stored / configured issuer strings (JWT `iss` is unbounded in theory).
const MAX_ISSUER_BYTES: usize = 2048;
/// Upper bound for `subject_prefix` (SPIFFE ID prefix + optional path).
const MAX_SUBJECT_PREFIX_BYTES: usize = 2048;
/// DNS hostname max length (octets) per RFC 1035.
const MAX_TRUST_DOMAIN_BYTES: usize = 253;

lazy_static! {
    static ref PATH_SEGMENT: Regex = Regex::new(r"^[a-zA-Z0-9._-]+$").unwrap();
}

fn reject_non_url_literal(s: &str, field: &str) -> Result<(), String> {
    if !s.is_ascii() {
        return Err(format!("{field} must contain only ASCII characters"));
    }
    if s.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err(format!(
            "{field} must not contain control characters (disallowed)"
        ));
    }
    if s.contains(['\\', '%', '#', ' ']) {
        return Err(format!(
            "{field} contains disallowed characters: must not contain spaces, '\\\\', '%', or '#' (no percent-encoding or fragments)"
        ));
    }
    Ok(())
}

fn spiffe_path_after_authority(u: &Url) -> &str {
    u.path().strip_prefix('/').unwrap_or("")
}

fn enforce_max_len(len: usize, max: usize, field: &str) -> Result<(), String> {
    if len > max {
        return Err(format!("{field} exceeds maximum length ({max} bytes)"));
    }
    Ok(())
}

fn normalize_trust_domain_token(host: &str) -> String {
    host.to_ascii_lowercase()
}

fn validate_trust_domain_len(host: &str) -> Result<(), String> {
    if host.is_empty() {
        return Err("trust domain must be non-empty".into());
    }
    if host.len() > MAX_TRUST_DOMAIN_BYTES {
        return Err(format!(
            "trust domain exceeds maximum length ({MAX_TRUST_DOMAIN_BYTES} bytes)"
        ));
    }
    Ok(())
}

/// Registered name host only (rejects IPv4/IPv6 literals from [`Url::host`]).
fn domain_only_host<'a>(
    u: &'a Url,
    field: &str,
    missing_host_msg: &str,
) -> Result<&'a str, String> {
    match u.host() {
        Some(Host::Domain(host)) => Ok(host),
        Some(Host::Ipv4(_) | Host::Ipv6(_)) => Err(format!(
            "{field}: trust domain must be a DNS hostname, not an IP address (got {:?})",
            u.host_str().unwrap_or("")
        )),
        None => Err(missing_host_msg.into()),
    }
}

/// No userinfo, query, or fragment (`field` prefixes errors, e.g. `issuer` or `subject_prefix`).
fn validate_url_no_query_fragment_userinfo(u: &Url, field: &str) -> Result<(), String> {
    if u.query().is_some() {
        return Err(format!("{field}: query is not allowed"));
    }
    if u.fragment().is_some() {
        return Err(format!("{field}: fragment is not allowed"));
    }
    if !u.username().is_empty() || u.password().is_some() {
        return Err(format!("{field}: URL must not contain userinfo"));
    }
    Ok(())
}

fn parse_identity_url(raw: &str, parse_err_label: &str) -> Result<Url, String> {
    Url::parse(raw).map_err(|e| format!("{parse_err_label}: invalid URL ({e})"))
}

/// Registered domain host, length check, lowercase trust-domain string.
///
/// [`Url::parse`] canonicalizes ASCII host **case** for `http`/`https`, but not consistently for
/// `spiffe://`; we always lowercase so `iss`, allowlists, and `subject_prefix` agree.
fn validated_trust_domain_token(
    u: &Url,
    field: &str,
    missing_host_msg: &str,
) -> Result<String, String> {
    let host = domain_only_host(u, field, missing_host_msg)?;
    validate_trust_domain_len(host)?;
    Ok(normalize_trust_domain_token(host))
}

/// Parse and validate JWT issuer URL (`http` / `https` / `spiffe`).
fn parse_issuer_url(issuer: &str) -> Result<Url, String> {
    let issuer = issuer.trim();
    if issuer.is_empty() {
        return Err("issuer is required".into());
    }
    enforce_max_len(issuer.len(), MAX_ISSUER_BYTES, "issuer")?;

    if !issuer.contains("://") {
        return Err(
            "issuer must be an http://, https://, or spiffe:// URL (bare hostnames are not supported)"
                .into(),
        );
    }

    reject_non_url_literal(issuer, "issuer")?;
    let u = parse_identity_url(issuer, "issuer")?;
    validate_issuer_url(&u)?;
    Ok(u)
}

fn serialize_issuer_url(u: &Url, host_lc: &str) -> String {
    let scheme = u.scheme();
    let port = match u.port() {
        Some(p) => format!(":{p}"),
        None => String::new(),
    };
    // `Url::path` is `/` when no path was written; omit it so `https://td` matches typical `iss`.
    let path = u.path();
    let path_part = if path == "/" { "" } else { path };
    format!("{scheme}://{host_lc}{port}{path_part}")
}

/// Parses JWT issuer once. Returns `(normalized_iss, trust_domain)` — canonical `iss` string
/// (lowercased host for trust domain; scheme per [`Url`]; explicit port and non-root path preserved;
/// default lone `/` path omitted) and lowercase registered host for SPIFFE trust domain.
pub(crate) fn normalize_issuer_and_trust_domain(issuer: &str) -> Result<(String, String), String> {
    let u = parse_issuer_url(issuer)?;
    let td = validated_trust_domain_token(&u, "issuer", "issuer: URL must have a host")?;
    let normalized = serialize_issuer_url(&u, &td);
    Ok((normalized, td))
}

// --- `[machine_identity].trust_domain_allowlist` (site policy; empty list = no extra check) ---

const MAX_ALLOWLIST_PATTERN_BYTES: usize = 512;

fn normalize_allowlist_token(s: &str) -> String {
    s.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// `*.suffix`: exactly one label under `suffix` (e.g. `auth.something.net`, not `a.b.something.net`).
fn trust_domain_matches_single_star_suffix(td: &str, suffix: &str) -> bool {
    let tail = format!(".{suffix}");
    td.strip_suffix(&tail)
        .is_some_and(|left| !left.is_empty() && !left.contains('.'))
}

/// `**.suffix`: `suffix` itself or any subdomain (`a.b.suffix`).
fn trust_domain_matches_double_star_suffix(td: &str, suffix: &str) -> bool {
    td == suffix || td.ends_with(&format!(".{suffix}"))
}

/// Returns `Ok` if `hostname` (already normalized, lowercase DNS name) is allowed by at least one pattern.
/// Empty `allowlist` → always `Ok`.
fn hostname_matches_allowlist(
    hostname: &str,
    allowlist: &[String],
    entity_label: &'static str,
    list_config_key: &'static str,
) -> Result<(), String> {
    if allowlist.is_empty() {
        return Ok(());
    }
    let td = normalize_allowlist_token(hostname);
    if td.is_empty() {
        return Err(format!("{entity_label} is empty"));
    }
    for raw in allowlist {
        let p = normalize_allowlist_token(raw);
        let matches = if let Some(suffix) = p.strip_prefix("**.") {
            trust_domain_matches_double_star_suffix(&td, suffix)
        } else if let Some(suffix) = p.strip_prefix("*.") {
            trust_domain_matches_single_star_suffix(&td, suffix)
        } else {
            td == p
        };
        if matches {
            return Ok(());
        }
    }
    Err(format!(
        "{entity_label} {td:?} is not allowed by {list_config_key}"
    ))
}

/// Returns `Ok` if issuer trust domain (normalized host) is allowed by at least one pattern.
/// Empty `allowlist` → always `Ok`.
pub fn trust_domain_matches_allowlist(
    trust_domain: &str,
    allowlist: &[String],
) -> Result<(), String> {
    hostname_matches_allowlist(
        trust_domain,
        allowlist,
        "trust domain",
        "machine_identity.trust_domain_allowlist",
    )
}

/// Same pattern language as trust-domain allowlist; `hostname` is the registered host from `token_endpoint`.
pub fn token_endpoint_domain_matches_allowlist(
    host: &str,
    allowlist: &[String],
) -> Result<(), String> {
    hostname_matches_allowlist(
        host,
        allowlist,
        "token_endpoint domain",
        "machine_identity.token_endpoint_domain_allowlist",
    )
}

fn validate_hostname_allowlist_patterns(
    entries: &[String],
    list_field: &str,
) -> Result<(), String> {
    for raw in entries {
        let p = normalize_allowlist_token(raw);
        if p.is_empty() {
            return Err(format!("{list_field}: empty entry (after trim)"));
        }
        if p.len() > MAX_ALLOWLIST_PATTERN_BYTES {
            return Err(format!(
                "{list_field}: pattern exceeds {MAX_ALLOWLIST_PATTERN_BYTES} bytes ({raw:?})"
            ));
        }
        if p == "*" || p == "**" {
            return Err(format!("{list_field}: bare `*` is not allowed ({raw:?})"));
        }
        if let Some(suffix) = p.strip_prefix("**.") {
            if suffix.is_empty() {
                return Err(format!("{list_field}: invalid pattern {raw:?}"));
            }
            if suffix.contains('*') {
                return Err(format!(
                    "{list_field}: `*` not allowed inside suffix ({raw:?})"
                ));
            }
        } else if let Some(suffix) = p.strip_prefix("*.") {
            if suffix.is_empty() {
                return Err(format!("{list_field}: invalid pattern {raw:?}"));
            }
            if suffix.contains('*') {
                return Err(format!(
                    "{list_field}: `*` not allowed inside suffix ({raw:?})"
                ));
            }
        } else if p.contains('*') {
            return Err(format!(
                "{list_field}: wildcards only as `*.` or `**.` prefix ({raw:?})"
            ));
        }
    }
    Ok(())
}

/// Validates `[machine_identity].trust_domain_allowlist` entries from config. Call at startup.
pub fn validate_trust_domain_allowlist_patterns(entries: &[String]) -> Result<(), String> {
    validate_hostname_allowlist_patterns(entries, "machine_identity.trust_domain_allowlist")
}

/// Validates `[machine_identity].token_endpoint_domain_allowlist` entries from config. Call at startup.
pub fn validate_token_endpoint_domain_allowlist_patterns(entries: &[String]) -> Result<(), String> {
    validate_hostname_allowlist_patterns(
        entries,
        "machine_identity.token_endpoint_domain_allowlist",
    )
}

/// `http` / `https` only; no userinfo, query, or fragment.
fn validate_token_endpoint_url(u: &Url) -> Result<(), String> {
    validate_url_no_query_fragment_userinfo(u, "token_endpoint")?;
    match u.scheme() {
        "http" | "https" => Ok(()),
        other => Err(format!(
            "token_endpoint: only http or https URLs are allowed (got {other:?})"
        )),
    }
}

/// RFC 8693 token endpoints: **`http://` and `https://` only** (no `spiffe://` or other schemes).
fn parse_token_endpoint_url(raw: &str) -> Result<Url, String> {
    let raw = raw.trim();
    enforce_max_len(raw.len(), MAX_ISSUER_BYTES, "token_endpoint")?;
    if !raw.contains("://") {
        return Err(
            "token_endpoint must be an http:// or https:// URL (bare hostnames are not supported)"
                .into(),
        );
    }
    reject_non_url_literal(raw, "token_endpoint")?;
    let u = Url::parse(raw).map_err(|e| format!("token_endpoint: invalid URL ({e})"))?;
    validate_token_endpoint_url(&u)?;
    Ok(u)
}

/// Parses `token_endpoint` when an allowlist is configured: registered DNS host, lowercase (rejects IP literals).
/// URL must use **`http` or `https`** scheme only.
pub fn registered_host_for_token_endpoint(token_endpoint: &str) -> Result<String, String> {
    let u = parse_token_endpoint_url(token_endpoint)?;
    validated_trust_domain_token(&u, "token_endpoint", "token_endpoint: URL must have a host")
}

/// `http` / `https` / `spiffe` only; no userinfo, query, or fragment.
fn validate_issuer_url(u: &Url) -> Result<(), String> {
    validate_url_no_query_fragment_userinfo(u, "issuer")?;
    match u.scheme() {
        "http" | "https" | "spiffe" => Ok(()),
        other => Err(format!(
            "issuer: only http, https, or spiffe URLs are allowed (got {other:?})"
        )),
    }
}

fn validate_subject_prefix_url(u: &Url) -> Result<(), String> {
    validate_url_no_query_fragment_userinfo(u, "subject_prefix")?;
    if u.scheme() != "spiffe" {
        return Err("subject_prefix must use the spiffe:// scheme".into());
    }
    Ok(())
}

fn default_subject_prefix(expected_td: &str) -> String {
    format!("spiffe://{expected_td}")
}

fn validate_path_segments(path_raw: &str) -> Result<Vec<&str>, String> {
    if path_raw.is_empty() {
        return Ok(Vec::new());
    }
    if path_raw.ends_with('/') {
        return Err(
            "subject_prefix path must not end with '/' (use spiffe://<td> for root only)".into(),
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
    enforce_max_len(raw.len(), MAX_SUBJECT_PREFIX_BYTES, "subject_prefix")?;
    reject_non_url_literal(raw, "subject_prefix")?;

    const PREFIX: &[u8] = b"spiffe://";
    let b = raw.as_bytes();
    if b.len() < PREFIX.len() || !b[..PREFIX.len()].eq_ignore_ascii_case(PREFIX) {
        return Err("subject_prefix must use the spiffe:// scheme".into());
    }

    let u = parse_identity_url(raw, "subject_prefix")?;
    validate_subject_prefix_url(&u)?;

    let td_norm = validated_trust_domain_token(
        &u,
        "subject_prefix",
        "subject_prefix is missing a trust domain after spiffe://",
    )?;
    if td_norm != expected_td {
        return Err(format!(
            "subject_prefix trust domain {:?} does not match issuer trust domain (expected {expected_td:?})",
            u.host_str().unwrap_or("")
        ));
    }

    let path_raw = spiffe_path_after_authority(&u);
    let segments = validate_path_segments(path_raw)?;
    if segments.is_empty() {
        Ok(default_subject_prefix(expected_td))
    } else {
        Ok(format!("spiffe://{expected_td}/{}", segments.join("/")))
    }
}

/// Resolves optional proto `subject_prefix`: default `spiffe://<expected_td>` or validated user value.
pub fn resolve_subject_prefix(
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
        let (_, td) = normalize_issuer_and_trust_domain(issuer)?;
        resolve_subject_prefix(&td, proto)
    }

    #[test]
    fn trust_domain_https_issuer() {
        assert_eq!(
            normalize_issuer_and_trust_domain("https://Issuer.EXAMPLE/path")
                .unwrap()
                .1,
            "issuer.example"
        );
    }

    #[test]
    fn trust_domain_https_issuer_optional_port() {
        assert_eq!(
            normalize_issuer_and_trust_domain("https://Issuer.EXAMPLE:8443/")
                .unwrap()
                .1,
            "issuer.example"
        );
    }

    #[test]
    fn trust_domain_https_issuer_rejects_query() {
        let err = normalize_issuer_and_trust_domain("https://issuer.example/?q=1").unwrap_err();
        assert!(err.contains("query"), "{err}");
    }

    #[test]
    fn trust_domain_spiffe_issuer() {
        assert_eq!(
            normalize_issuer_and_trust_domain("spiffe://Issuer.EXAMPLE/bundle")
                .unwrap()
                .1,
            "issuer.example"
        );
    }

    #[test]
    fn trust_domain_spiffe_issuer_scheme_any_case() {
        assert_eq!(
            normalize_issuer_and_trust_domain("SPIFFE://Issuer.EXAMPLE/bundle")
                .unwrap()
                .1,
            "issuer.example"
        );
        assert_eq!(
            normalize_issuer_and_trust_domain("SpIfFe://issuer.example")
                .unwrap()
                .1,
            "issuer.example"
        );
    }

    #[test]
    fn trust_domain_rejects_ip_host() {
        let err = normalize_issuer_and_trust_domain("https://127.0.0.1/").unwrap_err();
        assert!(err.contains("IP") || err.contains("not an IP"), "{err}");
        let err = normalize_issuer_and_trust_domain("spiffe://[::1]/x").unwrap_err();
        assert!(err.contains("IP"), "{err}");
    }

    #[test]
    fn resolve_identity_defaults_prefix() {
        assert_eq!(
            resolve_identity("https://my.idp.example", None).unwrap(),
            "spiffe://my.idp.example"
        );
    }

    #[test]
    fn resolve_identity_spiffe_form_issuer() {
        assert_eq!(
            resolve_identity("spiffe://my.idp.example/ns/x", None).unwrap(),
            "spiffe://my.idp.example"
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
        let err =
            resolve_identity("https://issuer.example", Some("spiffe://other.example")).unwrap_err();
        assert!(err.contains("does not match"));
    }

    #[test]
    fn percent_encoding_rejected() {
        let err = resolve_identity(
            "https://issuer.example",
            Some("spiffe://issuer.example/a%2Fb"),
        )
        .unwrap_err();
        assert!(err.contains("disallowed"), "{err}");
    }

    #[test]
    fn https_scheme_subject_prefix_rejected() {
        let err = resolve_identity("https://issuer.example", Some("https://issuer.example/p"))
            .unwrap_err();
        assert!(err.contains("spiffe://"));
    }

    #[test]
    fn https_userinfo_rejected() {
        let err = normalize_issuer_and_trust_domain("https://user@issuer.example/").unwrap_err();
        assert!(err.contains("userinfo"), "{err}");
    }

    #[test]
    fn https_password_in_userinfo_rejected() {
        let err =
            normalize_issuer_and_trust_domain("https://user:pass@issuer.example/").unwrap_err();
        assert!(err.contains("userinfo"), "{err}");
    }

    #[test]
    fn non_http_scheme_rejected() {
        let err = normalize_issuer_and_trust_domain("ftp://issuer.example/").unwrap_err();
        assert!(err.contains("http"), "{err}");
    }

    #[test]
    fn issuer_without_scheme_rejected() {
        let err = normalize_issuer_and_trust_domain("issuer.example").unwrap_err();
        assert!(err.contains("http://") || err.contains("https://"), "{err}");
        let err = normalize_issuer_and_trust_domain("issuer.example/extra").unwrap_err();
        assert!(err.contains("http://") || err.contains("bare"), "{err}");
    }

    #[test]
    fn issuer_backslash_rejected() {
        let err = normalize_issuer_and_trust_domain("https://issuer.example\\evil").unwrap_err();
        assert!(err.contains("disallowed"), "{err}");
    }

    #[test]
    fn issuer_too_long_rejected() {
        let long = format!("https://{}.example/", "a".repeat(MAX_ISSUER_BYTES));
        let err = normalize_issuer_and_trust_domain(&long).unwrap_err();
        assert!(err.contains("maximum length"), "{err}");
    }

    #[test]
    fn issuer_control_char_rejected() {
        let err = normalize_issuer_and_trust_domain("https://issuer.ex\0ample.com/").unwrap_err();
        assert!(err.contains("disallowed") || err.contains("ASCII"), "{err}");
    }

    #[test]
    fn subject_prefix_backslash_rejected() {
        let err = resolve_identity(
            "https://issuer.example",
            Some("spiffe://issuer.example/a\\b"),
        )
        .unwrap_err();
        assert!(err.contains("disallowed"), "{err}");
    }

    #[test]
    fn subject_prefix_whitespace_rejected() {
        let err = resolve_identity(
            "https://issuer.example",
            Some("spiffe://issuer.example/a b"),
        )
        .unwrap_err();
        assert!(err.contains("disallowed"), "{err}");
    }

    #[test]
    fn dns_trust_domain_too_long_rejected() {
        let label = "a".repeat(63);
        let host = std::iter::repeat_n(label.as_str(), 5)
            .collect::<Vec<_>>()
            .join(".");
        assert!(host.len() > MAX_TRUST_DOMAIN_BYTES);
        let issuer = format!("https://{host}/");
        let err = normalize_issuer_and_trust_domain(&issuer).unwrap_err();
        assert!(err.contains("maximum length"), "{err}");
    }

    #[test]
    fn subject_prefix_too_long_rejected() {
        let base = "spiffe://issuer.example";
        let pad_len = MAX_SUBJECT_PREFIX_BYTES.saturating_sub(base.len()) + 1;
        let prefix = format!("{base}{}", "x".repeat(pad_len));
        assert!(prefix.len() > MAX_SUBJECT_PREFIX_BYTES);
        let err = resolve_identity("https://issuer.example", Some(&prefix)).unwrap_err();
        assert!(err.contains("maximum length"), "{err}");
    }

    #[test]
    fn many_path_segments_ok_within_byte_limit() {
        let segs = std::iter::repeat_n("w", 200).collect::<Vec<_>>().join("/");
        let prefix = format!("spiffe://issuer.example/{segs}");
        assert!(prefix.len() <= MAX_SUBJECT_PREFIX_BYTES);
        let p = resolve_identity("https://issuer.example", Some(&prefix)).unwrap();
        assert!(p.matches('/').count() >= 200);
    }

    #[test]
    fn normalize_issuer_preserves_scheme_path_and_port() {
        assert_eq!(
            normalize_issuer_and_trust_domain("HTTP://Issuer.EXAMPLE/path")
                .unwrap()
                .0,
            "http://issuer.example/path"
        );
        assert_eq!(
            normalize_issuer_and_trust_domain("https://issuer.example:8443/ns")
                .unwrap()
                .0,
            "https://issuer.example:8443/ns"
        );
        assert_eq!(
            normalize_issuer_and_trust_domain("SpIfFe://Issuer.EXAMPLE/bundle")
                .unwrap()
                .0,
            "spiffe://issuer.example/bundle"
        );
    }

    #[test]
    fn allowlist_empty_allows_any_trust_domain() {
        assert!(trust_domain_matches_allowlist("anything.example", &[]).is_ok());
    }

    #[test]
    fn allowlist_exact_match() {
        let list = vec!["login.example.com".to_string(), "other.net".to_string()];
        assert!(trust_domain_matches_allowlist("login.example.com", &list).is_ok());
        assert!(trust_domain_matches_allowlist("LOGIN.EXAMPLE.COM.", &list).is_ok());
        assert!(trust_domain_matches_allowlist("bad.example.com", &list).is_err());
    }

    #[test]
    fn allowlist_single_star_one_label_under_suffix() {
        let list = vec!["*.something.net".to_string()];
        assert!(trust_domain_matches_allowlist("auth.something.net", &list).is_ok());
        assert!(trust_domain_matches_allowlist("something.net", &list).is_err());
        assert!(trust_domain_matches_allowlist("a.b.something.net", &list).is_err());
        assert!(
            trust_domain_matches_allowlist("notsomething.net", &list).is_err(),
            "dot boundary"
        );
    }

    #[test]
    fn allowlist_double_star_any_depth() {
        let list = vec!["**.internal.example".to_string()];
        assert!(trust_domain_matches_allowlist("internal.example", &list).is_ok());
        assert!(trust_domain_matches_allowlist("x.internal.example", &list).is_ok());
        assert!(trust_domain_matches_allowlist("a.b.internal.example", &list).is_ok());
        assert!(trust_domain_matches_allowlist("evil.internal.example.evil.com", &list).is_err());
    }

    #[test]
    fn allowlist_pattern_validation_rejects_bare_star() {
        assert!(validate_trust_domain_allowlist_patterns(&["*".to_string()]).is_err());
        assert!(validate_trust_domain_allowlist_patterns(&["**".to_string()]).is_err());
        assert!(validate_trust_domain_allowlist_patterns(&["*.".to_string()]).is_err());
        assert!(validate_trust_domain_allowlist_patterns(&["foo*bar".to_string()]).is_err());
        assert!(validate_trust_domain_allowlist_patterns(&["login.example".to_string()]).is_ok());
    }

    /// `*.suffix` must not match when there are two or more labels between leaf and suffix.
    #[test]
    fn allowlist_single_star_rejects_multi_label_under_suffix() {
        let list = vec!["*.something.net".to_string()];
        assert!(
            trust_domain_matches_allowlist("auth.prod.something.net", &list).is_err(),
            "only one label allowed above the suffix"
        );
    }

    /// `*.suffix` accepts a single DNS label (no dots) above the suffix.
    #[test]
    fn allowlist_single_star_accepts_one_label_mixed_case_pattern() {
        let list = vec!["*.SOMETHING.NET".to_string()];
        assert!(trust_domain_matches_allowlist("auth.something.net", &list).is_ok());
    }

    /// `**.suffix` must not match hosts that merely share a substring with suffix (dot-separated).
    #[test]
    fn allowlist_double_star_suffix_requires_dot_separated_zone() {
        let list = vec!["**.internal.example".to_string()];
        assert!(
            trust_domain_matches_allowlist("api.internal.example.com", &list).is_err(),
            "must end with .internal.example, not .internal.example.com"
        );
        assert!(
            trust_domain_matches_allowlist("not-relevant.internal.example.evil.com", &list)
                .is_err(),
        );
    }

    /// `**.suffix`: bare suffix and immediate child; `suffix` alone is the zone apex in pattern.
    #[test]
    fn allowlist_double_star_suffix_apex_and_subdomain() {
        let list = vec!["**.co.uk".to_string()];
        assert!(trust_domain_matches_allowlist("co.uk", &list).is_ok());
        assert!(trust_domain_matches_allowlist("tenant.co.uk", &list).is_ok());
        assert!(trust_domain_matches_allowlist("a.b.co.uk", &list).is_ok());
        assert!(trust_domain_matches_allowlist("other.uk", &list).is_err());
    }

    #[test]
    fn allowlist_matches_if_any_pattern_matches() {
        let list = vec!["exact.only".to_string(), "**.allowed.zone".to_string()];
        assert!(trust_domain_matches_allowlist("exact.only", &list).is_ok());
        assert!(trust_domain_matches_allowlist("x.allowed.zone", &list).is_ok());
        assert!(trust_domain_matches_allowlist("wrong.zone", &list).is_err());
    }

    /// Several allowlist entries at once: literal, `*.suffix`, and `**.suffix`; match is OR across entries.
    #[test]
    fn allowlist_multiple_entries_mixed_literal_and_wildcards() {
        let list = vec![
            "idp.example.com".to_string(),
            "localhost".to_string(),
            "*.tenant.example.net".to_string(),
            "**.corp.internal".to_string(),
        ];
        assert!(
            validate_trust_domain_allowlist_patterns(&list).is_ok(),
            "whole list must pass startup validation"
        );

        assert!(trust_domain_matches_allowlist("idp.example.com", &list).is_ok());
        assert!(trust_domain_matches_allowlist("LOCALHOST", &list).is_ok());
        assert!(trust_domain_matches_allowlist("auth.tenant.example.net", &list).is_ok());
        assert!(trust_domain_matches_allowlist("corp.internal", &list).is_ok());
        assert!(trust_domain_matches_allowlist("a.b.corp.internal", &list).is_ok());

        assert!(trust_domain_matches_allowlist("other.example.com", &list).is_err());
        assert!(trust_domain_matches_allowlist("auth.app.tenant.example.net", &list).is_err());
        assert!(trust_domain_matches_allowlist("not.corp.internal.evil.com", &list).is_err());
    }

    #[test]
    fn allowlist_patterns_trim_and_strip_trailing_dot() {
        let list = vec!["  *.Foo.COM.  ".to_string()];
        assert!(trust_domain_matches_allowlist("bar.foo.com", &list).is_ok());
    }

    #[test]
    fn validate_allowlist_rejects_empty_suffix_after_wildcard_prefix() {
        assert!(validate_trust_domain_allowlist_patterns(&["**.".to_string()]).is_err());
        assert!(validate_trust_domain_allowlist_patterns(&["*.".to_string()]).is_err());
    }

    #[test]
    fn validate_allowlist_rejects_star_inside_suffix() {
        assert!(validate_trust_domain_allowlist_patterns(&["**.foo.*.com".to_string()]).is_err());
        assert!(validate_trust_domain_allowlist_patterns(&["*.foo*bar.com".to_string()]).is_err());
    }

    #[test]
    fn validate_allowlist_rejects_empty_entry_after_trim() {
        assert!(validate_trust_domain_allowlist_patterns(&["   ".to_string()]).is_err());
        assert!(validate_trust_domain_allowlist_patterns(&["  \t ".to_string()]).is_err(),);
    }

    #[test]
    fn validate_allowlist_accepts_double_star_multi_label_suffix() {
        assert!(
            validate_trust_domain_allowlist_patterns(&["**.svc.cluster.local".to_string()]).is_ok()
        );
    }

    /// `notinternal.example` must not satisfy `*.internal.example` (no dot before `internal`).
    #[test]
    fn allowlist_single_star_dot_boundary_before_suffix() {
        let list = vec!["*.internal.example".to_string()];
        assert!(trust_domain_matches_allowlist("svc.internal.example", &list).is_ok());
        assert!(trust_domain_matches_allowlist("notinternal.example", &list).is_err());
    }

    #[test]
    fn token_endpoint_url_accepts_http_and_https_only() {
        assert_eq!(
            registered_host_for_token_endpoint("https://auth.example.com/oauth/token").unwrap(),
            "auth.example.com"
        );
        assert_eq!(
            registered_host_for_token_endpoint("http://auth.example:8080/token").unwrap(),
            "auth.example"
        );
        let err = registered_host_for_token_endpoint("spiffe://trust.example/path").unwrap_err();
        assert!(
            err.contains("http") && err.contains("https"),
            "unexpected err: {err}"
        );
        let err = registered_host_for_token_endpoint("ftp://auth.example/token").unwrap_err();
        assert!(err.contains("http") || err.contains("https"), "{err}");
    }
}
