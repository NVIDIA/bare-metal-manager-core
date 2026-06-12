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
    use carbide_test_support::Outcome::*;
    use carbide_test_support::{Case, check_cases};

    use super::*;

    fn resolve_identity(issuer: &str, proto: Option<&str>) -> Result<String, String> {
        let (_, td) = normalize_issuer_and_trust_domain(issuer)?;
        resolve_subject_prefix(&td, proto)
    }

    // Issuer trust-domain extraction (the `.1` of `normalize_issuer_and_trust_domain`).
    // Each row is `(issuer, error_substring)`: success rows `Yields` the lowercased trust
    // domain (the substring is unused, left ""); rejection rows assert the error contains the
    // given token via `FailsWith(true)`. The `String` error is not the asserted contract here
    // (the originals only checked substrings), so we project the error to "does it contain token".
    #[test]
    fn issuer_trust_domain_extraction() {
        check_cases(
            [
                Case {
                    scenario: "https issuer lowercases host, drops path",
                    input: ("https://Issuer.EXAMPLE/path", ""),
                    expect: Yields("issuer.example".to_string()),
                },
                Case {
                    scenario: "https issuer with explicit port",
                    input: ("https://Issuer.EXAMPLE:8443/", ""),
                    expect: Yields("issuer.example".to_string()),
                },
                Case {
                    scenario: "spiffe issuer lowercases host",
                    input: ("spiffe://Issuer.EXAMPLE/bundle", ""),
                    expect: Yields("issuer.example".to_string()),
                },
                Case {
                    scenario: "spiffe scheme uppercase",
                    input: ("SPIFFE://Issuer.EXAMPLE/bundle", ""),
                    expect: Yields("issuer.example".to_string()),
                },
                Case {
                    scenario: "spiffe scheme mixed case, no path",
                    input: ("SpIfFe://issuer.example", ""),
                    expect: Yields("issuer.example".to_string()),
                },
                Case {
                    scenario: "query string rejected",
                    input: ("https://issuer.example/?q=1", "query"),
                    expect: FailsWith(true),
                },
                Case {
                    scenario: "ipv4 host rejected",
                    input: ("https://127.0.0.1/", "IP"),
                    expect: FailsWith(true),
                },
                Case {
                    scenario: "ipv6 host rejected",
                    input: ("spiffe://[::1]/x", "IP"),
                    expect: FailsWith(true),
                },
                Case {
                    scenario: "userinfo (user only) rejected",
                    input: ("https://user@issuer.example/", "userinfo"),
                    expect: FailsWith(true),
                },
                Case {
                    scenario: "userinfo with password rejected",
                    input: ("https://user:pass@issuer.example/", "userinfo"),
                    expect: FailsWith(true),
                },
                Case {
                    scenario: "non-http(s)/spiffe scheme rejected",
                    input: ("ftp://issuer.example/", "http"),
                    expect: FailsWith(true),
                },
                Case {
                    scenario: "bare hostname (no scheme) rejected",
                    input: ("issuer.example", "http://"),
                    expect: FailsWith(true),
                },
                Case {
                    scenario: "bare hostname with path rejected",
                    input: ("issuer.example/extra", "http://"),
                    expect: FailsWith(true),
                },
                Case {
                    scenario: "backslash rejected",
                    input: ("https://issuer.example\\evil", "disallowed"),
                    expect: FailsWith(true),
                },
                Case {
                    scenario: "control char rejected",
                    input: ("https://issuer.ex\0ample.com/", "disallowed"),
                    expect: FailsWith(true),
                },
            ],
            |(issuer, token)| {
                normalize_issuer_and_trust_domain(issuer)
                    .map(|(_, td)| td)
                    .map_err(|e| e.contains(token))
            },
        );
    }

    // Normalized `iss` string (the `.0` of `normalize_issuer_and_trust_domain`): scheme/path/port
    // preservation, host lowercasing, default lone-`/` path omitted. All success rows.
    #[test]
    fn normalize_issuer_preserves_scheme_path_and_port() {
        check_cases(
            [
                Case {
                    scenario: "http scheme and path lowercased host",
                    input: "HTTP://Issuer.EXAMPLE/path",
                    expect: Yields("http://issuer.example/path".to_string()),
                },
                Case {
                    scenario: "explicit port and path preserved",
                    input: "https://issuer.example:8443/ns",
                    expect: Yields("https://issuer.example:8443/ns".to_string()),
                },
                Case {
                    scenario: "spiffe scheme normalized",
                    input: "SpIfFe://Issuer.EXAMPLE/bundle",
                    expect: Yields("spiffe://issuer.example/bundle".to_string()),
                },
            ],
            |s| {
                normalize_issuer_and_trust_domain(s)
                    .map(|(iss, _)| iss)
                    .map_err(drop)
            },
        );
    }

    // Subject-prefix resolution end-to-end (`resolve_identity`). Rows are `(issuer, proto, token)`:
    // success rows `Yields` the canonical prefix (token unused, ""); rejection rows assert the
    // error contains `token` via `FailsWith(true)`.
    #[test]
    fn resolve_subject_prefix_cases() {
        check_cases(
            [
                Case {
                    scenario: "no proto prefix -> default from https issuer",
                    input: ("https://my.idp.example", None, ""),
                    expect: Yields("spiffe://my.idp.example".to_string()),
                },
                Case {
                    scenario: "no proto prefix -> default from spiffe issuer",
                    input: ("spiffe://my.idp.example/ns/x", None, ""),
                    expect: Yields("spiffe://my.idp.example".to_string()),
                },
                Case {
                    scenario: "explicit prefix canonicalizes trust-domain case",
                    input: (
                        "https://issuer.example",
                        Some("spiffe://ISSUER.EXAMPLE/wl"),
                        "",
                    ),
                    expect: Yields("spiffe://issuer.example/wl".to_string()),
                },
                Case {
                    scenario: "trust domain mismatch rejected",
                    input: (
                        "https://issuer.example",
                        Some("spiffe://other.example"),
                        "does not match",
                    ),
                    expect: FailsWith(true),
                },
                Case {
                    scenario: "percent-encoding rejected",
                    input: (
                        "https://issuer.example",
                        Some("spiffe://issuer.example/a%2Fb"),
                        "disallowed",
                    ),
                    expect: FailsWith(true),
                },
                Case {
                    scenario: "https scheme prefix rejected (must be spiffe)",
                    input: (
                        "https://issuer.example",
                        Some("https://issuer.example/p"),
                        "spiffe://",
                    ),
                    expect: FailsWith(true),
                },
                Case {
                    scenario: "backslash in prefix rejected",
                    input: (
                        "https://issuer.example",
                        Some("spiffe://issuer.example/a\\b"),
                        "disallowed",
                    ),
                    expect: FailsWith(true),
                },
                Case {
                    scenario: "whitespace in prefix rejected",
                    input: (
                        "https://issuer.example",
                        Some("spiffe://issuer.example/a b"),
                        "disallowed",
                    ),
                    expect: FailsWith(true),
                },
            ],
            |(issuer, proto, token)| resolve_identity(issuer, proto).map_err(|e| e.contains(token)),
        );
    }

    // Length-limit rejections build runtime strings, so they stay out of the literal-input tables.
    #[test]
    fn issuer_too_long_rejected() {
        let long = format!("https://{}.example/", "a".repeat(MAX_ISSUER_BYTES));
        let err = normalize_issuer_and_trust_domain(&long).unwrap_err();
        assert!(err.contains("maximum length"), "{err}");
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

    // Hostname/trust-domain allowlist matching (`trust_domain_matches_allowlist`). Rows are
    // `(hostname, patterns)`: the originals only checked `is_ok()`/`is_err()`, so we map to
    // `Yields(())` / `Fails` (error discarded). Each row carries its own pattern list.
    #[test]
    fn trust_domain_allowlist_matching() {
        fn list(entries: &[&str]) -> Vec<String> {
            entries.iter().map(|s| s.to_string()).collect()
        }
        check_cases(
            [
                Case {
                    scenario: "empty allowlist allows any host",
                    input: ("anything.example", list(&[])),
                    expect: Yields(()),
                },
                Case {
                    scenario: "exact match",
                    input: (
                        "login.example.com",
                        list(&["login.example.com", "other.net"]),
                    ),
                    expect: Yields(()),
                },
                Case {
                    scenario: "exact match ignores case and trailing dot",
                    input: (
                        "LOGIN.EXAMPLE.COM.",
                        list(&["login.example.com", "other.net"]),
                    ),
                    expect: Yields(()),
                },
                Case {
                    scenario: "exact mismatch",
                    input: ("bad.example.com", list(&["login.example.com", "other.net"])),
                    expect: Fails,
                },
                Case {
                    scenario: "single-star: one label under suffix matches",
                    input: ("auth.something.net", list(&["*.something.net"])),
                    expect: Yields(()),
                },
                Case {
                    scenario: "single-star: bare suffix does not match",
                    input: ("something.net", list(&["*.something.net"])),
                    expect: Fails,
                },
                Case {
                    scenario: "single-star: two labels under suffix do not match",
                    input: ("a.b.something.net", list(&["*.something.net"])),
                    expect: Fails,
                },
                Case {
                    scenario: "single-star: dot boundary before suffix",
                    input: ("notsomething.net", list(&["*.something.net"])),
                    expect: Fails,
                },
                Case {
                    scenario: "double-star: bare suffix matches",
                    input: ("internal.example", list(&["**.internal.example"])),
                    expect: Yields(()),
                },
                Case {
                    scenario: "double-star: one label deep matches",
                    input: ("x.internal.example", list(&["**.internal.example"])),
                    expect: Yields(()),
                },
                Case {
                    scenario: "double-star: many labels deep match",
                    input: ("a.b.internal.example", list(&["**.internal.example"])),
                    expect: Yields(()),
                },
                Case {
                    scenario: "double-star: suffix not at end does not match",
                    input: (
                        "evil.internal.example.evil.com",
                        list(&["**.internal.example"]),
                    ),
                    expect: Fails,
                },
                Case {
                    scenario: "single-star: multi-label under suffix rejected",
                    input: ("auth.prod.something.net", list(&["*.something.net"])),
                    expect: Fails,
                },
                Case {
                    scenario: "single-star: one label matches mixed-case pattern",
                    input: ("auth.something.net", list(&["*.SOMETHING.NET"])),
                    expect: Yields(()),
                },
                Case {
                    scenario: "double-star: suffix as substring of longer zone rejected",
                    input: ("api.internal.example.com", list(&["**.internal.example"])),
                    expect: Fails,
                },
                Case {
                    scenario: "double-star: suffix mid-host rejected",
                    input: (
                        "not-relevant.internal.example.evil.com",
                        list(&["**.internal.example"]),
                    ),
                    expect: Fails,
                },
                Case {
                    scenario: "double-star: zone apex matches",
                    input: ("co.uk", list(&["**.co.uk"])),
                    expect: Yields(()),
                },
                Case {
                    scenario: "double-star: child of apex matches",
                    input: ("tenant.co.uk", list(&["**.co.uk"])),
                    expect: Yields(()),
                },
                Case {
                    scenario: "double-star: deep child of apex matches",
                    input: ("a.b.co.uk", list(&["**.co.uk"])),
                    expect: Yields(()),
                },
                Case {
                    scenario: "double-star: different apex rejected",
                    input: ("other.uk", list(&["**.co.uk"])),
                    expect: Fails,
                },
                Case {
                    scenario: "OR across entries: literal matches",
                    input: ("exact.only", list(&["exact.only", "**.allowed.zone"])),
                    expect: Yields(()),
                },
                Case {
                    scenario: "OR across entries: double-star matches",
                    input: ("x.allowed.zone", list(&["exact.only", "**.allowed.zone"])),
                    expect: Yields(()),
                },
                Case {
                    scenario: "OR across entries: neither matches",
                    input: ("wrong.zone", list(&["exact.only", "**.allowed.zone"])),
                    expect: Fails,
                },
                Case {
                    scenario: "mixed list: literal host matches",
                    input: (
                        "idp.example.com",
                        list(&[
                            "idp.example.com",
                            "localhost",
                            "*.tenant.example.net",
                            "**.corp.internal",
                        ]),
                    ),
                    expect: Yields(()),
                },
                Case {
                    scenario: "mixed list: literal host case-insensitive",
                    input: (
                        "LOCALHOST",
                        list(&[
                            "idp.example.com",
                            "localhost",
                            "*.tenant.example.net",
                            "**.corp.internal",
                        ]),
                    ),
                    expect: Yields(()),
                },
                Case {
                    scenario: "mixed list: single-star matches",
                    input: (
                        "auth.tenant.example.net",
                        list(&[
                            "idp.example.com",
                            "localhost",
                            "*.tenant.example.net",
                            "**.corp.internal",
                        ]),
                    ),
                    expect: Yields(()),
                },
                Case {
                    scenario: "mixed list: double-star apex matches",
                    input: (
                        "corp.internal",
                        list(&[
                            "idp.example.com",
                            "localhost",
                            "*.tenant.example.net",
                            "**.corp.internal",
                        ]),
                    ),
                    expect: Yields(()),
                },
                Case {
                    scenario: "mixed list: double-star deep matches",
                    input: (
                        "a.b.corp.internal",
                        list(&[
                            "idp.example.com",
                            "localhost",
                            "*.tenant.example.net",
                            "**.corp.internal",
                        ]),
                    ),
                    expect: Yields(()),
                },
                Case {
                    scenario: "mixed list: unrelated literal rejected",
                    input: (
                        "other.example.com",
                        list(&[
                            "idp.example.com",
                            "localhost",
                            "*.tenant.example.net",
                            "**.corp.internal",
                        ]),
                    ),
                    expect: Fails,
                },
                Case {
                    scenario: "mixed list: single-star too deep rejected",
                    input: (
                        "auth.app.tenant.example.net",
                        list(&[
                            "idp.example.com",
                            "localhost",
                            "*.tenant.example.net",
                            "**.corp.internal",
                        ]),
                    ),
                    expect: Fails,
                },
                Case {
                    scenario: "mixed list: double-star suffix mid-host rejected",
                    input: (
                        "not.corp.internal.evil.com",
                        list(&[
                            "idp.example.com",
                            "localhost",
                            "*.tenant.example.net",
                            "**.corp.internal",
                        ]),
                    ),
                    expect: Fails,
                },
                Case {
                    scenario: "pattern trimmed and trailing-dot stripped",
                    input: ("bar.foo.com", list(&["  *.Foo.COM.  "])),
                    expect: Yields(()),
                },
                Case {
                    scenario: "single-star: dot boundary, one label matches",
                    input: ("svc.internal.example", list(&["*.internal.example"])),
                    expect: Yields(()),
                },
                Case {
                    scenario: "single-star: no dot before suffix rejected",
                    input: ("notinternal.example", list(&["*.internal.example"])),
                    expect: Fails,
                },
            ],
            |(hostname, patterns)| {
                trust_domain_matches_allowlist(hostname, &patterns).map_err(drop)
            },
        );
    }

    // Allowlist pattern validation (`validate_trust_domain_allowlist_patterns`). Each row is one
    // entry list; the originals only checked `is_ok()`/`is_err()`, so `Yields(())` / `Fails`.
    #[test]
    fn trust_domain_allowlist_pattern_validation() {
        fn list(entries: &[&str]) -> Vec<String> {
            entries.iter().map(|s| s.to_string()).collect()
        }
        check_cases(
            [
                Case {
                    scenario: "bare `*` rejected",
                    input: list(&["*"]),
                    expect: Fails,
                },
                Case {
                    scenario: "bare `**` rejected",
                    input: list(&["**"]),
                    expect: Fails,
                },
                Case {
                    scenario: "`*.` (empty suffix) rejected",
                    input: list(&["*."]),
                    expect: Fails,
                },
                Case {
                    scenario: "wildcard inside label rejected",
                    input: list(&["foo*bar"]),
                    expect: Fails,
                },
                Case {
                    scenario: "plain hostname accepted",
                    input: list(&["login.example"]),
                    expect: Yields(()),
                },
                Case {
                    scenario: "`**.` (empty suffix) rejected",
                    input: list(&["**."]),
                    expect: Fails,
                },
                Case {
                    scenario: "`*.` (empty suffix) rejected again",
                    input: list(&["*."]),
                    expect: Fails,
                },
                Case {
                    scenario: "star inside double-star suffix rejected",
                    input: list(&["**.foo.*.com"]),
                    expect: Fails,
                },
                Case {
                    scenario: "star inside single-star suffix rejected",
                    input: list(&["*.foo*bar.com"]),
                    expect: Fails,
                },
                Case {
                    scenario: "whitespace-only entry rejected",
                    input: list(&["   "]),
                    expect: Fails,
                },
                Case {
                    scenario: "tab/space-only entry rejected",
                    input: list(&["  \t "]),
                    expect: Fails,
                },
                Case {
                    scenario: "double-star multi-label suffix accepted",
                    input: list(&["**.svc.cluster.local"]),
                    expect: Yields(()),
                },
                Case {
                    scenario: "mixed valid list passes startup validation",
                    input: list(&[
                        "idp.example.com",
                        "localhost",
                        "*.tenant.example.net",
                        "**.corp.internal",
                    ]),
                    expect: Yields(()),
                },
            ],
            |patterns| validate_trust_domain_allowlist_patterns(&patterns).map_err(drop),
        );
    }

    // Token-endpoint registered-host extraction (`registered_host_for_token_endpoint`): http/https
    // only. Rows are `(endpoint, token)`: success rows `Yields` the host (token ""); rejection rows
    // assert the error contains `token` via `FailsWith(true)`.
    #[test]
    fn token_endpoint_url_accepts_http_and_https_only() {
        check_cases(
            [
                Case {
                    scenario: "https endpoint -> host",
                    input: ("https://auth.example.com/oauth/token", &[][..]),
                    expect: Yields("auth.example.com".to_string()),
                },
                Case {
                    scenario: "http endpoint with port -> host",
                    input: ("http://auth.example:8080/token", &[][..]),
                    expect: Yields("auth.example".to_string()),
                },
                Case {
                    scenario: "spiffe scheme rejected",
                    input: ("spiffe://trust.example/path", &["http", "https"][..]),
                    expect: FailsWith(true),
                },
                Case {
                    scenario: "ftp scheme rejected",
                    input: ("ftp://auth.example/token", &["http"][..]),
                    expect: FailsWith(true),
                },
            ],
            // Rejection rows require every listed token in the error, preserving the
            // original's independent contains("http") && contains("https") check
            // rather than coupling to one exact phrase.
            |(endpoint, tokens)| {
                registered_host_for_token_endpoint(endpoint)
                    .map_err(|e| tokens.iter().all(|t| e.contains(t)))
            },
        );
    }
}
