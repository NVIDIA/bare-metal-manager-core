# Changelog

All notable changes to `carbide-ipmitool` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- IPMI v1.5 LAN transport (`-I lan`) for BMCs that do not support
  RMCP+ (IPMI v2.0), with MD5 and None authentication types
- Interactive SOL terminal session with bidirectional I/O, terminal raw
  mode, and `~`-prefixed escape sequences (`~.` disconnect, `~B` break,
  `~~` literal tilde, `~?` help)
- SOL payload type support in `build_authenticated_packet` (previously
  hardcoded to IPMI payload type)

### Changed

### Deprecated

### Removed

### Fixed

### Security

## [0.1.0] — 2026-03-13

Initial implementation of the pure-Rust IPMI v2.0 RMCP+ client library
and CLI binary, replacing the C `ipmitool` dependency.

### Added

- IPMI v2.0 types, error handling, and crypto primitives (HMAC-SHA1,
  HMAC-SHA256, HMAC-MD5, AES-CBC-128 with IPMI-custom padding, session
  key derivation) — aa7737d
- RMCP+ session establishment with full RAKP 1-4 mutual authentication
  handshake and cipher suite negotiation (cipher suite 17 default) — e957b4a
- Core IPMI commands: chassis power control/status/policy, MC device
  info/reset/watchdog, raw command passthrough — 11740dd
- CLI binary (`carbide-ipmitool`) with clap-based argument parsing,
  verbosity levels, and colored error output — 11740dd
- Data commands: SDR repository iteration with sensor name lookup, SEL
  event log with clear, FRU inventory read, and live sensor readings
  with unit conversion and linearization — 9f63eb2
- User management: list/summary/set-name/set-password/enable/disable
  and channel access/info queries — 28026e5
- SOL activation, deactivation, configuration get/set (enable, baud
  rate), and info display — 4ca3aa6
- `MockTransport` and `QueueMockTransport` for unit testing IPMI
  command logic without network access
