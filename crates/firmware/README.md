# carbide-firmware

Firmware metadata loading and lookup for Carbide.

## Overview

This crate owns the runtime loading logic for firmware metadata used
by Carbide services. It loads firmware definitions from two sources:

- Entries embedded in the main Carbide configuration file (host and
  DPU models).
- `metadata.toml` files discovered under a configured
  `firmware_directory` on disk.

Entries from both sources are merged into a single in-memory map
keyed by vendor and model, with conflict-resolution rules that let
newer on-disk metadata extend or override older entries.

## Scope

This crate is intentionally narrow:

- It depends on the firmware **data types** (`Firmware`,
  `FirmwareEntry`, `FirmwareComponentType`, ...) which live in
  `carbide-api-model`. Those types describe firmware; this crate
  loads and queries them.
- It does **not** define the top-level configuration file schema.
  Knobs like `firmware_directory` are part of `FirmwareGlobal` in
  `carbide-api`.
- It does **not** perform firmware upgrades, version comparison, or
  artifact fetching. Those concerns live in `carbide-api` and
  `carbide-scout`.

## Key types

### `FirmwareConfig`

The main entry point. Constructed from a base map (populated from
`CarbideConfig`) and a `firmware_directory` path. Offers lookup
methods keyed by vendor + model:

- `find(vendor, model)` — look up firmware metadata for a specific
  vendor/model pair.
- `find_fw_info_for_host(endpoint)` — look up firmware metadata for
  an explored endpoint.
- `find_fw_info_for_host_report(report)` — same, given the
  exploration report directly.

It also exposes disk-state observation:

- `map()` — produce the merged firmware map (reads disk each call).
- `config_update_time()` — modification time of `firmware_directory`,
  used by callers that want to detect on-disk changes.

## Loading behavior

`FirmwareConfig` is a **live view** over the firmware directory, not
a snapshot. Every call to a lookup method re-reads the directory,
parses every `metadata.toml`, and re-merges the entries on top of
the base map.

This lets operators add new firmware metadata at runtime without
restarting Carbide: the next lookup picks it up. Consumers that want
cheap in-memory lookups (or explicit snapshot semantics) should
cache the result themselves.

Merge rules, applied in oldest-to-newest directory order:

- A new vendor/model combination is inserted as-is.
- A newer `ordering` replaces the existing one (non-empty only).
- `explicit_start_needed = true` always wins.
- Per-component fields (`current_version_reported_as`,
  `preingest_upgrade_when_below`) are overwritten if the newer
  entry sets them.
- `known_firmware` entries are appended. If a newer entry marks one
  of its firmware versions as `default`, the `default` flag is
  cleared on all previously-registered entries for that component.

## Consumers

Currently used (directly or indirectly) by:

- `carbide-api`: `cfg/file.rs` (construction),
  `machine_update_manager` (hot-reload detection),
  `handlers/firmware.rs` (HTTP API), `preingestion_manager`,
  `site_explorer`, `state_controller`, tests.

## Future direction

`FirmwareConfig` currently fuses "loader" (disk I/O, merging) and
"catalog" (in-memory lookup) into a single type. A follow-up change
is expected to split this into:

- `FirmwareCatalog` — pure data, O(1) lookup.
- `FirmwareConfigLoader` — disk I/O, produces a `FirmwareCatalog`.

with consumers that want hot-reload holding an
`Arc<ArcSwap<FirmwareCatalog>>` refreshed by a background task. See
the enclosing carbide-api refactor notes for details.

## License

Apache-2.0. See `LICENSE` at the workspace root.
