# NICo Logging

How NICo services emit logs, the structured fields each line carries, and how to set log levels.

---

## TL;DR

- **Most** NICo services log in **[logfmt](https://brandur.org/logfmt)** (`key=value` pairs) to **stdout**;
  a few use other formats (e.g. `nico-dns` emits JSON — see [Coverage](#coverage)).
- Every **logfmt** line begins with `level=` and carries a **`component=`** field identifying the emitting
  component, so logs can be filtered by component instead of grepping the message text.
- Log verbosity is controlled by `RUST_LOG` (default `info`).
- For distributed **tracing** (spans exported via OTLP), see [Traces](tracing.md).

## Log format

There are two kinds of line.

**Events** — one per log call:
```
level=INFO component=nico-api span_id=0x4f… msg="…" location="crates/api-core/src/…"
```

**Spans** — emitted when a unit of work closes (`level=SPAN`), carrying the span name, id, its attributes,
and timing:
```
level=SPAN component=site-explorer span_id=0xf7… span_name=explore_site timing_elapsed_us=… timing_busy_ns=… timing_idle_ns=…
```

Common keys: `level`, `component`, `msg`, `location` (`file:line`); `span_id` when the line is inside a
span; plus any structured fields the call site adds (e.g. `controller=`, `object_id=`).

## Log level

Verbosity is an [`EnvFilter`](https://docs.rs/tracing-subscriber) directive set from `RUST_LOG`, defaulting
to `info`:
```
RUST_LOG=debug
RUST_LOG=info,carbide_site_explorer=debug   # raise one module
```
`nico-api` can also adjust its filter at runtime via `nico-admin-cli set log-filter`.

## The `component` field

On logfmt lines, NICo sets the `component` field to one of the following:

```
nico-api                       — API handlers, DB, startup: anything not in a subsystem below
├── site-explorer
├── machine_state_controller
├── switch_controller
├── rack_controller
├── power_shelf_controller
├── network_segments_controller
├── vpc_prefix_controller
├── ib_partition_controller
└── attestation_controller
nico-bmc-proxy
nico-dhcp
nico-dsx-exchange-consumer
nico-fmds
nico-hardware-health
nico-rvs
nico-test-artifact-cache
nico-dpu-agent
nico-scout
```

State-controller lines also carry a `controller=<name>` field with the same value.

### Adding it to new code

- **New binary** — set the default when building the `logfmt` layer:
  `logfmt::layer().with_event_fields([logfmt::EventField::with_default("component", "nico-my-service")])`
  — or pass the name to `carbide_host_support::init_logging("nico-my-service")` if the binary uses that
  helper. A binary that omits this sets no default `component`.
- **New in-process subsystem of `nico-api`** — add a `component` field to the subsystem's root span:
  `tracing::span!(parent: None, Level::INFO, "my_subsystem", component = "my-subsystem", /* … */)`. Nested
  instrumented functions and spawned tasks carried with `.instrument(...)` / `.in_current_span()` inherit it.

> **By convention, NICo uses the `component` key for the emitting component** — don't reuse the key for
> unrelated data; give domain values their own key.

### Coverage

Binaries that do not use the `logfmt` layer carry no `component`: `nico-dns` (emits JSON), `nico-pxe`
(hand-rolled formatter), `nico-ssh-console`, `nico-dpu-otel-agent`. CLI/dev tools and mocks are out of scope.

## Querying

Parse the logfmt line and filter on the field in whatever store the logs land in. For example, with logql
(Loki):
```logql
{namespace="nico-system"} | logfmt | component="site-explorer"
```
