# NICo Instrumentation

How to instrument significant events with `carbide-instrument`: this framework provides a single declaration that
produces a structured log line, a Prometheus metric, or both -- correlated, consistently
named, and with metric cardinality bounded by the type system.

---

## TL;DR

- **Just logging words? Keep using `tracing::`.** `info!`/`warn!`/`error!` with structured
  fields stays the right tool for plain logs; nothing migrates for its own sake.
- **Need a count, rate, or duration? Declare an `Event` and `emit()` it.** The event's two
  options -- `log = error|warn|info|debug|trace|off` and `metric = counter|histogram|none` --
  cover metric-only, log-only, or both from the same call.
- **Every Event has a stable identity.** `event_name` is a unique, flat `lower_snake_case`
  category for searches and schemas. Metric-backed Events separately declare the exact
  Prometheus `metric_name`; Event-generated logs carry both names when both sides emit.
- **Cardinality is enforced by the types.** `#[label]` fields must be bounded via
  `LabelValue` -- usually a fieldless enum, with a manual impl on a bounded newtype as the
  reviewed escape hatch; high-cardinality detail (`machine_id`, IPs, error text) goes in
  `#[context]` fields, which appear only when the Event emits a log line and *cannot* become
  metric labels.
- **The `metric_name` in the attribute is the exposed name, verbatim** -- what you grep on a
  dashboard is the string in the source. The derive validates it at compile time
  (`carbide_` prefix, `_total` for counters, a unit suffix for histograms).
- **Point-in-time state (gauges) is unchanged.** The framework models *occurrences*; observable
  gauges and `SharedMetricsHolder` snapshots stay exactly as they are.

Part of the instrumentation-coherency initiative
([#3169](https://github.com/NVIDIA/infra-controller/issues/3169)).

---

## When to use carbide-instrument

| You want | Use | Why |
|---|---|---|
| A plain log line | `tracing::info!(%machine_id, "...")` | No metric required. Most log sites stay exactly like this. |
| A failure you'd alert on | `emit(...)` with `log = warn, metric = counter` | The counter is the alert; the log line (same labels + context) provides the details. |
| A hot-path rate (per packet / per request) | `emit(...)` with `log = off, metric = counter` | The rate is the signal; no log line is built at all -- zero logging cost, and the noise is gone. |
| A duration or size distribution | `emit(...)` with `metric = histogram` | `#[observation]` supplies the value; the unit comes from the metric name. |
| "How many are in state X right now" | An observable gauge (existing pattern) | State is not an occurrence. Keep `SharedMetricsHolder` + `u64_observable_gauge`. |

**Adoption is opt-in** and call-site-by-call-site. Existing `tracing::` sites and existing
metric emitter structs keep working unchanged; when a site *does* migrate, its log line
keeps the same level, message, and domain fields (labels and context render as ordinary
logfmt fields), so existing greps keep working. Event-generated logs also gain the stable
identity fields, and a metric-backed migration gains the declared metric.

## Quick start

Declare the event next to the code that emits it:

```rust
use carbide_instrument::{emit, Event, LabelValue, Outcome};

#[derive(Debug, Clone, Copy, PartialEq, Eq, LabelValue)]
enum Backend {
    Nsm,
    Psm,
    Rms,
}

#[derive(Event)]
#[event(
    event_name  = "power_control_failed",       // stable event category
    metric_name = "carbide_power_control_total", // exposed metric, verbatim
    component   = "component_manager",
    log         = warn,                          // error|warn|info|debug|trace|off
    metric      = counter,                       // counter | histogram | none
    message     = "power control failed",
    describe    = "Power control has failed.",
)]
struct PowerControlFailed {
    #[label]
    backend: Backend, // enum -> label backend="rms" (metric AND log)
    #[label]
    outcome: Outcome, // the framework's shared ok|error vocabulary
    #[context]
    bmc_ip_address: std::net::IpAddr, // log-only, never a metric label
    #[context]
    error: String, // log-only
}

if let Err(e) = backend.power_control(&target, action).await {
    emit(PowerControlFailed {
        backend: Backend::Rms,
        outcome: Outcome::Error,
        bmc_ip_address,
        error: e.to_string(),
    });
}
```

One `emit()` writes both the log line and the metric. The log line carries the surrounding
span's `span_id`; the metric is an aggregate with no per-request identity, so correlation
runs the other way: pivot from the moving metric to the matching log lines by metric name
and label values, and `span_id` then ties each line to its request:

```logfmt
level=WARN component=nico-api span_id=0x4f... event_name=power_control_failed metric_name=carbide_power_control_total msg="power control failed" backend=rms outcome=error bmc_ip_address=10.0.0.5 error="deadline exceeded" location="..."
```

```text
carbide_power_control_total{backend="rms",outcome="error"} 1
```

Install the meter provider at startup **before the first emit** (every NICo binary
already does, for its existing metrics); instruments resolve from the global meter once
per event type.

## Log and metric options

Every event declares its log side and its metric side independently:

| `#[event(...)]` | Log line? | Metric? | Use for |
|---|---|---|---|
| `log = warn, metric = none` | Yes | No | A typed structured log (rare; plain `tracing::` is usually fine) |
| `log = warn, metric = counter` | Yes | Yes | A failure you alert on *and* read |
| `log = off, metric = counter` | No | Yes | Hot paths where the rate is the signal |
| `log = off, metric = histogram` | No | Yes | High-frequency latency as a distribution only |

`log = off` constructs no `tracing` event at all -- it is not "logged then filtered".
It still has a declared `event_name` for source-level identity and future cataloguing, but
there is no log record on which to render that field.

For per-instance control (count everything, log only failures), declare `log = dynamic`
and implement `DynamicLog` -- the derive routes `Event::log_at()` through it:

```rust
impl DynamicLog for CallFinished {
    fn log_at(&self) -> LogAt {
        match self.outcome {
            Outcome::Error => LogAt::Level(tracing::Level::WARN),
            Outcome::Ok => LogAt::Off, // counted, never logged
        }
    }
}
```

## Outbound calls

Every generated gRPC client method is already wrapped: it records
`carbide_external_call_duration_milliseconds{backend, operation, outcome}` on every
completion (the histogram's `_count` is the request and error rate) and writes one WARN --
with the error as log-only context -- on failure. For other outbound boundaries
(Redfish, HTTP, IPMI), wrap the call directly:

```rust
let response = carbide_instrument::red::instrumented("redfish", "power_control",
    client.power_control(&target, action)).await?;
```

The `backend`/`operation` labels are `&'static str` on purpose: compile-time literals
only, never values from the wire -- the type is the cardinality guard. Streaming calls
record time to the stream handle, not the stream's lifetime.

## Rules for labels and context

A metric's time-series count is the product of its label domains, so every label domain
must be small and closed. The framework makes that structural instead of a review checklist:

- **`#[label]` fields must implement `LabelValue`**, which is derivable **only for
  fieldless enums**. A derived label value is the variant's snake_case name.
  `String` never implements it.
- **`#[context]` fields take anything `Display`** and appear only when the Event emits a log
  line. This is where `machine_id`, addresses, and error text belong. A context field cannot
  become a metric label.
- **Bounded-but-not-enumerated values** such as vendor strings or SKUs can go through a
  **manual `impl LabelValue` on a newtype** -- the deliberate, greppable escape hatch, and
  the place to justify boundedness at review. The deciding factor should be real boundedness *at the call
  site*: a raw request-path segment is not bounded even when a proto surface suggests it
  should be -- caller-supplied values mint unbounded series. When in doubt, keep the value
  in `#[context]` and count without it.
- Per-object metric series remain the exception, and they stay on the opt-in,
  hold-time-bounded `PerObjectMetricsRegistry` -- not on event labels.

## Histograms and observations

A histogram event carries exactly one `#[observation]` field: a `Duration` (converted to
the unit the metric name declares) or a plain number (recorded as-is).

```rust
#[derive(Event)]
#[event(
    event_name = "bfb_copy_finished",
    metric_name = "carbide_preingestion_bfb_copy_duration_seconds",
    component = "preingestion-manager",
    log = info,
    metric = histogram,
    message = "BFB copy finished",
)]
struct BfbCopyFinished {
    #[label]
    outcome: Outcome,
    #[observation]
    took: std::time::Duration, // recorded in seconds -- checked against metric_name
    #[context]
    host_ip_address: std::net::IpAddr,
}
```

A histogram already exports a `_count` series, so it never needs a twin counter.

## Naming conventions

`event_name` and `metric_name` serve different contracts:

- `event_name` identifies a reusable semantic event category. It is a unique ASCII
  `lower_snake_case` literal, starts with a letter, and has no dot namespace, component
  prefix, severity, or unit. Add a semantic qualifier only when distinct Events would
  otherwise collide. Changing it breaks saved log searches and future schemas.
- `metric_name` is required exactly when `metric != none`. It is the exposed Prometheus
  name, verbatim, and keeps the existing metric compatibility contract.

`cargo xtask check-event-names` verifies that production Event declarations have unique
static event names. One Event declaration may still be emitted from any number of call
sites; uniqueness is about declarations, not occurrences.

For `metric_name`, the derive enforces these conventions at compile time:

- All new metrics use the `carbide_` prefix.
- Counter names have a `_total` suffix -- and only one: the Prometheus exporter appends `_total`,
  so an instrument name that already ends in `_total` (a doubled `_total_total`) is rejected.
- Histograms end in their unit: `_seconds`, `_milliseconds`, `_microseconds`, `_bytes`.
- Gauge names (existing pattern, not the framework) are mixed legacy forms; follow established
  neighboring names rather than a single suffix rule.

The `metric_name` in the attribute is the Prometheus metric-family name operators use -- a
dashboard name greps straight back to the declaring line. The framework accounts for the
exporter's suffix handling when it registers the instrument: a counter's declared `_total` remains
the exposed family name, while a histogram additionally exposes the normal `_bucket`, `_sum`, and
`_count` series derived from its family name.

**Existing metric names never change.** Migrating a pre-standard site onto the framework keeps
its frozen name via `metric_name_unchecked` (plus an explicit `unit = "..."` for histograms);
there are no such sites today, and a future use stays easy to audit because new metrics cannot use
the opt-out silently.

An Event that can log keeps a required, stable, human-readable `message`. `event_name` is
the machine contract while `message` is presentation for people and UIs; occasional wording
overlap is fine. Metric-only Events require no message because they construct no log line.

A counter documents itself: its `describe = "..."` is required and opens with "Number of ..." (the
tech-writer house rule, enforced by the derive). The text becomes the Prometheus HELP and the
Description column of the [core_metrics.md](core_metrics.md) catalogue. A grandfathered describe
keeps its wording with `describe_unchecked` -- the counterpart to `name_unchecked` -- and a search
for either finds every opt-out. A histogram takes any `describe` (or none); a log-only event
(`metric = none`) has no metric to document, so it must omit `describe`.

The catalogue is regenerated by `test_integration`, which scrapes `/metrics`, and checked in CI.
Because a metric no test exercises is never scraped, `cargo xtask check-metric-docs` also reads the
`#[event(...)]` declarations directly and fails if any framework counter or histogram -- other than a
`name_unchecked` one, whose exposed name is an OTel-sanitized transform (see #3221) -- is missing a
catalogue row, so a new metric cannot land undocumented.

## Derivation outputs and costs

`#[derive(Event)]` is [thiserror](https://docs.rs/thiserror/latest/thiserror/)-style: a plain struct you can construct, test, and match,
with the semantics in attributes. The generated code:

- Builds labels as a fixed-size array (no heap allocation on emit) with enum values
  rendering as `&'static str`
- Caches the OTel instrument in a per-event-type `OnceLock` -- a metric-only emit is an
  atomic load plus an `add()`
- Emits the log via `tracing::event!` with real static field names, so `logfmt`, the
  admin-UI log stream, and every other subscriber layer see an ordinary tracing event in
  the surrounding span. Its tracing metadata name and structured `event_name` field are the
  declared event identity; a metric-backed Event also emits `metric_name` on that log line.
- Never panics

## Testing the coherency

The `test-support` feature provides capture helpers, so "this event logged at WARN *and*
ticked the counter" is a plain unit test:

```rust
use carbide_instrument::testing::{capture_logs, MetricsCapture};

let metrics = MetricsCapture::start();
let logs = capture_logs(|| emit(PowerControlFailed { ... }));

assert_eq!(logs[0].level, tracing::Level::WARN);
assert_eq!(logs[0].metadata_name, "power_control_failed");
assert_eq!(logs[0].field("event_name"), Some("power_control_failed"));
assert_eq!(logs[0].field("metric_name"), Some("carbide_power_control_total"));
assert_eq!(
    metrics.counter_delta("carbide_power_control_total", &[("backend", "rms"), ("outcome", "error")]),
    1.0,
);
```

`MetricsCapture` serializes metric-asserting tests behind a process-global registry;
`capture_logs` is per-thread. `render()` prints the raw exposition text when a test needs
inspection.

## Potential hazards

- **`LogLimiter`-gated sites**: before migration, the limiter suppresses the log call
  before any event fires, so the true rate is invisible to everything -- including the
  framework. After migration onto an `Event`, the metric ticks on every occurrence and the
  limiter gates only the log line.
- **The logfmt `component` key** continues to come from the subscriber configuration and
  span attributes (as everywhere else); the event's `component` names the subsystem for
  tooling and tests and is not written as a log field.
- **Events are occurrences.** Do not model state with counters; keep gauges on the
  existing observable-gauge pattern.
- **Reserved Event-log fields**: `message` is always reserved. Events that can log must
  also not declare payload fields named `msg`, `level`, `location`, `component`, `span_id`,
  `event_name`, or `metric_name`. Metric-only legacy labels remain allowed because renaming
  a Prometheus label would break its metric contract.

## References

- The initiative: [#3169](https://github.com/NVIDIA/infra-controller/issues/3169)
  (unify logging and metrics behind a single instrumentation standard).
- The crate: `crates/instrument` (rustdoc on `Event`, `emit`, `LabelValue`, `testing`).
- The catalogue: [core_metrics.md](core_metrics.md) -- every new metric lands there.
- Conventions: [Prometheus metric and label naming](https://prometheus.io/docs/practices/naming/).
- Neighbors: [logging.md](logging.md), [tracing.md](tracing.md).
