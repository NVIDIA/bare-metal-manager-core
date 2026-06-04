# NICo Tracing

How NICo components tracing work, what it covers, how to turn it on and off and what it
costs.

---

## TL;DR

- **nico-api** (the `carbide-api` binary) is NICo's primary tracing source and the subject of this
  document. **nico-dns** also emits traces, but with a separate simpler always-on setup.
  No other NICo component emits traces.
- **nico-api traces are off by default**; two things must both be true before any spans are emitted:
  - OTEL endpoint configured at deploy time by setting the env var `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`
      ```yaml
      # Set OTEL endpoint in nico-api pod template
      ...
      env:
        - name: OTEL_EXPORTER_OTLP_TRACES_ENDPOINT
          value: http://<otel_endpoint_host>:4317 # gRPC (default port 4317)
      ...
      ```
  - The runtime switch turned on with `nico-admin-cli set tracing-enabled true`
- Tracing is **resource-intensive when on**, so turn it on for a debugging session and then off after.
    ```bash
    # Once the endpoint is configured:
    nico-admin-cli set tracing-enabled true     # start capturing
    # ... reproduce the issue, examine traces in your backend ...
    nico-admin-cli set tracing-enabled false    # stop capturing traces
    ```
  Leaving the OTEL endpoint configured while the runtime switch is off costs almost nothing
- Transport is **OTLP/gRPC, plaintext**; nico-api cannot do OTLP/HTTP or originate TLS

---

## 1. How tracing works

### 1.1 Which components emit traces

Two binaries build an OTLP span exporter:

- **nico-api** (`crates/api-core/src/logging/setup.rs`) - the rich, control-plane tracing this
  document is mostly about, off by default behind the two-part enablement
- **nico-dns** (`crates/dns/src/main.rs`) - a separate, much simpler **always-on** setup.

The other binaries (nico-pxe, nico-dhcp, nico-bmc-proxy, nico-hardware-health, nico-ssh-console-rs,
nico-dsx-exchange-consumer) carry the OpenTelemetry crates in the workspace but do not build a span
exporter, so they emit no traces.

Unless noted otherwise, the rest of this document describes **nico-api** tracing.
nico-dns differs as described in 1.5.

### 1.2 What operations are covered

nico-api links many library crates in-process and the `#[tracing::instrument]` spans live in
those crates. When tracing is enabled, the instrumented operations are:

| Area | Crate | Operations (span sites) |
|---|---|---|
| **Hardware component management** | `component-manager` | `power_control`, `update_firmware` / `queue_firmware_updates`, `get_firmware_status`, `list_firmware(_bundles)` across three backends - **NSM**, **PSM** (power-shelf), **RMS** (rack). Each span carries `backend="nsm\|psm\|rms"`. |
| **Reconcile controllers** | `machine-controller`, `switch-controller`, `power-shelf-controller` | `handle_object_state` (fields `object_id`, `state`). |
| **Discovery / infra** | `site-explorer`, `api-db` (migrations) | one span each. |
| **Database queries** | `sqlx-query-tracing` | wraps SQLx queries as spans. |

There is also a metric, `carbide_api_tracing_spans_open`, that reports the number of currently
open spans (exported by the `spancounter` crate) - useful for spotting span leaks or runaway
trace volume.

These cover the control-plane paths an operator most often needs to debug: machine
provisioning/reconcile loops, power control and firmware updates against the BMC/power/rack
backends, plus the database work underneath them - which maps directly to the EPIC's
"time on a given state of the machine, nodes stuck" need.

### 1.3 How spans are selected (sampler)

nico-api uses a custom `CarbideSpanSampler` wrapped as **`ParentBased`**:

- A **root span** is recorded only if both are true:
  - the runtime `tracing-enabled` flag is on
  - the span's `code.namespace` begins with `carbide::`
- **Child spans inherit the root's decision** (that's what `ParentBased` means), so once a
  trace is sampled the whole call tree beneath it is captured - **except tokio spans, which are
  always dropped** (they leak and would exhaust memory).
- The exporter resource is `service.name = carbide-api`; the tracer is named `carbide`.

### 1.4 How traces leave nico-api

nico-api pushes spans over **OTLP/gRPC** to a collector endpoint you configure. It does not
discover or get injected with anything - it simply connects out to whatever
`OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` points at. The transport details: gRPC-only, plaintext.

### 1.5 nico-dns tracing (separate and always-on)

nico-dns has its own tracing setup (`crates/dns/src/main.rs`), independent of and simpler than
nico-api's:

- **Always on.** nico-dns builds the span exporter unconditionally at startup - there is no
  endpoint env-var check and no `tracing-enabled` switch. If the process runs, it is exporting.
- **Endpoint from config, with a default.** The target is the `otlp_endpoint` config field
  (`crates/dns/src/config.rs`), which defaults to
  `http://opentelemetry-collector.otel.svc.cluster.local:4317`. Because of that default, nico-dns
  tries to export out of the box
- **Default sampler.** It uses the OpenTelemetry SDK's default sampler (no `CarbideSpanSampler`),
  so it records broadly, filtered only by the log-level directives in its `EnvFilter`. It
  instruments `retrieve_records`, among others.
- **Resource / output:** `service.name = carbide-dns`; logs are JSON on stdout (not logfmt).
- **Same transport constraints:** OTLP/gRPC, plaintext (`with_tonic`, no `tls` feature)

---

## 2. How to enable and disable tracing

Enabling tracing has **two parts**: a one-time **deploy-time configuration** and a **runtime switch**.
Both must be in place; satisfying only one produces no traces

```
 Deploy-time configuration (once)                  Runtime switch (per debugging session)
 ┌───────────────────────────────┐                  ┌─────────────────────────────────────┐
 │ a. a traces backend           │                  │ nico-admin-cli set tracing-enabled  │
 │ b. a collector to receive     │   ── then ──▶    │   true   → start emitting           │
 │    OTLP from nico-api         │                  │   false  → stop emitting            │
 │ c. OTEL_EXPORTER_OTLP_TRACES_ │                  │ (live, no restart needed)           │
 │    ENDPOINT set on nico-api   │                  └─────────────────────────────────────┘
 └───────────────────────────────┘
```

### 2.1 Deploy-time configuration

**(a) A traces backend.** Anything that accepts OTLP traces: e.g. Tempo, Jaeger, Grafana Cloud,
Datadog, Elastic APM or another OTEL collector acting as a gateway.

**(b) A collector to receive OTLP from nico-api.** nico-api should send to a collector, not
straight to the backend - the collector is where you do sampling, batching, attribute
normalization and (importantly) TLS for anything leaving the cluster. There are two common
ways to give nico-api a collector to talk to:

*Option A - a shared collector* (Deployment or DaemonSet) that many workloads send to. A minimal
**otel-collector** `traces` pipeline:

```yaml
receivers:
  otlp:
    protocols:
      grpc: { endpoint: 0.0.0.0:4317 }   # nico-api connects here

processors:
  memory_limiter:
    check_interval: 1s
    limit_percentage: 75
    spike_limit_percentage: 20
  tail_sampling:              # optional but recommended; keeps trace volume sane
    decision_wait: 10s
    policies:
      - name: errors
        type: status_code
        status_code: { status_codes: [ERROR] }
      - name: slow
        type: latency
        latency: { threshold_ms: 500 }
      - name: probabilistic-baseline
        type: probabilistic
        probabilistic: { sampling_percentage: 5 }
  batch/traces:
    send_batch_size: 1024     # keep batches small if the backend is Tempo (gRPC msg-size limits)
    send_batch_max_size: 2048

exporters:
  otlp/traces:
    endpoint: <backend-host>:4317   # Tempo / Jaeger / Grafana Cloud / Datadog / Elastic OTLP
    tls: { insecure: true }         # in-cluster plaintext; set real TLS/mTLS per backend
    retry_on_failure: { enabled: false }   # best-effort; don't queue traces if backend is down

service:
  pipelines:
    traces:
      receivers:  [otlp]
      processors: [memory_limiter, tail_sampling, batch/traces]
      exporters:  [otlp/traces]
```

With Option A, nico-api's endpoint is the collector's in-cluster Service, e.g.
`http://otel-collector.observability.svc.cluster.local:4317`.

*Option B - a per-pod sidecar collector injected by the OpenTelemetry Operator.* If your cluster
runs the [OpenTelemetry Operator](https://github.com/open-telemetry/opentelemetry-operator), you can have it inject a collector container into the nico-api
pod via a pod annotation. nico-api then talks to the collector over `localhost` (same pod, same network namespace)

The annotation value follows the form **`<namespace>/<collector-name>`**:

```yaml
# nico-api pod template
metadata:
  annotations:
    sidecar.opentelemetry.io/inject: "observability/otel-sidecar"
spec:
  template:
    spec:
      containers:
        - name: nico-api
          env:
            - name: OTEL_EXPORTER_OTLP_TRACES_ENDPOINT
              value: http://localhost:4317   # the injected sidecar shares the pod network
```

**(c) Point nico-api at the collector.** nico-api builds its OTLP span exporter **only if**
`OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` is set. If it is unset, no tracing layer is constructed at
all and nothing is ever emitted - regardless of the runtime switch.

```yaml
# nico-api container env (e.g. via the nico-api Helm values)
env:
  # Option A (shared collector): the collector's Service
  OTEL_EXPORTER_OTLP_TRACES_ENDPOINT: http://otel-collector.observability.svc.cluster.local:4317
  # Option B (injected sidecar): the in-pod collector on localhost
  # OTEL_EXPORTER_OTLP_TRACES_ENDPOINT: http://localhost:4317
```

Notes:

- This is the **only** trace-related setting nico-api reads from the environment.
  Other standard OTEL env vars are **ignored**.
- The endpoint must be a **plaintext gRPC** target (`http://…`, h2c); 4317 is the default
  OTLP/gRPC port. Do not point it at a 4318 HTTP receiver and do not use `https://`.
- This env var is intentionally not committed in NICo's manifests; adding it is the deliberate
  "deploy tracing" step. It puts the plumbing in place but does **not** start emission on its own.

### 2.2 Runtime switch (enable / disable)

With the endpoint configured, emission is still controlled by a runtime flag that defaults **off**.
Toggle it live without a restart:

```bash
# start capturing traces (e.g. while reproducing an issue)
nico-admin-cli set tracing-enabled true

# stop capturing, turn it back off when done
nico-admin-cli set tracing-enabled false
```

Under the hood this sets the dynamic config `ConfigSetting::TracingEnabled`, which flips the
in-process `tracing_enabled` flag that `CarbideSpanSampler` reads. Leaving it **off** in steady
state is the intended operating mode.

### 2.3 Do I need to restart nico-api?

It depends on which part you are changing:

| What you're doing | Restart needed? |
|---|---|
| Endpoint already set at startup, want traces now | **No** - `nico-admin-cli set tracing-enabled true` |
| Turning tracing back off | **No** - `nico-admin-cli set tracing-enabled false` |
| Adding `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` for the first time | **Yes** - roll the nico-api pod once |
| Adding the OTEL sidecar-injection annotation | **Yes** - pod-spec change; injected only at admission |

Why: `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` is read **exactly once, at process startup**
(`crates/api-core/src/logging/setup.rs`). If it was unset when nico-api started, the OTLP
exporter and tracing layer were never constructed and there is no way to add them at runtime -
so the **first** time you set the endpoint you must restart/roll the pod. The runtime switch,
by contrast, only flips an in-process flag and **never** needs a restart.

**Recommendation:** set `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` at deploy time and leave it in place
permanently - the plumbing is cheap while tracing is toggled off. Enabling/disabling then
never requires a restart, which is the whole point of separating the configuration from the switch.

### 2.4 Verifying it works

1. `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` is set on the nico-api pod and points at the collector's
   gRPC endpoint.
2. The collector has a `traces` pipeline and its logs show the OTLP receiver listening on 4317.
3. `nico-admin-cli set tracing-enabled true` has been run.
4. Exercise a traced operation (e.g. a machine power/firmware action), then look in your backend
   for spans with `service.name = carbide-api`.
5. Watch `carbide_api_tracing_spans_open` to confirm spans are being opened.

---

## 3. Downsides and overhead

Tracing has real cost, which is the reason it defaults off. The cost depends on
which of three states nico-api is in:

| State | nico-api overhead | I/O / network | Notes |
|---|---|---|---|
| Endpoint **unset** | **None** | None | No tracing layer is built at all. |
| Endpoint **set**, switch **off** | **Near-zero** (small per-span bookkeeping) | None | Layer is installed but the sampler drops everything; nothing is recorded or exported. |
| Endpoint set, switch **on** | **Significant** | Yes | Full recording + serialization + export. This is the "resource-intensive" mode. |

### 3.1 When tracing is ON

This is the expensive mode the dev team warns about:

- Because the sampler is `ParentBased`, a sampled root span pulls in its **entire child subtree**
  (the component-manager, machine-a-tron, controller and DB spans beneath it). A single traced
  operation can therefore produce many spans.
- Costs land in several places: extra **CPU and memory** on nico-api, added **latency** on
  instrumented hot paths, **network egress** to the collector and **storage** in the backend.
- Mitigate with `tail_sampling` at the collector (keep errors/slow traces, sample the rest) and -
  most importantly - **only enable it during an active investigation**, then turn it back off.

### 3.2 When the endpoint is set but tracing is OFF

This is the common steady state if you follow the recommendation to leave the endpoint configured. The
overhead here is **near-zero but not exactly zero**:

- At startup, because the endpoint is set, nico-api builds the OTLP exporter, a tracer provider
  with a batch span processor and installs the OpenTelemetry tracing layer into its subscriber
  stack. That layer stays present.
- Per span, the layer is invoked on each (non-tokio) instrumented span and does a little
  bookkeeping/allocation before the sampler returns "drop". A background batch task exists but
  idles.
- What does **not** happen: no span recording, no attribute serialization, no batches to flush,
  **no network or gRPC export**. There is no I/O.
- Net: a small, roughly constant per-span CPU cost - negligible next to the "on" mode, but not
  the literal zero you get with the endpoint unset.

### 3.3 Practical guidance

- Leave `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` configured and keep the runtime switch **off** in steady
  state - cheap and avoids a pod roll when you need traces.
- Treat "on" as a temporary debugging state. Turn it off when done; watch
  `carbide_api_tracing_spans_open` and nico-api CPU/latency while it is on.

---

## 4. How traces are sent (transport & security)

- nico-api speaks **OTLP/gRPC only** (no OTLP/HTTP).
- nico-api **cannot originate TLS or mTLS** for traces. The endpoint must be plaintext
- Therefore keep the **nico-api → collector hop local** (in-cluster Service, or the in-pod
  sidecar) and make the **collector the TLS boundary** for anything leaving the cluster.
- Traces are **push-based**: nico-api connects out to the collector. There is no scrape/discovery
annotation involved for traces

---

## 5. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| No traces at all, env var **is** set | Runtime switch is off | `nico-admin-cli set tracing-enabled true` |
| No traces at all, switch **is** on | Endpoint not configured - `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` unset, so no exporter was built | Set the env var on nico-api and roll the pod |
| nico-api can't connect / TLS errors | Endpoint uses `https://` or points at the 4318 HTTP port | Use plaintext `http://…:4317` (gRPC); nico-api has no TLS and no HTTP |
| Sidecar injected but still no traces | Endpoint env var not set, or points somewhere other than `localhost:4317` | Set `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT: http://localhost:4317` on nico-api |
| Traces reach the collector but not the backend | Collector exporter endpoint/TLS wrong | Check the exporter config; for remote backends configure TLS/mTLS on the collector |
| Sudden resource/latency spike on nico-api | Tracing left on | `nico-admin-cli set tracing-enabled false` |
| Spans arrive but request trees look sparse | The `carbide::` root-span nuance | Verify where the root span originates on a live environment |

---

## 6. References

- [NICo core metrics catalogue](https://docs.nvidia.com/infra-controller/documentation/operations/observability/core-metrics) - includes `carbide_api_tracing_spans_open`.
