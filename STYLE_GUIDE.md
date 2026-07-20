# How to write Rust in infra-controller

The goal of this document is to help keep our codebase consistent and maintainable by outlining best-practices we've
learned through experience. It is currently a mix of best practices for _this codebase_ (ie. how we expect code to
be organized), and best practices for *Rust in general*. The latter is mostly motivated by issues we seen enough to
warrant writing them down, but otherwise this document not aim to be a "how to write Rust" guide.

## Core Principles

- Prefer simple, explicit code over clever or heavily abstracted code. Optimize for readability and maintainability
  first.
- Prefer designs that are hard to misuse. The more the compiler can catch bugs, the better.
- Abstractions should justify their existence: Do not add abstractions "just in case". Wait until there is a real
  requirement for them.

## Reviewability

PR descriptions should be written as if the audience has no context for the change: Explain why it's happening.
Don't assume people are already aware of your feature roadmap.

Prefer to not land unused code if nobody's using it yet, unless not doing so would make for too large of a change to
review. For example, a PR that lands protobuf changes but without any code using it yet, makes for a lot of
guesswork during review: If we can't see how the code will be used, we are just guessing at what the best API
contract will be. Landing both changes together means we can look at it all holistically.

## Lints and Warnings

We enable all clippy lints by default, and treat all warnings as errors. If a warning or clippy lint is firing for
your code, strongly consider fixing it. Avoid using `#[allow(...)]` unless you have a strong reason to do so. New
code should generally not have to `#[allow]` any lints or warnings.

### A note on dead code

Dead code detection is important to catch mistakes and to avoid unused code building up and hurting
maintainability. Strongly avoid using `#[allow(dead_code)]`.

An exception is when a part of the codebase is not finished: If a new feature is too large to land all in one PR,
and is being written in phases, code may be merged with nothing calling it yet, and `#[allow(dead_code)]` is
necessary for it to be merged early.

Other common places where we've seen `#[allow(dead_code)]` that are not necessary:

- If a field or function is only used in tests: Use `#[cfg(test)]` to include it only in test builds.
- If a field is written to but never read, but needs to be held so its `Drop` impl does not run: Name it with an
  underscore to hint that it's not supposed to be read
- If a field is only used if certain crate features are enabled, prefer `#[cfg(feature = "feature")]` to only
  include it when that feature is being used.
- If a field isn't currently yet, but you want to leave it around as documentation on what fields could exist (like an
  unused database column, or unused JSON field), comment it out.
- Otherwise, strongly consider deleting the code.

## Testing

Prefer **table-driven tests** for any function that maps inputs to outputs, errors, or other observable results —
parsers, validators, conversions, serde round-trips, formatters, and the like. The `carbide-test-support` crate
provides tiny helpers for exactly this. Add it as a dev-dependency:

```toml
[dev-dependencies]
carbide-test-support = { path = "../test-support" }
```

Write the test as a list of labeled cases — each a `scenario`, an `input`, and an `expect`ed result — and run them all
through one operation, written once:

```rust
use carbide_test_support::Outcome::*;
use carbide_test_support::scenarios;

#[test]
fn parse_port() {
    scenarios!(parse_port:
        "valid ports" {
            "0" => Yields(0),
            "443" => Yields(443),
        }

        "invalid ports" {
            "https" => Fails,
            "99999" => FailsWith(PortError::TooLarge),
        }
    );
}
```

- Use **`scenarios!`** with `Outcome` (`Yields` / `Fails` / `FailsWith`) for **fallible** operations (those returning
  `Result`). It expands to `check_cases` and keeps failures labeled by both scenario and input.
- Use **`value_scenarios!`** for **total** operations (those returning a plain value, `Option`, or `bool`). It expands to
  `check_values`.
- Use **`check_cases`** / **`check_values`** directly when a macro would obscure a table with several inputs or several
  expected fields per row.
- Reach for `FailsWith(err)` only when the error type is `PartialEq` and its exact value is the contract. Otherwise use
  `Fails` (with `.map_err(drop)` in the operation) when only "it failed" matters.

Why we prefer this:

- **It is the cheapest path to thorough coverage.** Each branch of the function under test — every `match` arm, each
  `Option`/`Result` path, every boundary and error case — becomes one more row. To comprehensively test (and cover) a
  function, simply *enumerate its input variants as cases*: the operation is written once, and every row exercises it.
  This is by far the easiest way to take a function from partially-tested to nearly fully-covered, and it applies equally
  whether a human or an agent is writing the tests.
- **Failures are precise.** Each row carries its `scenario` label, so a failure names the exact case instead of leaving
  you to bisect a wall of `assert!`s.
- **Adding a case is one line**, so there is no friction to covering the edge case you would otherwise skip.

Reach for a table whenever two or more tests call the same operation with different inputs. Do **not** force
genuinely-distinct tests (different setup, a different operation, or several unrelated assertions) into a table — a table
that obscures intent is worse than a few honest standalone `#[test]`s.

When an exact expected value is awkward to write by hand, assert a robust property instead of guessing: a round-trip
(`Yields(input)` after serialize-then-deserialize), `Fails` vs `Yields(())` for plain success/failure, or a
substring/`contains` check. The case still exercises — and covers — the path.

See [`crates/test-support/src/lib.rs`](crates/test-support/src/lib.rs) for the full API and more examples.

## gRPC API definitions

- APIs to list resources and retrieve resource state should be paginated in order to scale to a high amount of managed
  resources. Pagination should be achieved in the following fashion:
    - An API call with the format `FindResourceNameIds` (e.g. `FindMachineIds`) should be used to list the IDs of all
      resources. It should take a `ResourceNameSearchFilter` message as argument, that allows to narrow down the amount
      of returned IDs according to certain criteria. If multiple criteria are provided, the API should search for
      resources where all criteria apply.
    - An API call with the format `FindResourceNamesByIds` (e.g. `FindMachinesByIds`) should be used to retrieve the
      state of the resources.
- Each resource object that is configurable by API users should contain the following set of fields:
    - An `id` field that identifies the resource.
    - A `config` field that holds every value that is set by API callers (site admins or tenants).
    - A `status` field which holds every value that is generated by the system (not user-provided)
    - A `metadata` field if the resource has user-changeable metadata (name, description or labels)
    - A `version` field which describes how often the `config` of the resource was updated and when the last change
      occured. The version field needs to get incremented every time a tenant or site admin changes the `config` of a
      certain resource. This allows the system to identify whether anything changed purely by comparing version numbers.

  Example of a complete resource:
  ```
  message AmazingResource {
    common.AmazingResourceId id = 1;
    Metadata metadata = 2;
    AmazingResourceConfig config = 3;
    AmazingResourceStatus status = 4;
    string version = 5;
  }
  ```
- If the lifecycle of a resource is managed by a state handler, the resource should contain the following extra fields:
    - A `state` field which shows the lifecycle state of the resource
    - A `state_version` field which gets incremented every time the resource switches between states
    - A `state_reason` field which shows the outcome of the last state handler run
    - A `state_sla` field which shows the SLA for the state, and whether it had been breached.

## Networking integrations

Networking technologies should be integrated using the workflows described in [Networking Integrations](book/src/architecture/networking_integrations.md).

## Metrics

When designing metrics, be careful with cardinality. Do not attach highly unique labels that explode time-series
count, like per-machine or per-instance attributes.

## Instrumentation

A significant event -- a count, a rate, or a duration -- is declared with the instrumentation framework
(`carbide-instrument`) rather than by hand-rolling an OpenTelemetry instrument. One `#[derive(Event)]` declaration
produces a structured log line, a Prometheus metric, or both from a single `emit()`, with metric cardinality bounded by
the type system. See [Instrumentation](docs/observability/instrumentation.md) for the full model and when to use it.

The canonical pattern, checked at compile time by the derive:

- **`carbide_` prefix** on every metric name. The name in the attribute is the exposed name, verbatim, so a dashboard
  greps straight back to the source line.
- **`_total` suffix for counters** (never a doubled `_total_total` -- the Prometheus exporter appends the suffix), and a
  **unit suffix for histograms** (`_seconds`, `_milliseconds`, `_microseconds`, `_bytes`).
- **A counter's `describe` opens with "Number of ..."**. That HELP text is the row the
  [core metrics catalogue](docs/observability/core_metrics.md) records, and every framework counter and histogram --
  apart from a `name_unchecked` one, whose exposed name is an OTel-sanitized transform -- must appear there, enforced by
  `cargo xtask check-metric-docs`. When it flags a missing row, run `cargo xtask check-metric-docs --fix` to add it
  automatically, in sorted position -- no hand-editing the catalogue.
- **Bounded `#[label]` fields; high-cardinality detail in `#[context]`**. Labels come from `LabelValue` enums; machine
  IDs, IPs, and error text stay on the log line only.

`name_unchecked` and `describe_unchecked` are the greppable escape hatches for grandfathered metrics; new metrics use
the standard form.

## Logging

All services should emit logs in "logfmt" syntax. This structured logging format allows administrators to efficiently
search logs by certain attributes (key/value pairs).

Tracing events must use a stable, human-readable string literal for the message and record dynamic operational values
as structured fields whenever a meaningful field name can be derived. Do not interpolate such values into the message,
including when the event already contains other structured fields.

Describe the event in the message; do not narrate fields that already describe themselves. For example, prefer
`info!(%domain_id, "Domain created")` over `info!(%domain_id, "Domain created with ID")`, and prefer
`info!(%instance_id, %ip_address, "Instance is terminating")` over a message ending in `"at address"`. Keep wording
that conveys a relationship, source, destination, or behavior that the field names alone do not express.

Use native field shorthand for types that implement `tracing::Value`, `%field` for `Display`, and `?field` for `Debug`.
Use consistent semantic field names rather than incidental local variable names; for example, record an error held in
`e` as `error = %e`. Do not reuse formatter metadata keys such as `level`, `msg`, `location`, or `span_id`; choose a
domain-specific key such as `configured_log_level` or `error_location` instead. On the Event log surface,
`event_name` and `metric_name` are also reserved for fields generated by `carbide_instrument::Event`. Existing
metric-only labels with these names remain allowed because renaming them would change the metric contract.

Typed Events declare a globally unique, flat `lower_snake_case` `event_name` that identifies the reusable event
category, not an individual occurrence. A metric-backed Event separately declares the exact Prometheus
`metric_name`. Event-generated log lines include `event_name` and, when applicable, `metric_name`; ordinary
`tracing::` calls do not add either field. Keep `message` as a stable human-readable description on Events that log,
even when it resembles the machine-facing `event_name`. See
[`docs/observability/instrumentation.md`](docs/observability/instrumentation.md) for the declaration and naming rules.

Field names are part of the operational interface: dashboards, alerts, and ad hoc searches depend on them. The table
below defines the common vocabulary. It is not an exhaustive schema -- event-specific fields should still describe
their values precisely -- but do not introduce an alias for one of these concepts.

| Concept | Field name | Notes |
|---|---|---|
| Rust error | `error` | Normalize incidental bindings such as `e` and `err` with `error = %e`. Supplemental forms such as `error_chain` may accompany, but not replace, `error`. |
| gRPC status code | `grpc_status_code` | Keep the transport namespace explicit; do not shorten it to `code`. |
| HTTP status | `http_status` | Use for the complete HTTP status or its numeric code; do not introduce `status_code` aliases. |
| Domain explanation | `reason` | Use for an outcome or persisted explanation that is not a Rust error. Keep typed domain fields such as `failure_cause` when that is the model's actual name. |
| IP address | `ip_address` | Add a semantic role when known, such as `bmc_ip_address`, `source_ip_address`, or `host_bmc_ip_address`; do not shorten it to `ip` or `addr`. |
| MAC address | `mac_address` | Add a semantic role when known, such as `bmc_mac_address` or `interface_mac_address`; do not shorten it to `mac`. |
| Socket or service address | role-specific `*_address` | Prefer names such as `listen_address`, `peer_address`, `metrics_address`, or `endpoint_address`; reserve `*_ip_address` for an IP without a port. |
| Entity state | role-specific `*_state` | Prefer `machine_state` or `instance_state` over bare `state`. Use `previous_state`, `next_state`, and `target_state` for transitions. |
| Cardinality | `<thing>_count` | Name what is counted; avoid bare `count`, `total`, or `num_*`. Put qualifiers before the noun, as in `pending_partition_count`. |
| Quantity | `<thing>_<unit>` | Include the unit when it is not encoded by the type, such as `file_size_bytes`, `retry_delay_seconds`, or `elapsed_milliseconds`. |
| Command | `command` | Do not introduce local abbreviations such as `cmd`. Use the same full-word rule for keys such as `interface_name` and `firmware_type`. |

For a typed identifier, derive the default field name from the Rust type name in snake case. Common examples include
`MachineId` -> `machine_id`, `MachineInterfaceId` -> `machine_interface_id`, `InstanceId` -> `instance_id`, `VpcId` ->
`vpc_id`, `VpcPrefixId` -> `vpc_prefix_id`, `NetworkSegmentId` -> `network_segment_id`, `NetworkPrefixId` ->
`network_prefix_id`, `DpaInterfaceId` -> `dpa_interface_id`, `ExtensionServiceId` -> `extension_service_id`,
`SpxPartitionId` -> `spx_partition_id`, `IBPartitionId` -> `ib_partition_id`, and `NvLinkLogicalPartitionId` ->
`nvlink_logical_partition_id`. Preserve established product tokenization in field names; for example, the `NvLink`
product name remains the single token `nvlink` rather than `nv_link`.

Use a role qualifier when it distinguishes multiple values of the same type or preserves important lifecycle context,
as in `host_machine_id`, `dpu_machine_id`, `source_machine_id`, or `failed_machine_id`. Otherwise prefer the type-derived
name. Avoid bare or abbreviated identifiers such as `id`, `segment_id`, `dpa_id`, and `service_id` when the concrete
identifier type is known. For network segments specifically, use `network_segment`, `network_segment_id`, and
`network_segment_name` for the value, identifier, and name respectively.

For example:

```rust
fn avoid(machine_id: MachineId, attempt_number: u32) {
    if let Err(e) = process_machine(machine_id) {
        tracing::error!(
            "failed to process machine {machine_id} on attempt {attempt_number}: {e}"
        );
    }
}
fn prefer(machine_id: MachineId, attempt_number: u32) {
    if let Err(e) = process_machine(machine_id) {
        tracing::error!(
            %machine_id,
            attempt_number,
            error = %e,
            "failed to process machine",
        );
    }
}
```

Keep intentional presentation formatting intact when the rendered text is itself the payload, such as CLI output,
aligned tables, or multi-line displays. Passthrough helpers and macros whose purpose is to forward caller-supplied text
unchanged are also exempt from the literal-message requirement. Preserve special or custom formatting when converting
it would change behavior; add structured fields alongside it when that can be done without changing the rendered
output.

## Core API handlers

- Implementations of all gRPC functions exposed by the core service should reside in subdirectories of
  `api/src/handlers`.
- API handlers should inject the deserialized request arguments into the API logs by calling `log_request_data` to
  assist debugging. If the request contains sensitive data (e.g. credentials), the data however needs to be filtered
  before logging.

### Core API handler Errors

Inside API handlers, the `NicoError` data type should be used to construct errors. It should then be converted into
`tonic::Status` using `.into()`. All errors being derived from `NicoError` assures that the errors will look uniform
to tenants.

The `NicoError` variant that is used should be selected based on whether the error gets returned due to the user
passing invalid arguments or due to the system not being able to handle the request correctly. Error variants that
should be used if the user passing invalid arguments can be `InvalidArgument`, `InvalidConfiguration`, `NotFoundError`
or `ConcurrentModificationError` - these will map to "4xx-like" gRPC error codes. An example of a system-side error
would be `NicoError::Internal`.

```rust
// Avoid — constructing Status directly, bypassing `NicoError` error mapping
pub async fn create_resource(
    api: &Api,
    request: Request<rpc::Resource>,
) -> Result<Response<()>, Status> {
    let resource = request.into_inner();
    let id = resource
        .id
        .ok_or_else(|| Status::invalid_argument("id is required"))?;
}

// Prefer — uses `NicoError::InvalidArgument`
pub async fn create_resource(
    api: &Api,
    request: Request<rpc::Resource>,
) -> Result<Response<()>, Status> {
    let resource = request.into_inner();
    let id = resource
        .id
        .ok_or(NicoError::InvalidArgument("id is required".into()))?;
}
```

## Crate Features

Avoid using crate features unless there is a good reason. Our CI runners only build with the default features you get
from `cargo build --release`, meaning that if certain code breaks under certain combinations of crate features, it
might not get caught by CI. If we wanted to support numerous crate features, we would need CI runners to produce
checks for each meaningful combination of feature flags we support, which scales exponentially to the feature count.

Cases where features *are* warranted:

- For shared crates when only a subset of dependents need certain code: For example, the `nico_uuid` is used by
  several dependents, but only the `nico_api` crate needs the sqlx conversions. We don't want e.g.
  `nico_admin_cli` to take a dependency on `sqlx`, so the sqlx conversions are behind a `sqlx` crate feature. But
  this is covered by CI tests, since CI builds both the admin-cli and the api crate, both sets of features are
  exercised.

- For supporting non-linux builds: The `nico_api` crate needs to use types from the `tss-esapi` crate to support
  validating secure-boot keys, but `tss-esapi` only builds on Linux. To support developers running `nico_api` on
  their Mac for testing, the parts which require `tss-esapi` are carefully carved out into a `linux-build` feature
  (which is enabled by default). We do not run CI tests with this feature disabled, so supporting a build without
  `linux-build` enabled is best-effort.

## Async code

Due to the "virality" of async code, prefer synchronous versions of abstractions if both are available. For instance,
prefer a `std::sync::Mutex` to a `tokio::sync::Mutex` if either will work for you, so that you don't need to make
your interface `async` just so you can use the tokio Mutex. That way callers can call you without needing to be
async themselves. Async work should generally be traceable to some I/O or timer that needs to be used, otherwise
code should typically be synchronous.

## Database transactions

Transactions should be used to group write operations together such that they can be rolled back on failure. But do
not hold a transaction open while doing long-running work. Doing so can exhaust the connection pool if the thing
you're awaiting is blocked or slow. We have a custom lint, `txn_held_across_await` which will catch cases where you're
`await`ing a future while holding a transaction, which mitigates this. If it happens, your
code needs to be fixed, do not `#[allow(txn_held_across_await)]`.

## Database wrappers

- Type definitions: The code in `crates/api-db` is intended to wrap database calls, whereas `crates/api-model` should
  contain the actual model definitions. In the api-db crate, prefer bare functions that take a model as an argument, to
  OO-style methods on db-specific types. This allows the model types to live in a separate model crate, without the
  temptation for an OO-style database type to become a quasi-model unto itself.

- Read vs Write: Prefer accepting a `impl DbReader` as a connection if your database function is read-only. This allows
  callers to pass a `PgPool` and avoid needing boilerplate to begin a transaction and commit it just to call a
  read-only function.

## Background tasks

Avoid spawning background tasks without joining them. Any panics that happen in background tasks will not propagate to
the rest of the process unless you join them via `JoinHandle::join()` or add them to a `JoinSet` which is later awaited
with `JoinSet::join_all()`.

For nico-api, we use a single `JoinSet` to spawn all background tasks, and call `join_all()` to block "forever" until
the process is shut down. This makes it so any panics in the JoinSet will propagate to the main task, and crash the
process (which is what we want.) If you want to spawn background work, prefer accepting a `&mut JoinSet` and spawn your
background task into it. Your task can be constructed it inside `nico::setup::initialize_and_spawn_controllers`,
which has a JoinSet it can pass to your `start()` function.

Avoid using `oneshot::Sender<()>` as a cancellation signal, and prefer tokio_util's `CancellationToken`, which can
be cloned and re-used to cancel sub-tasks.

A note on function naming: `start` or `spawn` should mean "spawns work in the background". `run` should mean "run
forever".

### Cancelling background tasks

If your background task is a "service" with a handle that clients can use to talk to it (like sending it commands over a
tokio channel), prefer using RAII-style primitives to automatically cancel your task when the last handle is dropped.
Avoid explicit cancellation, which could cause your task to cancel even while there are still consumers.

Example:

```rust
impl MyService {
    // Returns a Handle that callers can use to interact with the background
    // task. We don't need a cancel token passed to us, instead just stop once
    // all handles have dropped.
    pub fn start(self, join_set: &mut JoinSet<()>) -> Handle {
        let (cmd_tx, cmd_rx) = mpsc::channel(BUF_SIZE);
        join_set.spawn(self.run(cmd_rx));
        // When the cmd_tx refcount drops to zero, work will stop
        Handle { cmd_tx }
    }

    async fn run(self, cmd_rx: mpsc::Receiver<Command>) {
        while let Some(cmd) = cmd_rx.recv().await {
            // handle command...
        }
        tracing::info!("All handles dropped, MyService shutting down");
    }
}

pub struct Handle {
    cmd_tx: mpsc::Sender<Command>,
}
```

For background tasks that have no clients, but instead run forever at some interval until the container is terminated,
the RAII style is less useful, since there are no clients to keep track of. In this case, prefer accepting an explicit
cancellation token from the toplevel `initialize_and_start_controllers` method, and stop your work when that token is
cancelled.

Example:

```rust
impl ClientlessBackgroundJob {
    // Returns nothing, since callers don't interact with it. We need a cancel_token to know when to stop.
    pub fn start(self, join_set: &mut JoinSet<()>, cancel_token: CancellationToken) {
        join_set.spawn(self.run(cancel_token)));
    }

    async fn run(self, cancel_token: CancellationToken) {
        let mut interval = tokio::time::interval(INTERVAL_DURATION);
        while let Some(()) = cancel_token.run_until_cancelled(interval.tick()).await {
            // do periodic work
        }
    }
}
```

Avoid mixing the approaches and returning an RAII handle for "client-less" background tasks, if it only exists to stop
the task when dropped. In nico-api, there are many such client-less background jobs, and storing each of their
handles for the correct lifetime is awkward and error-prone. Propagating a single top-level CancellationToken to each of
them is the preferred approach.

## General Rust Coding Standards

### Mutability

Prefer immutable data when possible. Mutable data can be hard to reason about if it's being reused multiple times,
and it's not clear when mutations are supposed to "stop". For example:

```rust
fn example(machines: Vec<Machine>) {
    let mut index: HashMap<MachineId, &Machine> = HashMap::new();
    for machine in &machines {
        index[machine.id] = machine;
        do_something_else_with(machine);
    }

    process_machines(&index);

    // Someone comes in later and adds:
    let another_machine = lookup_machine();
    index[another_machine.id] = another_machine;
    // Hmm, do I need to call `process_machines` again? Or will that process the same machines twice?
    process_machines(&index);
}
```

If data is left mutable (like `index` above), it's not clear at a given line of code if the data is "done" being
built, or still has more writes to go. It's also not clear whether it's safe to use the partially-written `index`. And
interleaving the construction of `index` with other side-effects (like `do_something_else_with(machine)`) makes it
unclear what the role of certain code is.

When building a Vec or a HashMap, prefer using iterators to building them from a for-loop:

```rust
fn example(machines: Vec<Machine>) {
    // index is immutable
    let index: HashMap<MachineId, &Machine> = machines.iter().map(|machine| {
        (machine.id, machine)
    }).collect();

    for machine in &machines {
        do_something_else_with(machine); // it's clear this is unrelated to constructing the index
    }

    // it's clear the index is now fully-built
    process_machines(&index);

    // This will now fail to compile, making it clear you have to move this to the beginning and use
    // `machines.iter().chain(Some(another_machine))` to include it in the original index.
    let another_machine = lookup_machine();
    index[another_machine.id] = another_machine;
}
```

### Initialization

Prefer struct literals for "plain old data", and only add a `new()` function if your type has fields which need to be
non-public. Prefer a Builder pattern only if your `new()` function is too large or difficult to call.

Reasoning: Struct literals include named fields which aid in readability, versus a `new()` function which does not have
labels for parameters. Builders can be more readable than a large `new()` function, but sacrifice compile-time
checks if any of the fields are required.

Compare:

```rust
fn example() {
    let u = User {
        id: "john",
        full_name: "John Smith",
    };
}
```

to:

```rust
fn example() {
    let u = User::new("john", "John Smith");
}
```

In the former it is clear what each argument is, whereas the latter you have to memorize which positional argument
corresponds to what field.

For types that are not simple plain-old-data, for example "services" (like a redfish client), or any other case
where you don't want the caller to initialize certain fields, a `new()` function may be required:

```rust
struct RedfishClient {
    // Callers pass this
    url: Url,
    // Callers don't pass this
    inner: HttpClient,
}

impl RedfishClient {
    fn new(url: Url) {
        Self { url, inner: make_http_client(url) }
    }
}
```

If your type has fields that can all be default values in the common case (like a Config object), prefer implementing
`Default` for the type and let callers call `T::default()`, instead of a parameterless `new()`.

If, in addition to not wanting callers to initialize certain fields, you also have a large number of fields that can
to be passed, consider adding a Builder type.

```rust
struct BigService {
    name: String,
    // ... lots of fields
}

struct BigServiceBuilder {
    name: Option<String>, // careful!
    // .. lots of Option<T> fields
}

impl BigServiceBuilder {
    fn name(mut self, name: String) -> Self {
        self.name = Some(name);
        self
    }

    fn build(self) -> BigService {
        BigService {
            name: self.name.expect("caller didn't provide name"), // oops!
            // ...
        }
    }
}
```

But be aware that this can sacrifice compile-time safety if any of the builder fields are required to construct the
object. You can work around this by requiring callers to pass any required fields in order to construct a builder:

```rust
impl BigService {
    fn builder(name: String) -> BigServiceBuilder {
        BigServiceBuilder {
            name,
            // ...
        }
    }
}
```

But as the number of required fields grows, a builder becomes less and less helpful in the first place. Builders
are most helpful when all fields are optional or have defaults, and are less helpful if there are a complex mix of
required and non-required fields. If you have a large struct with lots of required fields and lots of non-required
fields, consider splitting it into two types, one for the required fields, and a `Config` or `Params` type for the
non-required (defaultable) ones.

### Type Conversions

Prefer implementing `From` or `TryFrom` for types, rather than writing bespoke `.to_foo()` methods on objects. This
makes your conversion logic more idiomatic and discoverable (e.g. you can write `src.into()`) than custom methods.

Prefer implementing `From<T>` over `From<&T>`. This allows the conversion to move data without cloning. If the caller
cannot move the value, they can explicitly call `.clone()` themselves, which makes the cost more obvious.

An exception is when the conversion doesn't require cloning at all (e.g. it only reads `Copy` fields from the source.)
In this case borrowed conversion can be provided for ergonomics, but it should be provided in addition to the owned
conversion, not instead of it.

If you need to convert from a string representation, prefer `FromStr` to `From<String>` or `From<&str>`. This lets
callers call `.parse()`, which can be given a `&str` slice, which can avoid needless clones.

### Fields and getters

Avoid writing getters like `.some_field()` for a type, and prefer just making that field public.

The reason for this is specific to Rust and its ownership model: Public fields allow _partial moves_ of an object to
take ownership of its fields, whereas getters have to pick an ownership model that might not match what the caller
needs.

For example, if a type `User` has a field `pub name: String`, callers that own a User have several options for
reading the name field:

```rust
fn example(u: User) {
    foo(&u.name); // borrow `name`
    bar(u.name.clone()); // clone `name`
    baz(u.name); // partial move of `name` out of `u`
}
```

Whereas if `name()` were a getter, you have to pick an ownership model:

```rust
impl User {
    // By borrow: But callers have to clone if they need an owned string
    fn name(&self) -> &str {
        &self.name
    }

    // By cloned value: If callers only need to borrow, this clone is wasteful
    fn name(&self) -> String {
        self.name.clone()
    }

    // By transferring ownership: Now callers have to move `self` to get the name, and can no longer access other fields
    fn name(self) -> String {}
}
```

In cases where you don't want a field to be public for other reasons (like not allowing callers to write to it), and
you must write a getter, consider making two versions, a borrowed getter and an `into_` getter:

```rust
impl User {
    // Borrowed version
    fn name(&self) -> &str {
        &self.name
    }

    // Owned/destructured version
    fn into_name(self) -> String {
        self.name
    }
}
```

or an `into_parts` function, if you want to return multiple fields at once. But again, `pub` fields are
simplest and can avoid all of this, if you are able to use them.

### Avoid needless clones

Seeing `.clone()` all over is a sign that the ownership model may need some rethinking. Can you borrow the data
instead? Can you take ownership of the value you're cloning?

Common usages of clone that have easy fixes:

- Borrowing: Sometimes a clone happens because you have a borrow and need an owned value:

```rust
fn takes_string(s: String) {
    println!("{s}");
}

fn example(s: &str) {
    takes_string(s.clone()); // takes_string requires ownership so we have to clone
}
```

But the `takes_string` function doesn't truly need an owned string, it can be changed to take a `&str` as well.

Or conversely, `example` could be changed to take an owned String.

- Iterators: You can use `.into_iter()` instead of `.iter()` to an an owned version of each value, which you can then
  move without cloning:

```rust
fn takes_string(s: String) {}

fn avoid(v: Vec<String>) {
    v.iter().for_each(|i| takes_string(i.clone())); // avoid: needless clone
}

fn prefer(v: Vec<String>) {
    v.into_iter().for_each(|i| takes_string(i)); // prefer: moves out of v
}
```

- Struct initialization ordering: Sometimes just moving the order of parameters to a struct literal can avoid a clone:

```rust
struct Outer {
    inner: Inner,
    id: uint
}

struct Inner {
    name: String,
    id: uint
}

fn avoid(inner: I) -> Outer {
    Outer {
        inner: inner.clone(), // can't move inner yet, still need inner.id?
        id: inner.id,
    }
}

fn prefer(inner: I) -> Outer {
    Outer {
        id: inner.id, // Better: just swap the parameters and we can move inner last
        inner,
    }
}
```

- Making use of `Cow<T>`: If you might use a borrowed value or might produce your own, consider using `Cow` to avoid
  the clone in the borrowed case.

```rust
fn avoid(user: Option<&User>) -> User {
    if let Some(u) = user {
        u.clone()
    } else {
        User::default()
    }
}

fn prefer(user: Option<&User>) -> Cow<'_, User> {
    if let Some(u) = user {
        Cow::Borrowed(u)
    } else {
        Cow::Owned(User::default())
    }
}
```

### Error handling

Prefer custom errors for library crates, using the `thiserror` crate to reduce boilerplate for declaring them. Use
automatic conversions to convert between errors, or `.map_err()` if you have to. Using `eyre` is acceptable for crates
that are used for tests/mocks, or for toplevel binaries where errors are given to the user for informational purposes,
and not intended to be inspected by other rust code. (We do not always adhere to this rule.)

Avoid using `let _unused = foo();` to discard errors. This is error-prone: If later `foo()` is refactored to become
an async function, assigning the result to `_unused` silences the compiler warning telling you forgot to call `.await`.
If you don't care about the errors a function produces, prefer using `.ok()` to convert the error into a
(discardable) Option.

```rust
fn fails() -> Result<(), Error> {}

fn avoid() {
    // if somebody makes `fails()` async later, the compiler won't complain, and the future will
    // never get run
    let _dontcare = fails();
}


fn prefer() {
    // if somebody makes `fails()` async later, you get a compiler error
    fails().ok();
}
```

### Avoid stringly-typed values

When a value has a known, finite set of possibilities, model it with an enum
(or a struct of enums) and implement traits `Display` and `FromStr` — do not
pass it around as a bare `String` or `&str` literal. Stringly-typed values are
easy to misspell (`NICO-` vs `NICOO-`), silently break log filters and alerts,
and can't be exhaustively checked by the compiler. See
[`ErrorCode`](crates/api-model/src/errors.rs) for the pattern: typed
`ErrorSystem`/`ErrorSubsystem` parts plus a `code`, rendered to the wire string
in one place. Reserve raw strings for genuinely open-ended values.

### Prefer methods over free functions

When a function operates primarily on a specific type, define it as a method on that type rather than a free-standing function. This keeps related behavior co-located with the type, makes it easier to discover via autocomplete, and reads more naturally at the call site.

```rust
// Avoid — free function that operates on a specific type
fn machine_display_name(machine: &Machine) -> String {
    format!("{} ({})", machine.hostname, machine.id)
}

fn is_machine_ready(machine: &Machine) -> bool {
    machine.state == MachineState::Ready && machine.health.is_ok()
}

// Prefer — methods on the type itself
impl Machine {
    fn display_name(&self) -> String {
        format!("{} ({})", self.hostname, self.id)
    }

    fn is_ready(&self) -> bool {
        self.state == MachineState::Ready && self.health.is_ok()
    }
}
```

This applies to enums as well:

```rust
// Avoid
fn is_terminal_state(state: &MachineState) -> bool {
    matches!(state, MachineState::Failed | MachineState::Decommissioned)
}

fn state_label(state: &MachineState) -> &'static str {
    match state {
        MachineState::Ready => "ready",
        MachineState::Failed => "failed",
        MachineState::Decommissioned => "decommissioned",
    }
}

// Prefer
impl MachineState {
    fn is_terminal(&self) -> bool {
        matches!(self, Self::Failed | Self::Decommissioned)
    }

    fn label(&self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Failed => "failed",
            Self::Decommissioned => "decommissioned",
        }
    }
}
```

Free functions are still appropriate when the logic genuinely spans multiple unrelated types, belongs in a module rather than a single type, or is a utility with no natural owner.

### Error message style

Error messages follow the Rust API Guidelines ([C-GOOD-ERR]): the `Display` text of an error should
be a lowercase phrase with no trailing period. Errors are frequently wrapped into a larger chain, and
lowercase fragments compose cleanly where a capitalized, punctuated sentence would not:

```rust
// Avoid — capitalized and punctuated; jarring once it's wrapped
#[error("Failed to open the config file.")]
// -> "error starting service: Failed to open the config file.: permission denied"

// Prefer — lowercase, no trailing period
#[error("failed to open the config file")]
// -> "error starting service: failed to open the config file: permission denied"
```

This applies to every error-message surface: `thiserror`'s `#[error("...")]`, `anyhow!`/`bail!`,
`.context()`/`.wrap_err()`, and `CarbideError`/`Status` constructors. Every plain capitalized word is
lowercased (`Generic Quote Error: {0}` becomes `generic quote error: {0}`); a word carrying an internal
capital -- an acronym (`BMC`), an acronym-prefix (`DHCPv4`), or a CamelCase identifier
(`CreateVirtualNetwork`) -- is left as-is, as is a lone capital letter (which can't be told
apart from a single-letter identifier such as a DNS `A` record).

`cargo make lint-error-messages` enforces this in CI; `cargo xtask lint-error-messages --fix` rewrites
offenders in place. For the rare message that must keep its casing (a quoted external string, say), add
a `// xtask:allow-error-case` comment on, or directly above, the line. Rust sources with a leading
`// This file is @generated by ...` banner are skipped because their messages are owned by the generator.

[C-GOOD-ERR]: https://rust-lang.github.io/api-guidelines/interoperability.html#c-good-err
