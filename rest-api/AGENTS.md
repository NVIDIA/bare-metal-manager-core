# AGENTS.md

This file provides guidance for AI coding agents working in the
`infra-controller-rest` repository.

## Project Overview

**NVIDIA Infrastructure Controller REST** is a collection of Go microservices that comprise
the management backend for NVIDIA Infrastructure Controller (NICo), exposed as a REST API. It
provides multi-tenant, API-driven bare-metal lifecycle management, working in
concert with [NVIDIA Infrastructure Controller Core](https://github.com/NVIDIA/infra-controller-core)
for on-site hardware operations.

> **Status:** Experimental/Preview. APIs, configurations, and features may
> change without notice between releases.

### Key Responsibilities

- REST API for hardware inventory, provisioning, and lifecycle orchestration
- Multi-tenant site and instance management
- Temporal-based cloud and site workflow orchestration
- On-site agent for datacenter-local operations
- IP address management (IPAM)
- Authentication and authorization (Keycloak, JWT, service accounts)
- Native PKI certificate management
- CLI client (`nicocli`) with interactive TUI

## Repository Structure

```text
infra-controller-rest/
├── api/                  # Main REST API server (Echo-based)
├── auth/                 # Authentication (Keycloak, JWT, service accounts)
├── cert-manager/         # Native PKI certificate management (credsmgr)
├── cli/                  # CLI client (nicocli) with TUI
├── common/               # Shared utilities and configuration
├── db/                   # Database layer (Bun ORM, pgx, migrations)
├── deploy/               # Kubernetes deployment (Kind, Kustomize, Helm)
├── docker/               # Dockerfiles (local dev and production)
├── helm/                 # Helm charts for Kubernetes deployment
├── ipam/                 # IP address management
├── nvswitch-manager/     # NVSwitch firmware management (NSM)
├── openapi/              # OpenAPI spec and SDK generation
├── powershelf-manager/   # Power shelf management (PSM)
├── flow/                 # Carbide Flow logic
├── sdk/                  # Go API client (simple and standard variants)
├── site-agent/           # On-site agent for datacenter
├── site-manager/         # Site management service (sitemgr)
├── site-workflow/        # Site-level Temporal workflows
├── temporal-helm/        # Temporal Helm chart
├── workflow/             # Cloud Temporal workflows and activities
├── workflow-schema/      # Protobuf and workflow schemas
├── .github/              # GitHub Actions workflows and templates
├── Makefile              # Primary build/task automation
└── go.mod                # Go module and dependency management
```

## Technology Stack

- **Language:** Go (version specified in `go.mod`; module `github.com/NVIDIA/infra-controller-rest`)
- **HTTP framework:** Echo v4 (with middleware for CORS, auth, rate limiting, audit)
- **Database:** PostgreSQL via pgx v5 (connection pool) and Bun ORM (queries, migrations)
- **Workflow engine:** Temporal (cloud and site workflows/activities)
- **gRPC:** Connect-RPC and google.golang.org/grpc (site-agent, workflow schemas)
- **Protobuf:** buf for code generation
- **Observability:** OpenTelemetry, Prometheus (echoprometheus), Sentry
- **Auth:** Keycloak, JWT
- **Testing:** testify (assert/require/suite), go-sqlmock, testcontainers-go, gomock
- **Build tool:** Make

## Build, Test, and Lint Commands

### Building

```bash
# Build all binaries (linux/amd64, static)
make build

# Build and install CLI to $GOPATH/bin
make nico-cli

# Build Docker images (production)
make docker-build

# Build Docker images (local dev, public base images)
make docker-build-local
```

### Testing

```bash
# Run all tests (auto-manages PostgreSQL container)
make test

# Module-level tests
make test-api
make test-db
make test-workflow
make test-auth
make test-common
make test-cert-manager
make test-site-agent        # requires mock gRPC servers
make test-site-manager
make test-site-workflow
make test-ipam

# PostgreSQL management for tests
make postgres-up            # start test PostgreSQL container
make postgres-down          # stop test PostgreSQL container
make ensure-postgres        # start if not running, wait until ready
make migrate                # run database migrations against test DB
```

Tests require a PostgreSQL container (postgres:14.4-alpine) on port 30432.
The Makefile manages this automatically via `ensure-postgres`.

### Linting and Formatting

```bash
# Check formatting (fails if repo is dirty after go fmt)
make fmt-go

# Run all linters (go vet + golangci-lint + revive)
make lint-go

# Auto-fix formatting
go fmt ./...
```

### OpenAPI

```bash
# Lint the OpenAPI spec
make lint-openapi

# Preview in Redoc UI (http://127.0.0.1:8090)
make preview-openapi

# Generate Go SDK from OpenAPI spec
make generate-sdk

# Publish OpenAPI docs
make publish-openapi
```

### Protobuf Code Generation

```bash
make nico-proto          # fetch proto files from nico-core
make nico-protogen       # generate Go code from protos
make flow-proto             # fetch Flow proto files
make flow-protogen          # generate Go code from Flow protos
```

### Local Development (Kind cluster)

```bash
make kind-reset             # full reset: cluster + infra + Helm deploy
make kind-reset-kustomize   # full reset with Kustomize instead of Helm
make kind-redeploy          # rebuild and restart (fast iteration)
make helm-redeploy          # rebuild and restart via Helm
make kind-status            # check pod status
make kind-logs              # tail API logs
make kind-verify            # health checks
make kind-down              # tear down cluster
```

## Coding Conventions

- Follow standard Go conventions; `go fmt` is enforced in CI.
- Linting uses `golangci-lint` (v2 config in `.golangci.yml`) with most
  linters enabled, plus `revive` (config in `.revive.toml`).
- Use `testify` (assert/require) for test assertions.
- Tests that need a database use a PostgreSQL container (testcontainers-go
  or the Makefile-managed container).
- Tests run with `-p 1` (serial) and often with `-race`.
- API handlers live in `api/pkg/api/handler/`, request/response models in
  `api/pkg/api/model/`, and DB models in `db/pkg/db/model/`.
- OpenAPI schema in `openapi/spec.yaml` must be updated whenever API
  endpoints are added or modified.

### Prefer range-based iteration over C-style `for` loops

The module is on Go 1.25, so reach for range-based iteration before the
three-clause `for i := 0; i < n; i++` / `i--` form. Go 1.22 range-over-integer
and Go 1.23 range-over-function iterators (`slices.Backward`, `slices.All`,
`slices.Values`, `maps.Keys`, `maps.Values`, …) drop the manual index
bookkeeping that the older form makes a reader re-derive to trust.

1. **Counting loop → range-over-integer.** When the bound is a count (not a
   slice you also index for values), use `for i := range n` (index needed) or
   `for range n` (index unused) instead of `for i := 0; i < n; i++`. This
   covers `reflect` walks: `for i := range v.NumField()` /
   `for i := range v.Len()`.
2. **Reverse loop → `slices.Backward`.** Replace
   `for i := len(s) - 1; i >= 0; i--` with `for i, v := range slices.Backward(s)`.
   When the reverse order is intentional (LIFO teardown, "find the last element
   matching X"), `slices.Backward` states that intent instead of leaving it
   implicit in the index arithmetic. Use `for i := range slices.Backward(s)`
   when you only need the index (to take `&s[i]` or mutate `s[i]`).
3. **Index loop over a slice → plain `range`.** `for i := 0; i < len(s); i++`
   that reads `s[i]` becomes `for i, v := range s` (or `for _, v := range s`);
   keep the index-only `for i := range s` when the body needs `&s[i]`.

Keep the C-style form when range can't express the loop, and say why if it
isn't obvious:

- **Byte-wise string scans.** A loop that indexes `s[i]` on a `string` must
  stay C-style — `for i := range s` over a string yields *runes*, silently
  changing byte offsets.
- **The index is mutated or looks ahead/behind** in the body (`i++` to consume
  a paired argument, `s[i+1]`, `i = j-1`). Range indices are read-only.
- **1-indexed or offset-start loops** (`for page := 1; page <= total; page++`,
  `for i := windowStart; i < windowEnd; i++`). Range-over-integer is 0-based;
  forcing a `+1` reads worse than the original.
- **Generated code** (e.g. `sdk/standard`) — leave it; regeneration overwrites
  hand edits.

A related cleanup: a backward byte scan for a delimiter is
`strings.LastIndexByte`, not a hand-rolled `for i := idx; i >= 0; i--` — see
`(*IPAddr).Scan` in `powershelf-manager/pkg/db/model/types.go`.

### Proto conversion methods

DB and API model types that round-trip with a workflow-schema (`cwssaws`)
or Flow (`flowv1`) protobuf types carry conversion as receiver methods, not
free functions. The convention layers cleanly so call sites are
predictable and every entity has the same surface:

1. **Primary entity ↔ proto entity** lives on the DB model:
   `func (m *T) ToProto(...) *protoT` and
   `func (m *T) FromProto(p *protoT, ...)` — symmetric pair, defined
   together. `FromProto` mutates the receiver and returns no error.
   The field-level contract is:
   - A `nil` proto is a no-op (receiver untouched).
   - Required ID fields (e.g. `m.ID`) are preserved on a missing or
     unparseable proto value, because callers pre-validate UUIDs
     before calling.
   - Optional pointer fields are cleared when the proto omits them
     **or** when the proto value is invalid (e.g. an unparseable
     UUID). For example, `(*Vpc).FromProto` clears
     `NVLinkLogicalPartitionID` in both cases so the receiver ends
     up as a clean reset rather than a partial merge.
2. **Per-API-request → proto request** lives on the corresponding API
   request type, not on the entity:
   `func (req *APIXCreateRequest) ToProto(...) *protoXCreateRequest`,
   `func (req *APIXUpdateRequest) ToProto(...) *protoXUpdateRequest`.
   These methods commonly read the canonical fields via the entity's
   `ToProto()` (passed in or fetched) and overlay request-specific
   fields. Putting them on the API request type keeps the entity
   surface focused on the canonical representation. When the API
   request type uses `*T` to distinguish "field not provided" (nil)
   from "explicitly clear" (non-nil pointer to zero value), the
   request's `ToProto` is responsible for preserving that distinction
   on the wire — overriding the entity-derived value when the API
   request touched the field, even if the post-merge entity has the
   same zero value.

   **`ToProto` does not return errors.** It trusts that the request
   has already been validated and that the handler has performed any
   cross-context checks Validate cannot see. Validation lives in
   `(req *APIXCreateRequest).Validate() error`, which is the
   universal pre-`ToProto` step and must be called before the request
   reaches `ToProto`. Anything `ToProto` would otherwise have to
   double-check — width casts on bounded request fields, enum-value
   checks, cross-field structural rules — belongs in `Validate`
   instead, so the translation step stays a focused mapper.

   **What stays in the handler:** authorization (RBAC, tenant
   privileges, cross-resource ownership lookups), and validation that
   depends on context `Validate` cannot see (site config defaults
   resolved at request time, DAO lookups, etc.). These run before
   `ToProto` so that by the time it executes the request is safe to
   trust.
3. **Entity-level request shapes that don't have an API request body**
   (e.g. delete by path-param, maintenance / metadata-update flows that
   carry no client payload) stay on the entity:
   `func (m *T) ToDeletionRequestProto() *protoXDeletionRequest`,
   `func (m *T) ToMaintenanceRequestProto(...) *protoXMaintenanceRequest`.
4. **Side inputs that are not on the model** (BMC credentials, a linked
   machine ID resolved by the caller, a fallback timestamp, validated /
   converted enum values) are passed as additional arguments —
   preferably grouped into a `XCredentials` struct declared next to the
   model, with a comment explaining why the field isn't persisted.
5. **Sub-messages of a proto request:** when a request DTO produces a
   reusable piece of a proto request that is shared across multiple
   request types (e.g. `OperationTargetSpec`, `[]*Filter`), name the
   method after the sub-message it returns: `ToTargetSpec()`,
   `ToFilters()` (see `RackFilter`, `APIRackGetAllRequest`).
6. **Constructor wrappers for `FromProto`:** API model types that are
   constructed from a proto in handlers commonly expose a
   `func NewAPIX(p *protoX) *APIX` wrapper that returns `nil` for a `nil`
   proto and otherwise builds the value and calls `FromProto`. See
   `NewAPITray`, `NewAPIRack`.

`Vpc` is the reference implementation for rules 1–3:
`(*cdbm.Vpc).ToProto/FromProto` cover the entity↔proto round-trip,
`(*model.APIVpcCreateRequest).ToProto` / `(*model.APIVpcUpdateRequest).ToProto`
cover request-shape conversion, and `(*cdbm.Vpc).ToDeletionRequestProto`
stays on the entity because there's no API request body for delete.

`InstanceType` is the reference for everything else under this rollout
(typed-slice validation, typed-map proto behavior, ozzo composition,
shared conversion helpers): `(*cdbm.InstanceType).ToProto/FromProto`
+ `(*InstanceType).AttachCapabilities` on the entity,
`APIMachineCapabilities` + `APIMachineCapability` for the list/element
split, `cdbm.Labels` for the typed map, and
`common/pkg/util.IntPtrToUint32Ptr` for shared casts.

### Validate cooperates with ToProto

`Validate` and `ToProto` work as a pair: `Validate` enforces every rule
the wire format relies on, and `ToProto` is a pure mapper that trusts
the result. The conventions below are how the rules are organised.

1. **Prefer ozzo's built-in rules.** `validation.Required`,
   `validation.Min`, `validation.Max`, `validation.In`,
   `validation.Length`, `validation.By`, `validation.Each` compose
   cleanly inside `validation.ValidateStruct`. Custom helpers like a
   `validateXBounds(value, name)` free function are usually
   unnecessary — reach for them only when no built-in fits.
2. **List-level rules live on a typed slice.** When a request carries
   a slice and needs both per-element rules and rules that span
   elements (uniqueness, ordering, cross-element constraints), define
   `type APIXs []APIX` with its own `Validate()` that calls
   `validation.Validate(s, validation.Each())` to delegate per-element
   checks and then enforces the list-level rules. The parent struct
   wires it up with a single `validation.Field(&parent.Xs)`; ozzo
   discovers the typed slice's `Validate` via the Validatable
   interface. See `(APIMachineCapabilities).Validate` for the
   canonical shape.
3. **Cross-field rules use named methods via `validation.By`.** When a
   check spans multiple fields on the same struct, pull it out as a
   named method on the type and reference it with
   `validation.By(t.validateX)`. Avoid inline anonymous closures —
   named methods are discoverable, individually testable, and the
   `Validate` body reads like a high-level outline of the rules. See
   `(APIMachineCapability).validateDeviceType` and
   `validateInactiveDevices`.
4. **Validators that compose with `validation.By` take `interface{}`.**
   Helpers used across structs (e.g. `util.ValidateLabels`,
   `util.ValidateNameCharacters`) match ozzo's `RuleFunc` signature
   `func(value interface{}) error`, so they drop into
   `validation.Field(&t.Field, validation.By(util.ValidateX))`
   directly. Internal type assertion handles the concrete type.

### Named types own their proto behavior

A `map`, `slice`, or other primitive composite that represents a
domain concept with conversion needs gets a named type with methods,
not a free function. The receiver-method form keeps the call site
discoverable (`t.Field.ToProto()` / `t.Field.FromProto(...)`) and
makes the type the single home for all related behavior. Free
functions like `LabelsToProto(m map[string]string)` or
`LabelsFromProtoMetadata(md *Metadata) Labels` are an anti-pattern —
make the value typed and put the method on it.

`FromProto` on a leaf named type is a pointer-receiver method that
mutates the receiver in place, mirroring the entity-level
`(*T).FromProto` shape. A `nil` input clears the receiver to its
zero value so callers can distinguish "no data reported" from "data
explicitly cleared." Reach the method on a struct field with
`t.Field.FromProto(...)` — which requires the field itself to use
the named type, not the underlying primitive. Entity struct fields
that round-trip with the proto should be typed accordingly (e.g.
`Labels Labels` instead of `Labels map[string]string`); CreateInput
/ UpdateInput shapes that don't call `FromProto` themselves may stay
on the underlying primitive until they need it.

- `db/pkg/db/model.Labels` (`type Labels map[string]string` with
  `(Labels).ToProto() []*cwssaws.Label` and
  `(*Labels).FromProto([]*cwssaws.Label)`) is the reference for
  map-shaped values that round-trip with workflow `Metadata.Labels`.
  Entity callers reach it via `entity.Labels.FromProto(proto.Metadata.GetLabels())`
  — the proto getter is nil-safe and returns `nil` for missing
  metadata, which the method translates into a `nil` receiver.
- `db/pkg/db/model.MachineCapabilityType` and `MachineCapabilityDeviceType`
  (`type X string` with `(X).ToProto() cwssaws.X` and
  `(*X).FromProto(cwssaws.X)`) are the reference for **typed-string
  domain enums** that round-trip with proto enum values. The DB column
  stays a plain string under the named type, but the conversion to /
  from the proto enum lives as methods on the type — not as a free
  helper. `(*MachineCapability).ToProto` collapses to
  `mc.Type.ToProto()` / `mc.DeviceType.ToProto()`, and `FromProto`
  collapses to `mc.Type.FromProto(...)`. Unknown values silently leave
  the receiver as the empty string (a warning is logged) so the
  entity-level `Validate` can be the gate that rejects them; an
  optional `*X` field with the proto's zero-value enum on the wire
  drops to `nil` rather than encoding an "unknown" pointer.
- `APIMachineCapabilities` (`type APIMachineCapabilities
  []APIMachineCapability` with `(APIMachineCapabilities).Validate()`)
  is the reference for slice-shaped values that own list-level rules.

### Shared conversion helpers live in `common/pkg/util`

Helpers that convert primitive types (`*int` ↔ `*uint32`, etc.) and
have no entity association live in `common/pkg/util/converter.go`,
not in entity-specific files. Under the ToProto / FromProto
convention they are trusted casts: the bounds checks live in
`Validate` upstream of them, so the helpers do not return errors and
do not log warnings — anything that needs to fail belongs in
`Validate`. `common/pkg/util.IntPtrToUint32Ptr` is the reference.

### Database transactions

Handler code that touches the database uses the closure-based transaction
helpers from `db/pkg/db`, not manual `BeginTx`/`Commit`/`Rollback`. Most of
the rules below are lessons from the WithTx migration of every primary
handler — applying them keeps the next handler's diff predictable.

1. **Use `cdb.WithTx` / `cdb.WithTxResult`.** Both run the closure in a
   transaction and unwind it for you on error. `WithTxResult[T]` returns a
   single `T` from the closure; `WithTx` returns only `error` and uses
   outer-scope variables for any outputs.
2. **Pick one or the other — don't mix.** `WithTxResult` paired with
   outer-scope partner vars populated inside the closure is the worst of
   both worlds. Either use `WithTxResult` cleanly (single value out) or use
   `WithTx` with every output as an outer-scope variable. The Network
   Security Group, InfiniBand Partition, and VPC Prefix handlers were
   reworked specifically to settle this.
3. **Reads belong outside the transaction unless they need to be inside.**
   Pure input-validation reads (does this site exist, does the tenant own
   it, is the SSH key on this tenant) hold the tx open and pin a DB
   connection for no benefit. Move them above the `cdb.WithTx(...)` call
   and start the tx only when writes begin. Reads that *do* belong inside
   are: anything done under an advisory lock for race protection,
   anything whose result drives a write decision that must see the locked
   state (e.g. existing associations used for sync-state diff), and
   reads done in the same tx as their dependent writes for read-your-writes
   consistency.
4. **Acquire an advisory lock at the top of the closure for TOCTOU-prone
   flows.** When the closure does read-then-mutate on one entity (or two
   concurrent writers could both pass a pre-flight check), call
   `tx.TryAcquireAdvisoryLock(ctx, cdb.GetAdvisoryLockIDFromString(<key>), nil)`
   first. After the lock, re-read whatever you pre-checked outside the tx
   so the check and the write happen against the same snapshot. Don't keep
   the pre-flight check around if the in-tx check covers it — one source
   of truth is clearer than two.
5. **Workflow-trigger flows use the `timeoutResp` pattern.** When the
   closure does `stc.ExecuteWorkflow` + `we.Get(...)`, a timeout has to
   terminate the workflow *after* the DB tx unwinds so the cleanup call
   doesn't block holding a connection. Declare `var timeoutResp func() error`
   in the outer scope, set it inside the timeout branch, return a
   `cutil.NewAPIError` from the closure to roll back the tx, then call
   `timeoutResp()` after `WithTx` returns:

   ```go
   var timeoutResp func() error
   err = cdb.WithTx(ctx, dbSession, func(tx *cdb.Tx) error {
       // ... writes ...
       we, wferr := stc.ExecuteWorkflow(wfCtx, opts, "CreateInstanceV2", req)
       // ... wferr handling ...
       wferr = we.Get(wfCtx, nil)
       if wferr != nil {
           var timeoutErr *tp.TimeoutError
           if errors.As(wferr, &timeoutErr) || wferr == context.DeadlineExceeded || wfCtx.Err() != nil {
               timeoutCause := wferr // explicit capture; defensive against future refactors
               timeoutResp = func() error {
                   return common.TerminateWorkflowOnTimeOut(c, logger, stc, wid, timeoutCause, "Instance", "CreateInstanceV2")
               }
               return cutil.NewAPIError(http.StatusInternalServerError, "Instance create workflow timed out", nil)
           }
           // ... non-timeout error paths ...
       }
       return nil
   })
   // The wrapping `if err != nil` ensures real tx-helper errors (commit /
   // rollback failures that wrap into something other than the cutil.APIError
   // marker we returned for the timeout case) are surfaced via HandleTxError,
   // while the timeout-case APIError falls through to the timeoutResp call.
   if err != nil {
       var apiErr *cutil.APIError
       if !errors.As(err, &apiErr) || timeoutResp == nil {
           return common.HandleTxError(c, logger, err, "Failed to create Instance, DB transaction error")
       }
   }
   if timeoutResp != nil {
       return timeoutResp()
   }
   ```

   Notes:
   - `common.TerminateWorkflowOnTimeOut` replaces ~12 lines of inline
     `stc.TerminateWorkflow` + manual context boilerplate. Always prefer it.
   - **Pass the literal workflow name** (the exact string used in
     `stc.ExecuteWorkflow`), not a shortened action label. The helper uses
     it in logs and the termination reason, so `"CreateInstanceV2"` —
     not `"Create"` — is what should be there.
   - **Capture the timeout error explicitly** (`timeoutCause := wferr`)
     before the closure literal. The closure-scoped variable usually
     preserves the right value due to Go's per-iteration scoping, but the
     explicit capture documents intent and is resilient to future
     refactors that rename or move things around.
6. **Error returns inside vs. outside the closure.** Inside, return
   `cutil.NewAPIError(code, msg, data)` — `common.HandleTxError` translates
   it to a response after the tx unwinds. Outside (post-`WithTx`), return
   `cutil.NewAPIErrorResponse(c, code, msg, data)` directly. When moving a
   read out of the closure, the error path's constructor needs to flip too.
7. **Don't leak raw DB errors to clients.** Pass `nil` (not the underlying
   `derr`) as the `data` argument of `cutil.NewAPIError` /
   `cutil.NewAPIErrorResponse`. Log the underlying error with the contextual
   `logger` so it lands in server logs without ending up in the response
   payload.
8. **Split assign-and-condition into two statements.** Prefer

   ```go
   derr := someDAO.Action(ctx, tx, ...)
   if derr != nil {
       logger.Error().Err(derr).Msg("...")
       return cutil.NewAPIError(http.StatusInternalServerError, "...", nil)
   }
   ```

   over `if derr := someDAO.Action(...); derr != nil { ... }`. This is a
   reviewer preference applied consistently across the codebase — the
   wider scope on the error variable is a feature, not a bug, and the two
   statements read more cleanly than the combined form.

The Instance handlers (`api/pkg/api/handler/instance.go`) cover rules 1–8
end-to-end across Create/Update/Reboot/Delete and serve as the most
complete reference. SSH Key Group's Create handler is the cleanest example
of rule 3 (validation reads hoisted out of the tx). NVLink Logical
Partition's Delete handler shows the rule 5 `timeoutResp`-gating pattern
in its simplest form.

## Git Workflow

When writing git commit messages, follow the conventions below:

- Use `git mv` to move files already checked into git.
- Explain non-obvious trade-offs in the commit message.
- Wrap prose (not code) to match git commit conventions; follow semantic
  commit conventions for the title (e.g. `feat:`, `fix:`, `chore:`).
- Use backticks for types or short code snippets; use indented code blocks
  for full lines of code.

## Code Style Preferences

- Document when you have intentionally omitted code that the reader might
  otherwise expect to be present.
- Add TODO comments for features or nuances not important to implement
  right away.

## Commit Guidelines

All commits **must** meet the following signing requirement:

- **DCO sign-off** — certifies the Developer Certificate of Origin:
  ```bash
  git commit -s -m "Your commit message"
  ```
  DCO compliance is enforced automatically; unsigned commits block merging.

## Pull Request Guidelines

- Write PR descriptions as if the audience has no context: explain the *why*.
- Reference related issues.
- Keep PRs focused on a single change.
- Do not land unused code unless the PR is too large to review otherwise.
- Ensure all CI checks pass before requesting review.

## CI / CD

The primary CI workflow (`.github/workflows/main-build.yml`) runs on pushes
to `main`, `feat/**`, `fix/**`, `chore/**`, `hotfix/**`, `version/**`,
and `pull-request/[0-9]+` branches, as well as `v*.*.*` tags and manual
`workflow_dispatch`. It performs:

- Style checks (`go fmt`, `revive`, `go vet`)
- Lint (`golangci-lint`)
- OpenAPI spec validation
- Generated files check
- Test matrix across all modules (with PostgreSQL service container)
- Binary builds (api, workflow, migrations, sitemgr, credsmgr, site-agent)
- Security scanning (TruffleHog)
- Docker image builds and pushes
- Helm chart validation
- Release promotion

## Pre-commit Hooks

```bash
make pre-commit-install     # install pre-commit + trufflehog hooks
make pre-commit-run         # scan all files for secrets
make pre-commit-update      # update hooks to latest versions
```

## Further Reading

- [`README.md`](README.md) — Project overview and getting started
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — Contribution workflow and DCO process
- [`openapi/README.md`](openapi/README.md) — OpenAPI schema development
- [`cli/README.md`](cli/README.md) — CLI client reference
- [`deploy/README.md`](deploy/README.md) — Deployment quickstart guide
- [`deploy/INSTALLATION.md`](deploy/INSTALLATION.md) — Detailed installation guide
