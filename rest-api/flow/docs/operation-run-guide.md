# Operation Run Guide

This guide collects implementation notes for operation runs. It starts with
the gRPC contract summary added in the first implementation phase; future
sections should describe service behavior, dispatcher flow, persistence, and
operational considerations as those pieces land.

## gRPC Contracts

This section summarizes the operation-run gRPC contracts added to `Flow` so
reviewers can evaluate the API surface without reading the full design doc.

### RPCs

The operation-run API adds the following RPCs:

```proto
CreateOperationRun
GetOperationRun
ListOperationRuns
ListOperationRunTargets
PauseOperationRun
ResumeOperationRun
CancelOperationRun
```

An operation run is a durable, phased rollout over selected rack execution
targets. The create request stores a reusable configuration containing target
selection, execution options, and an operation template.

The current server implementation explicitly returns `codes.Unimplemented` for
these RPCs until the execution path is implemented.

### Create And Read APIs

`CreateOperationRunRequest` contains `name`, `description`, and required
`OperationRunConfiguration`. `CreateOperationRunResponse` returns only the
generated run ID, keeping create lightweight and avoiding expensive target or
stats computation on the create path.

`GetOperationRunRequest` takes an ID and an `include_stats` flag. When
`include_stats` is false, the response returns the run summary plus
configuration. When true, Flow computes derived stats from
`operation_run_target` rows and includes `OperationRun.stats`.

`ListOperationRunsRequest` returns lightweight `OperationRunSummary` records,
not full configurations or target-derived stats. Filtering supports name query,
operation kind, status, and status reason. Status and reason are modeled
together as `OperationRunStateFilter`; each filter entry ANDs its populated
fields, and multiple entries OR together.

### Target Listing

`ListOperationRunTargetsRequest` lists materialized rack execution targets for
one run. It supports a target status filter, pagination, and phase scope.
`UNKNOWN` status means no status filter.

Phase scope can be:

- `CURRENT_PHASE`
- `COMPLETED_PHASES`
- `CURRENT_AND_COMPLETED_PHASES`

This lets callers inspect just the active phase, prior completed phases, or the
full materialized set so far.

### Configuration

`OperationRunConfiguration` has three parts:

```proto
OperationRunSelector selector
OperationRunOptions options
OperationRunOperation operation
```

The selector currently supports percentage-based selection only.
`PercentageSelector.percentage` is required and valid from `1..100`. `seed` is
optional; if omitted, Flow generates and stores one so the chosen cohort is
deterministic and auditable.

`OperationRunOptions` includes:

- `max_concurrent_targets`: max active child tasks at once.
- `safety_policy`: required safety gates.
- `conflict_policy`: optional; defaults are operation-type/code based.
- `ordering_policy`: optional; defaults to random ordering with generated seed.
- `phase_policy`: optional; defaults to one phase containing all selected
  targets.

### Safety Gates

`OperationRunSafetyPolicy` contains repeated gates. Gates compose with OR
semantics: any tripped gate pauses the run.

Supported gates are:

- `OperationRunFailureRateGate`
- `OperationRunFailureCountGate`

Both support `CURRENT_PHASE` and `CUMULATIVE_RUN` scopes. Failure rate uses
`failed_targets / planned_targets` for the selected scope.

### Ordering, Conflict, And Phases

Ordering is a `oneof` policy. Random ordering is supported now.
Physical-location ordering is present in the contract for future expansion but
documented as unsupported in the first implementation.

Conflict handling currently supports retry policy only. Missing retry durations
are filled from operation-specific defaults and stored as effective
configuration.

Phase policy supports equal phases, explicit percentage phases, and explicit
count phases. For count phases, configured counts define the early phases; the
final generated phase covers the remaining targets.

`OperationRunPhaseAdvancePolicy.auto_advance` controls phase boundaries. When
false, a successful phase pauses with `PHASE_GATE` and waits for
`ResumeOperationRun`. When true, the dispatcher advances automatically as long
as safety gates are not tripped.

### Target Scope

`OperationRunTargetScope` controls how candidate scope is built before applying
the selector.

The embedded operation `target_spec`, when present, is the inclusive base scope.
If `target_spec` is omitted, the planner uses the default qualified/applicable
scope. `default_scope_component_filter` can restrict that default scope to
specific component types or component UUIDs, such as "all compute trays in all
qualified racks"; that field is only valid when `target_spec` is omitted.
`exclude_operation_run_ids` then removes materialized targets from prior
operation runs from that base scope before selector application.

### Operation Template

`OperationRunOperation` is a `oneof`. The only supported operation today is
`upgrade_firmware`.

For normal `UpgradeFirmware`, `target_spec` means "run exactly on these
targets" and is required. Inside `CreateOperationRun`, the embedded
`target_spec` is optional and defines candidate scope before selector
application.

### State And Stats

Run state is modeled as `OperationRunState` with `OperationRunStatus` and
`OperationRunStatusReason`. Reasons distinguish operator pause, phase gate,
safety gate, and conflict retry timeout.

Stats are optional and derived, not returned unless requested.
`OperationRunStats` contains current phase stats and cumulative phase stats.
Each phase stat includes phase index, selected target count, and outcome
counts: completed, failed, terminated, skipped.

`OperationRunTarget` represents a materialized rack execution target. It tracks
rack ID, sequence index, phase index, optional child task ID, target status,
message, the resolved `components_by_type` execution set, and timestamps. The
target output uses resolved components grouped by type rather than a
`ComponentFilter`, because target rows are materialized execution state instead
of unresolved selection criteria.

## Execution Planning

Phase 2 adds planning helpers under `internal/operationrun/manager/planner`.
The planner does not submit tasks and does not query inventory directly.
Instead, it depends on a `TargetLookup` interface for primitive target reads
from default scope, explicit target specs, and prior runs. The planner owns
when those sources are used, scope composition, selection, ordering, phase
assignment, and conversion into deterministic `OperationRunTarget` rows.

The planning flow is:

1. Resolve the embedded operation `target_spec` as the base scope when present.
   Otherwise, resolve the default qualified scope.
2. Resolve targets from `exclude_operation_run_ids`, when present, and subtract
   them from the base scope.
3. Apply `PercentageSelector` using a stored selector seed.
4. Apply `OrderingPolicy`; the first implementation supports random ordering.
5. Assign `sequence_index` and `phase_index` from the selected order and phase
   policy while converting rack execution targets into operation-run target
   rows.

This staged lookup matters for both correctness and memory use. An explicitly
specified but empty `target_spec` remains an empty candidate scope instead of
falling back to all qualified racks. Prior operation-run targets are resolved
only when `exclude_operation_run_ids` is present, then subtracted from the base
scope.

The first implementation models each `operation.RackExecutionTarget` as a
rack-scoped execution unit with a concrete resolved component set. Caller-facing
filters are resolved before planning; planner set operations subtract component
UUIDs rather than unresolved filter expressions. Target rows persist this
resolved map as `components_by_type`, matching the shape used by task
attributes when tasks are submitted.

`operation.RackExecutionTarget` intentionally lives in the shared `operation`
package, even though operation runs are the first consumer. Task schedule scope
resolution already produces the same resolved shape, and a follow-on PR should
refactor task schedules to use `operation.RackExecutionTarget` before
converting to `TaskScheduleScope` rows. Keeping the type next to `TargetSpec`
now avoids moving the shared resolved-target model again as operation-run
dispatching and other management models start to consume it.

`CreateOperationRun` plans targets for all phases in one pass: the selected and
ordered targets are persisted once, then later phase execution reads the
already materialized rows. Code that needs one phase should filter the
materialized targets by `phase_index` instead of re-planning a phase
independently.

Physical-location ordering is intentionally rejected by the planner for now,
even though the API branch exists. That keeps the first execution path narrow
while preserving the contract shape needed for later location-aware rollouts.

Planner configuration includes `MaxCandidateScopeTargets`, a memory guard for
target lookup. The planner passes this limit to `TargetLookup` as
`TargetLookupOptions`; lookup implementations should enforce it while querying
by fetching at most `limit + 1` rows and returning a clear error if the source
scope is too large. This prevents default-scope or prior-run lookups from
building oversized in-memory target lists before selection can run.

## Manager Layer

`internal/operationrun/manager` is the intended access point for service code
and future dispatcher code that needs to manage operation runs. The root
`operationrun` package owns domain/configuration types; `manager/planner`
builds deterministic target plans; `manager/store` owns persistence.

`Manager.Create` accepts an `OperationRun` and orchestrates creation: it asks
the planner to build the deterministic target plan, rejects empty plans, and
persists the run plus all planned targets in one store transaction. The stored
selector, options, and operation template are decoded and validated inside the
planner path as candidate resolution, selection, ordering, and phase assignment
need each part of the configuration.

Read paths are thin manager delegations for now. Stats calculation,
`TargetLookup` implementation, dispatcher lifecycle changes, and
pause/resume/cancel state transitions should be added behind this manager
boundary instead of having service code reach into planner or store directly.
