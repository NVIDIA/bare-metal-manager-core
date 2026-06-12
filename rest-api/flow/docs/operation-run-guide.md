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

### Target Scope Composition

`OperationRunTargetScope` controls how candidate scope is built before applying
the selector.

Sources can come from:

- embedded operation `target_spec`
- materialized targets from previous operation runs

Each source can be inclusive or exclusive:

- `exclude_target_spec`
- `exclude_operation_run_targets`

If both `target_spec` and previous-run targets are inclusive,
`inclusive_scope_composition` controls how they combine:

- `INTERSECT`: target must be in both sources.
- `UNION`: target can be in either source.

Exclusion sources are always subtracted after inclusive scope composition.

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
message, optional component filter, and timestamps.
