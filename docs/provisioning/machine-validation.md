# Machine Validation <Badge intent="info">v2.0</Badge>

Machine Validation is NVIDIA Infra Controller's in-band validation framework for
checking a machine before it is made available to tenants. NICo uses Scout to run
validation tests on the host, collect the results, and report them back to the
site controller.

The framework is intended to be extensible. NICo provides a catalog of built-in
hardware validation tests and supports site-provided container plugins through
the Machine Validation API.

## Summary

Machine Validation helps operators answer a simple question: is this machine
healthy enough to enter or return to the tenant-ready pool?

NICo can run validation during lifecycle workflows such as discovery and release,
and administrators can also start validation on demand for a specific machine.
Each validation run selects tests based on context, platform support, test
enablement, verification state, tags, and any allow list supplied by the
operator.

In normal lifecycle validation, NICo runs only tests that are both enabled and
verified. Unverified tests can be exercised through on-demand validation before
they are promoted into the standard workflow.

## Audience

This guide is written for site administrators, SREs, platform administrators, and
developers who manage or extend NICo machine validation. The examples assume the
operator has access to the target site through `nico-admin-cli` and has the
permissions required to view or modify machine validation configuration.

## Prerequisites

Before using Machine Validation, confirm the following:

- Machine Validation is enabled for the site.
- The operator has privileges to view validation runs and manage validation
  tests.
- The target machine is under platform control and is not allocated to a tenant.
- Required validation images, tools, and external configs are available for the
  selected tests.

## How Machine Validation Fits Into NICo

Machine Validation runs while a machine is under platform control and before it
is allocated to a tenant. Typical entry points include:

- Initial discovery, before a newly discovered machine reaches `Ready`.
- Cleanup or release workflows, before a returned machine is made available
  again.
- On-demand validation, when an administrator explicitly starts validation for a
  machine that needs additional checks.

Machine Validation complements SKU validation. SKU validation checks that the
machine inventory matches the expected hardware model. Machine Validation runs
tests on the machine to prove that the hardware and relevant host-side software
paths behave correctly.

## Framework Concepts

| Concept | Description |
| --- | --- |
| Validation run | One execution of Machine Validation for a machine. A run contains the selected tests and their results. |
| Test definition | The stored definition of a validation test, including command, arguments, image, contexts, supported platforms, timeout, tags, and version. |
| Context | The lifecycle situation in which a test is eligible to run. Common contexts are `Discovery`, `Cleanup`, and `OnDemand`. |
| Platform mapping | The list of machine platforms on which a test is supported. Scout uses the discovered machine platform to select compatible tests. |
| Enabled flag | Controls whether the test is eligible for selection. Disabled tests are not selected for normal validation. |
| Verified flag | Indicates that an administrator has validated the test itself. Normal lifecycle runs skip unverified tests. |
| Tags | Optional selectors that allow administrators to group tests and run targeted suites. |
| External config | A named configuration file, such as registry credentials, that can be referenced by a test without embedding secrets in the test command. |
| Result | The recorded output for one test execution, including status, timing, exit code, and captured output. |

## Test Selection

When a validation run starts, NICo and Scout select tests using the following
criteria:

1. The Machine Validation feature must be enabled for the site.
2. The test must be enabled, unless the site configuration explicitly overrides
   the catalog selection mode.
3. The test must be verified for normal lifecycle runs.
4. The test context must match the run context, such as `Discovery`, `Cleanup`,
   or `OnDemand`.
5. The test must support the machine platform.
6. If tags are supplied, the test must match the requested tags.
7. If an allow list is supplied, the test must be included in the allow list.

On-demand validation can intentionally include unverified tests by using the
current CLI flag `--run-unverfied-tests`. The spelling of `unverfied` is part of
the current CLI interface and must be used exactly as shown.

## Built-In Validation Coverage

The exact test IDs, versions, enabled state, and supported platforms are
deployment and release specific. Use `nico-admin-cli machine-validation tests
show` as the source of truth for the running site.

The built-in catalog commonly includes the following test groups:

| Area | Common tests | What they validate |
| --- | --- | --- |
| GPU health | `CudaSample`, `DcgmFullShort`, `DcgmFullLong` | CUDA execution, DCGM diagnostics, and basic GPU health. |
| GPU performance | `Nvbandwidth`, `RaytracingVk` | GPU memory bandwidth and graphics or compute paths used by supported platforms. |
| CPU | `CPUTestShort`, `CPUTestLong`, `CpuBenchmarkingFp`, `CpuBenchmarkingInt` | CPU stress and benchmark coverage for short and long validation windows. |
| Memory | `MemoryTestShort`, `MemoryTestLong`, `MmMemBandwidth`, `MmMemLatency`, `MmMemPeakBandwidth`, `MqStresserShort`, `MqStresserLong` | Memory stress, latency, bandwidth, and queue pressure. |
| Storage | `FioFile`, `FioPath`, `FioSSD` | File, path, and device-level I/O validation with fio-based tests. |
| Operational extensions | `DefaultTestCase`, runbook-style tests | Site or release-specific checks used to extend the validation workflow. |

Built-in tests that are delivered through NICo migrations are normally
read-only. Direct creation and update of legacy test definitions are currently
disabled while those mutation paths are hardened. Site-provided container
plugins use the separate API-managed definition path described below.

## Site Configuration

Machine Validation is controlled by the site configuration. A minimal
configuration enables the feature:

```toml
[machine_validation_config]
enabled = true
```

A site can also control the catalog selection behavior:

```toml
[machine_validation_config]
enabled = true
test_selection_mode = "Default"
run_interval = "60s"
stale_run_timeout = "24h"
tests = [
  { id = "CudaSample", enable = true },
]
# Required before a plugin image from this registry can be registered.
approved_plugin_registries = ["nvcr.io"]
allow_privileged_plugins = false
allow_full_host_plugins = false
```

| Setting | Description |
| --- | --- |
| `enabled` | Enables or disables Machine Validation for the site. |
| `test_selection_mode` | Controls how configured tests are selected. `Default` uses the catalog and per-test settings, `EnableAll` enables all configured tests, and `DisableAll` disables all configured tests. |
| `run_interval` | Controls how often the controller processes pending validation work. |
| `stale_run_timeout` | Grace period before an active validation run is considered stale. The default is `24h`; configured values below `90s` are raised to `90s` so healthy runs are not failed between Scout heartbeats. |
| `tests` | Optional per-test overrides. Use the test identifiers reported by `tests show` for the running site. |
| `approved_plugin_registries` | Registries permitted for plugin images. The default is empty, which denies new plugin registrations. Use explicit registry hostnames, for example `nvcr.io`; this does not affect legacy tests. |
| `allow_privileged_plugins` | Permits plugin registration and execution with privileged container settings. Default: `false`. |
| `allow_full_host_plugins` | Permits registration and execution of privileged plugins with the writable `/host` mount. Default: `false`. |

### Private Registry Credentials for Plugins

The registry allow-list controls **where** a plugin image may come from. Registry
credentials control **how Scout authenticates** when that allowed registry is
private. They are separate from the plugin definition and site configuration.

To configure a private registry for a plugin:

1. Add the registry hostname to `approved_plugin_registries` and apply the site
   configuration rollout.
2. Store a username and registry token with the existing credential command.
   The hostname must exactly match the registry portion of the plugin image
   reference. Use the hidden prompt and standard-input form below so the token
   is not placed in command arguments or shell history.

   ```sh
   read -r -s -p 'Registry token: ' registry_token; printf '\n'
   printf '%s' "$registry_token" | nico-admin-cli credential registry set \
     --registry registry.example.com \
     --username registry-user \
     --password-stdin
   unset registry_token
   ```

3. Create the plugin definition with a digest-pinned image from that registry.
4. When Scout pulls the image, it retrieves the credential for that hostname
   from NICo's credential manager, passes it to `nerdctl login` through standard
   input, and then pulls the image.

Do not put credentials, tokens, Docker configuration, or secrets in the plugin
definition, `parameters_json`, `input.json`, or the site configuration file. A
registry without a stored credential is treated as public, and Scout attempts
the pull without login. Use a short-lived token where the registry supports it
and avoid placing a real token in shell history or source-controlled files.

## External Configuration for Legacy Tests

Some legacy validation tests require external configuration. Store those inputs
as named external configs instead of embedding secrets in test definitions.

Plugin images use the per-registry credential workflow above. The
`container_auth` file below remains supported for legacy container tests.

For example, to add or update the container authentication file:

```sh
nico-admin-cli machine-validation external-config add-update \
  --name container_auth \
  --description "Container registry credentials for machine validation" \
  --file-name /tmp/config.json
```

To view or remove external configuration:

```sh
nico-admin-cli machine-validation external-config show --name container_auth
nico-admin-cli machine-validation external-config remove --name container_auth
```

## Managing the Test Catalog

### List Tests

Use the test catalog to see the tests available in the site:

```sh
nico-admin-cli machine-validation tests show
```

Show a specific test:

```sh
nico-admin-cli machine-validation tests show --test-id <test_id>
```

Filter by platform or context:

```sh
nico-admin-cli machine-validation tests show --platforms <platform>
nico-admin-cli machine-validation tests show --contexts Discovery
```

Show unverified tests:

```sh
nico-admin-cli machine-validation tests show --show-un-verfied
```

The current CLI flag is spelled `--show-un-verfied`; use the spelling shown
above.

### Enable or Disable Tests

Enable a test when it should be eligible for selection:

```sh
nico-admin-cli machine-validation tests enable \
  --test-id <test_id> \
  --version <version>
```

Disable a test when it should not be selected:

```sh
nico-admin-cli machine-validation tests disable \
  --test-id <test_id> \
  --version <version>
```

Use the `test_id` and `version` values returned by `tests show`.

### Verify Tests

Verify a test after it has been proven safe and correct for the target site:

```sh
nico-admin-cli machine-validation tests verify \
  --test-id <test_id> \
  --version <version>
```

Verification is a promotion step. A newly added test should be run on demand
first, reviewed, and then marked verified before it is allowed into normal
lifecycle validation.

## Site-Provided Container Plugins

Machine Validation can run a site-provided, digest-pinned OCI container. Site
admins create and manage plugins with `nico-admin-cli machine-validation plugins`.

The site admin supplies the image, entrypoint, and non-secret JSON parameters.
The image registry must be listed in
`machine_validation_config.approved_plugin_registries`; configure private
registry credentials as described above. Machine Validation creates plugin tests
disabled and unverified, and the existing verify and enable operations control
when they can be selected.

Scout runs the container sequentially with networking disabled, a non-root user,
no Linux capabilities, and `no-new-privileges`. It supplies standard input and
result files at `/opt/nico/mv/input/input.json` and
`/opt/nico/mv/output/result.json`. Image acquisition and execution share the
configured timeout, which must be between one second and 24 hours. A pull
failure, timeout, invalid or missing result, or non-zero container exit is a
framework failure. Before Scout starts a pending plugin, the API rechecks the
current site policy and, for full-host plugins, the approval of that revision.

`--privileged` changes the runtime to a privileged container. Adding
`--host-access-full` also mounts the writable host root at `/host`; both options
require matching site policy, and full-host access requires separate approval
of the exact verified revision.

The legacy `nico-admin-cli machine-validation tests add` command cannot create a
plugin. Use the plugin-aware commands instead. For the normal unprivileged
container profile:

```sh
nico-admin-cli machine-validation plugins create \
  --name gpu-health \
  --image registry.example.com/example-ai-west-prod/gpu-health@sha256:REPLACE_WITH_DIGEST \
  --entrypoint /plugin/entrypoint \
  --context Discovery \
  --platform HGX-B200 \
  --parameters '{"expectedGpuCount":8}'
```

For a privileged container with writable host access:

```sh
nico-admin-cli machine-validation plugins create \
  --name host-gpu-health \
  --image registry.example.com/example-ai-west-prod/host-gpu-health@sha256:REPLACE_WITH_DIGEST \
  --entrypoint /plugin/entrypoint \
  --context Discovery \
  --platform HGX-B200 \
  --parameters '{"expectedGpuCount":8}' \
  --privileged \
  --host-access-full
```

The command prints the immutable test ID and version needed for the following
steps, for example `Created plugin revision: forge_host_gpu_health 1.0.0`.

The API creates the revision disabled and unverified. Verify it, approve full
host access when requested, then enable it using the same test ID and version:

```sh
nico-admin-cli machine-validation plugins verify --test-id forge_host_gpu_health --version 1.0.0
nico-admin-cli machine-validation plugins approve-full-host --test-id forge_host_gpu_health --version 1.0.0
nico-admin-cli machine-validation plugins enable --test-id forge_host_gpu_health --version 1.0.0
```

Only one plugin revision for a test ID can be enabled at a time. Enabling a new
revision disables the previously enabled plugin revision for that test ID.

Privileged and full-host execution require the matching site settings above.
Device capabilities, site-managed input files, resource overrides, and parallel
execution are not supported by the current implementation.

## Legacy Test Definitions

The `nico-admin-cli machine-validation tests add` and update commands currently
send legacy test definitions and are rejected while legacy mutation paths are
hardened. Existing built-in tests can still be listed, verified, enabled, and
disabled through their established operations. New site-specific container
checks use the plugin-aware CLI workflow described above.

## Execution Models

Machine Validation tests can be implemented as host commands or container-based
commands.

| Model | When to use it | Common fields |
| --- | --- | --- |
| Host command | Use when the test tool is already present in the discovery environment or host filesystem. | `--command`, `--args`, `--timeout` |
| Container command | Use when the test needs a packaged dependency set or must run from a validation image. | `--img-name`, `--container-arg`, `--external-config-file` |
| Host filesystem execution | Use when a containerized test must execute against the host filesystem. | `--execute-in-host true` |

Tests can also declare output file locations with `--extra-output-file` and
`--extra-err-file` when a command writes important diagnostics outside stdout or
stderr. Keep those outputs concise. Scout records command output for result
review, but Machine Validation is not a replacement for long-term log storage.

## Run Tracking and Stale Recovery

Machine Validation tracks active work at two levels:

- Run items show which tests were selected for a validation run.
- Attempts show each execution of a selected test, including state, timing, exit
  code, and output summaries.

Scout sends heartbeats while tests are running. The controller uses the latest
heartbeat to find work that stopped making progress. If a record has no
heartbeat, the controller falls back to the run start time, expected duration,
and `stale_run_timeout`.

When stale work is found, the controller fails the validation and records the
normal failed-validation health alert. This keeps a machine from staying stuck
in an active validation state after Scout stops reporting.

Operators can monitor this behavior with:

| Metric | Meaning |
| --- | --- |
| `carbide_machine_validation_oldest_active_age_seconds` | Age of the oldest active validation run. |
| `carbide_machine_validation_stale_runs_count` | Number of active validation runs considered stale in the latest reconciliation pass. |

## Database Changes and Upgrades

Recent Machine Validation reliability work introduced database schema changes
for execution tracking and stale recovery:

| Area | Database change |
| --- | --- |
| Execution tracking | Adds `machine_validation_run_items` and `machine_validation_attempts` tables. |
| Heartbeat recovery | Adds `machine_validation.last_heartbeat_at` and heartbeat indexes for active validations, run items, and attempts. |

Deployments must apply the normal API database migrations before relying on the
new run tracking and stale recovery behavior. No manual data backfill is
required for existing validation rows. Older rows without heartbeat timestamps
continue to use the duration-based stale detection fallback.

## Updating Site-Specific Tests

Use `tests update` to change a mutable test definition:

```sh
nico-admin-cli machine-validation tests update \
  --test-id <test_id> \
  --version <version> \
  --timeout 3600 \
  --description "Updated validation timeout"
```

Use updates for site-specific tests only. Built-in tests may be read-only,
depending on how they were delivered to the site.

## Extension Design Guidelines

Use the following guidelines when designing a new validation test:

| Area | Recommendation |
| --- | --- |
| Naming | Use a stable, descriptive PascalCase name such as `GpuFabricSmoke` or `StorageFioPath`. Avoid embedding temporary incident names or one-off ticket IDs. |
| Scope | Keep each test focused on one hardware or software concern. Prefer separate tests over a large script that hides multiple failure modes. |
| Contexts | Use `Discovery` for pre-allocation checks, `Cleanup` for checks after release, and `OnDemand` for operator-triggered validation or test qualification. |
| Platform support | Map tests only to platforms where the command, devices, firmware, and drivers are expected to exist. |
| Verification | Treat verification as a release gate for the test definition. Do not verify a test until it has passed on representative hardware. |
| Timeouts | Set an explicit timeout that matches the expected runtime. Long tests should be intentional and documented. |
| Secrets | Use external config files for credentials and sensitive inputs. Do not pass secrets directly in command arguments. |
| Output | Write concise stdout and stderr that explains what failed. Use extra output files only for diagnostics that cannot be emitted directly. |
| Pre-conditions | Use pre-conditions to skip tests that do not apply to a machine rather than failing unrelated platforms. |
| Tags | Add tags when operators need to run a targeted suite such as `gpu-smoke`, `storage`, or `burn-in`. |

## Running On-Demand Validation

Start validation for a specific machine:

```sh
nico-admin-cli machine-validation on-demand start --machine <machine_id>
```

Run only selected contexts:

```sh
nico-admin-cli machine-validation on-demand start \
  --machine <machine_id> \
  --contexts OnDemand
```

Run selected tests:

```sh
nico-admin-cli machine-validation on-demand start \
  --machine <machine_id> \
  --allowed-tests <test_id_1> \
  --allowed-tests <test_id_2>
```

Run a tagged suite:

```sh
nico-admin-cli machine-validation on-demand start \
  --machine <machine_id> \
  --tags gpu-smoke
```

Run unverified tests during qualification:

```sh
nico-admin-cli machine-validation on-demand start \
  --machine <machine_id> \
  --allowed-tests <test_id> \
  --run-unverfied-tests
```

The current CLI flag is spelled `--run-unverfied-tests`; use the spelling shown
above.

## Viewing Runs and Results

Show validation runs:

```sh
nico-admin-cli machine-validation runs show
```

Show runs for one machine:

```sh
nico-admin-cli machine-validation runs show --machine <machine_id>
```

Include historical runs:

```sh
nico-admin-cli machine-validation runs show --machine <machine_id> --history
```

Show validation results for a machine:

```sh
nico-admin-cli machine-validation results show --machine <machine_id>
```

Show results for a specific validation run:

```sh
nico-admin-cli machine-validation results show --validation-id <validation_id>
```

Show a specific test result from a run:

```sh
nico-admin-cli machine-validation results show \
  --validation-id <validation_id> \
  --test-name <test_name>
```

## Interpreting Results

Each test result records the command execution outcome, timing, exit code, and
captured output. A non-zero exit code indicates failure unless the test command
implements a documented skip or pre-condition behavior.

Scout captures stdout and stderr after the command exits. Captured output is
bounded, so tests should print useful progress and final diagnostic information
without producing unbounded logs. Live log streaming should not be assumed unless
the deployment has additional logging integration.

When a validation run fails, review:

- Whether the selected test is supported on the machine platform.
- Whether the test was verified and enabled intentionally.
- The command exit code and captured output.
- Any referenced external configuration.
- Whether the test timed out.
- Whether a pre-condition skipped or changed the intended execution path.

## Operational Guidance

Use Machine Validation as a controlled pre-allocation gate. Do not enable or
verify a new test in the standard lifecycle until it has been qualified with
on-demand runs on representative hardware.

For production sites:

- Keep the built-in catalog enabled according to the site's hardware and release
  policy.
- Use short tests for routine lifecycle validation and long tests for burn-in,
  repair validation, or targeted on-demand workflows.
- Prefer tags and allow lists for targeted validation instead of modifying the
  global catalog for temporary needs.
- Keep site-specific test names stable across releases so operators can compare
  historical results.
- Store registry credentials and sensitive test inputs as external config.
- Review the output format of extension tests so failures are actionable from
  the CLI and admin UI.

## Troubleshooting

| Symptom | Common causes | Next step |
| --- | --- | --- |
| No tests are selected | Feature disabled, tests disabled, tests unverified, context mismatch, platform mismatch, tags do not match, or allow list excludes all tests. | Run `tests show` with the relevant platform and context, and confirm enabled and verified state. |
| A new test does not run in lifecycle validation | The test is unverified or disabled. | Run the test on demand with `--run-unverfied-tests`, review the result, then enable and verify it. |
| After modifying or updating a test, I no longer see the test | The updated test may have become unverified, or the current `tests show` filter may exclude its new context, platform, or version. | Run `tests show --show-un-verfied --test-id <test_id>`, review the updated definition, then re-enable or re-verify the test as needed. |
| A test fails only on one platform | Platform mapping is too broad, platform-specific dependency is missing, or the test command assumes hardware that is not present. | Restrict `supported-platforms` or add a pre-condition. |
| A legacy container test cannot start | Image name, registry credentials, or external config are incorrect. | Confirm the image exists and refresh `container_auth`. |
| A test times out | Timeout is too short, the test is hung, or the machine is unhealthy. | Review captured output and set a deliberate timeout for the test's expected runtime. |
| Result output is incomplete | The test wrote too much output or logs outside captured stdout and stderr. | Keep CLI output concise and write important diagnostics before exit. |
