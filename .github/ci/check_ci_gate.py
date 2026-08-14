#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Keep every CI job accounted for by its final required check.

`inventory` checks the static wiring. The workflow's root `jobs` block is the
complete job inventory, and the final gate's `needs` list says which jobs feed
that required check. Every remaining job needs a reviewed exemption.

`results` checks one run. A successful job always passes. A skipped job passes
only when the workflow's recorded decisions and run context explain that skip.
We consume those existing facts instead of calculating path or release policy
again; a second answer could drift and approve the wrong skip.

Both checks fail closed. A job omitted from the gate, a missing decision, or an
applicable job that was skipped makes the final required check fail.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

# This is intentionally not a general YAML parser. We only accept the workflow
# layout needed to find root jobs, `gate_job.if`, and `gate_job.needs`. If that
# layout changes, failing here is safer than silently missing a job and letting
# the required check approve it.
JOB_KEY = re.compile(r"^  (?P<job>[A-Za-z_][A-Za-z0-9_-]*):(?:\s*#.*)?$")
NEEDS_ITEM = re.compile(r"^      - (?P<job>[A-Za-z_][A-Za-z0-9_-]*)(?:\s*#.*)?$")
GATE_IF = re.compile(r"^    if:\s*(?P<condition>.*)$")
PR_REF_PREFIX = "refs/heads/pull-request/"
CANONICAL_REPOSITORY = "NVIDIA/infra-controller"


# Workflow inventory


class WorkflowFormatError(ValueError):
    """The workflow does not use the job layout this checker can verify."""


@dataclass(frozen=True)
class GatePolicy:
    """Name one final gate and every job intentionally outside it.

    `display_name` identifies the lane in human-readable output. `gate_job`
    is the top-level job that branch protection requires. Each exemption maps
    a job ID to the reviewed reason it cannot or should not gate that lane.
    """

    display_name: str
    gate_job: str
    exemptions: Mapping[str, str]


CORE_POLICY = GatePolicy(
    display_name="Core CI",
    gate_job="core-ci-pass",
    exemptions={
        "build-summary": (
            "This reporting-only job writes the Actions summary and does not "
            "validate build output."
        ),
        "notify-build-status": (
            "This administrative job reports the completed build to Slack on "
            "protected refs."
        ),
        "core-ci-pass": "A job cannot depend on itself.",
    },
)

REST_POLICY = GatePolicy(
    display_name="REST CI",
    gate_job="rest-ci-pass",
    exemptions={"rest-ci-pass": "A job cannot depend on itself."},
)

POLICIES: Mapping[str, GatePolicy] = {
    "core": CORE_POLICY,
    "rest": REST_POLICY,
}


@dataclass(frozen=True)
class WorkflowInventory:
    """The gate policy extracted from one workflow.

    `jobs` keeps every top-level job ID in declaration order. `gate_needs`
    keeps the gate's direct dependencies in their written order, including
    duplicates, so the inventory check can report invalid entries instead of
    normalizing them.
    """

    jobs: tuple[str, ...]
    gate_needs: tuple[str, ...]


def _leading_spaces(line: str) -> int:
    """Return the number of literal spaces at the start of `line`."""

    return len(line) - len(line.lstrip(" "))


def _find_jobs(lines: list[str]) -> tuple[list[str], dict[str, int]]:
    """Return every top-level job and its first line in the workflow."""

    jobs_blocks = [index for index, line in enumerate(lines) if line == "jobs:"]
    if len(jobs_blocks) != 1:
        raise WorkflowFormatError(
            f"expected one root `jobs` block, found {len(jobs_blocks)}"
        )

    jobs: list[str] = []
    positions: dict[str, int] = {}
    for index in range(jobs_blocks[0] + 1, len(lines)):
        line = lines[index]
        if not line.strip() or line.lstrip().startswith("#"):
            continue

        indentation = _leading_spaces(line)
        if indentation == 0:
            break
        if indentation != 2:
            continue

        match = JOB_KEY.fullmatch(line)
        if match is None:
            raise WorkflowFormatError(
                f"line {index + 1} is not a supported top-level job declaration: {line!r}"
            )

        job = match.group("job")
        if job in positions:
            raise WorkflowFormatError(f"top-level job `{job}` is declared more than once")
        jobs.append(job)
        positions[job] = index

    if not jobs:
        raise WorkflowFormatError("the root `jobs` block contains no top-level jobs")

    return jobs, positions


def _parse_gate(
    lines: list[str],
    jobs: list[str],
    positions: Mapping[str, int],
    gate_job: str,
) -> list[str]:
    """Read the final gate and require the form this checker can protect.

    `if: always()` is part of the contract. Without it, an upstream failure
    skips the aggregate before it can report which dependency failed.
    """

    gate_start = positions.get(gate_job)
    if gate_start is None:
        raise WorkflowFormatError(f"the workflow does not define `{gate_job}`")

    gate_index = jobs.index(gate_job)
    gate_end = (
        positions[jobs[gate_index + 1]] if gate_index + 1 < len(jobs) else len(lines)
    )

    gate_conditions = [
        match.group("condition")
        for index in range(gate_start + 1, gate_end)
        if (match := GATE_IF.fullmatch(lines[index])) is not None
    ]
    if len(gate_conditions) != 1:
        raise WorkflowFormatError(
            f"expected one gate-level `if` on `{gate_job}`, "
            f"found {len(gate_conditions)}"
        )
    if gate_conditions[0] != "always()":
        raise WorkflowFormatError(
            f"`{gate_job}.if` must be `always()`, found {gate_conditions[0]!r}"
        )

    needs_lines = [
        index
        for index in range(gate_start + 1, gate_end)
        if lines[index] == "    needs:"
    ]
    if len(needs_lines) != 1:
        raise WorkflowFormatError(
            f"expected one block-style `needs` list on `{gate_job}`, "
            f"found {len(needs_lines)}"
        )

    needs: list[str] = []
    for index in range(needs_lines[0] + 1, gate_end):
        line = lines[index]
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indentation = _leading_spaces(line)
        if indentation == 4 and line.startswith("    - "):
            raise WorkflowFormatError(
                f"line {index + 1} must indent `{gate_job}.needs` items "
                f"by six spaces: {line!r}"
            )
        if indentation <= 4:
            break

        match = NEEDS_ITEM.fullmatch(line)
        if match is None:
            raise WorkflowFormatError(
                f"line {index + 1} is not a supported `{gate_job}.needs` item: "
                f"{line!r}"
            )
        needs.append(match.group("job"))

    if not needs:
        raise WorkflowFormatError(f"`{gate_job}.needs` contains no jobs")

    return needs


def parse_workflow(workflow_text: str, gate_job: str) -> WorkflowInventory:
    """Parse the small part of a GitHub Actions workflow the gate relies on."""

    lines = workflow_text.splitlines()
    jobs, positions = _find_jobs(lines)
    gate_needs = _parse_gate(lines, jobs, positions, gate_job)
    return WorkflowInventory(jobs=tuple(jobs), gate_needs=tuple(gate_needs))


def _inventory_errors(
    inventory: WorkflowInventory, exemptions: Mapping[str, str]
) -> list[str]:
    """Explain invalid classifications in an already parsed inventory."""

    errors: list[str] = []
    jobs = set(inventory.jobs)
    gated_jobs = set(inventory.gate_needs)
    exempt_jobs = set(exemptions)

    duplicate_needs = sorted(
        job for job, count in Counter(inventory.gate_needs).items() if count > 1
    )
    if duplicate_needs:
        errors.append(
            "gate dependencies are listed more than once: " + ", ".join(duplicate_needs)
        )

    unknown_needs = sorted(gated_jobs - jobs)
    if unknown_needs:
        errors.append(
            "gate dependencies are not top-level jobs: " + ", ".join(unknown_needs)
        )

    unknown_exemptions = sorted(exempt_jobs - jobs)
    if unknown_exemptions:
        errors.append(
            "exemptions are not top-level jobs: " + ", ".join(unknown_exemptions)
        )

    empty_reasons = sorted(job for job, reason in exemptions.items() if not reason.strip())
    if empty_reasons:
        errors.append("exemptions need a reason: " + ", ".join(empty_reasons))

    duplicate_classifications = sorted(gated_jobs & exempt_jobs)
    if duplicate_classifications:
        errors.append(
            "jobs cannot be both gated and exempt: "
            + ", ".join(duplicate_classifications)
        )

    missing_jobs = sorted(jobs - gated_jobs - exempt_jobs)
    if missing_jobs:
        errors.append("top-level jobs are not gated or exempt: " + ", ".join(missing_jobs))

    return errors


def inventory_errors(workflow_text: str, policy: GatePolicy) -> list[str]:
    """Parse the workflow and explain every invalid gate classification."""

    try:
        inventory = parse_workflow(workflow_text, policy.gate_job)
    except WorkflowFormatError as error:
        return [str(error)]

    return _inventory_errors(inventory, policy.exemptions)


# Recorded run decisions


class ResultContextError(ValueError):
    """The gate did not receive the decisions needed to classify its jobs."""


# Most Core jobs run whenever the Core lane is selected. This is the small set
# whose own `if` expressions narrow that decision with a `prepare` output.
# Keeping only the exceptions here makes a newly gated job fail on an
# unexplained skip without requiring another full copy of the workflow.
CORE_PREPARE_OUTPUTS: Mapping[str, frozenset[str]] = {
    "build_container_x86_64_run": frozenset({"build-container-x86_64"}),
    "build_container_aarch64_run": frozenset({"build-container-aarch64"}),
    "runtime_container_x86_64_run": frozenset({"build-runtime-container-x86_64"}),
    "runtime_container_aarch64_run": frozenset({"build-runtime-container-aarch64"}),
    "build_artifacts_container_x86_64_run": frozenset(
        {"build-artifacts-container-x86_64"}
    ),
    "build_artifacts_container_aarch64_run": frozenset(
        {"build-artifacts-container-aarch64"}
    ),
    "publish_images": frozenset(
        {
            "merge-manifests-nvmetal-carbide",
            "merge-manifests-forge-cli",
            "merge-manifests-machine-validation",
            "build-push-helm-chart",
            "build-push-helm-prereqs-chart",
            "build-push-bluefield-helm-charts",
            "promote-to-be-scanned-image",
        }
    ),
    "source_files_changed": frozenset(
        {"build-machine-a-tron", "build-mat-k8s-controller", "lint-police"}
    ),
    "proto_files_changed": frozenset({"proto-police"}),
    "core_rpc_proto_files_changed": frozenset({"check-rest-core-proto-sync"}),
}

CORE_PR_ONLY_JOBS = frozenset({"lint-police", "migration-police", "proto-police"})
CORE_CANONICAL_JOB = "promote-to-be-scanned-image"


def _job_outputs(
    needs_context: Mapping[str, object], job: str
) -> Mapping[str, object]:
    """Return one job's output map or reject malformed Actions context."""

    details = needs_context.get(job)
    outputs = details.get("outputs") if isinstance(details, Mapping) else None
    if not isinstance(outputs, Mapping):
        raise ResultContextError(f"`{job}` did not provide a job outputs object")
    return outputs


def _read_boolean_output(
    outputs: Mapping[str, object], job: str, name: str
) -> bool:
    """Read one exact GitHub string boolean."""

    value = outputs.get(name)
    if not isinstance(value, str) or value not in {"true", "false"}:
        raise ResultContextError(
            f"`{job}` output `{name}` must be 'true' or 'false', found {value!r}"
        )
    return value == "true"


def _is_pull_request_run(environment: Mapping[str, str]) -> bool:
    """Classify the PR-mirror ref namespace used by the job conditions."""

    ref = environment.get("GITHUB_REF")
    if not ref:
        raise ResultContextError("`GITHUB_REF` is not set")
    return ref.startswith(PR_REF_PREFIX)


def _lane_selected(needs_context: Mapping[str, object], output_name: str) -> bool:
    """Read the decision made by the workflow's unconditional `changes` job."""

    changes = needs_context.get("changes")
    if not isinstance(changes, Mapping):
        raise ResultContextError("`changes` did not provide a job result object")
    if changes.get("result") != "success":
        raise ResultContextError("`changes` was unexpectedly skipped")
    return _read_boolean_output(
        _job_outputs(needs_context, "changes"), "changes", output_name
    )


def _core_allowed_skips(
    needs_context: Mapping[str, object], environment: Mapping[str, str]
) -> set[str]:
    """Return Core jobs whose recorded conditions explain a skip."""

    lane_selected = _lane_selected(needs_context, "run_core_ci")
    pull_request = _is_pull_request_run(environment)
    if not lane_selected:
        if not pull_request:
            raise ResultContextError(
                "Core CI must be selected for a non-pull-request run"
            )
        # A REST-only PR skips the entire Core lane. `changes` still records
        # that decision, while migration policy remains PR-wide.
        return set(needs_context) - {"changes", "migration-police"}

    prepare = needs_context.get("prepare")
    if not isinstance(prepare, Mapping) or prepare.get("result") != "success":
        raise ResultContextError("`prepare` was unexpectedly skipped")
    prepare_outputs = _job_outputs(needs_context, "prepare")

    allowed: set[str] = set()
    # These are the same booleans the jobs consumed. Re-running path filters or
    # release logic here could give the gate a different answer than the run.
    for output_name, jobs in CORE_PREPARE_OUTPUTS.items():
        if not _read_boolean_output(prepare_outputs, "prepare", output_name):
            allowed.update(jobs)

    if not pull_request:
        allowed.update(CORE_PR_ONLY_JOBS)

    repository = environment.get("GITHUB_REPOSITORY")
    if not repository:
        raise ResultContextError("`GITHUB_REPOSITORY` is not set")
    if repository != CANONICAL_REPOSITORY:
        allowed.add(CORE_CANONICAL_JOB)
    return allowed


def _rest_allowed_skips(
    needs_context: Mapping[str, object], environment: Mapping[str, str]
) -> set[str]:
    """Return REST jobs whose lane/ref conditions explain a skip."""

    lane_selected = _lane_selected(needs_context, "run_rest_ci")
    pull_request = _is_pull_request_run(environment)
    if not lane_selected:
        if not pull_request:
            raise ResultContextError(
                "REST CI must be selected for a non-pull-request run"
            )
        return set(needs_context) - {"changes"}

    # Both reusable build callers are direct gate dependencies, but the ref
    # selects exactly one of them for a given run.
    if pull_request:
        return {"build-and-push"}
    return {"build-and-push-pr"}


def result_errors(
    needs_context: Mapping[str, object],
    policy_name: str,
    *,
    environment: Mapping[str, str] | None = None,
) -> list[str]:
    """Reject unhealthy results and skips unexplained by the selected lane."""

    if not needs_context:
        return ["the gate received no job results"]

    results: dict[str, str] = {}
    errors: list[str] = []
    for job, details in sorted(needs_context.items()):
        if not isinstance(details, Mapping):
            errors.append(f"`{job}` did not provide a job result object")
            continue

        result = details.get("result")
        if result == "failure":
            errors.append(f"`{job}` failed")
        elif result == "cancelled":
            errors.append(f"`{job}` was cancelled")
        elif result == "success" or result == "skipped":
            results[job] = result
        else:
            errors.append(f"`{job}` returned unsupported result {result!r}")
    if errors:
        # Once a dependency is unhealthy, its downstream skips need no second
        # explanation: the aggregate is already guaranteed to fail.
        return errors

    runtime = os.environ if environment is None else environment
    try:
        if policy_name == "core":
            allowed_skips = _core_allowed_skips(needs_context, runtime)
        elif policy_name == "rest":
            allowed_skips = _rest_allowed_skips(needs_context, runtime)
        else:
            return [f"unknown gate policy {policy_name!r}"]
    except ResultContextError as error:
        return [str(error)]

    # We only police skips. A job that ran despite being optional has already
    # completed successfully, so there is no gate failure left to prevent.
    return [
        f"`{job}` was unexpectedly skipped"
        for job, result in sorted(results.items())
        if result == "skipped" and job not in allowed_skips
    ]


# Command-line entry points


def _print_annotations(errors: list[str]) -> None:
    """Write each error using GitHub Actions' workflow-command format."""

    for error in errors:
        print(f"::error::{error}")


def _check_inventory(workflow_path: Path, policy: GatePolicy) -> int:
    """Check one workflow file and report inventory errors as annotations.

    Returns zero only when the file is readable, uses the supported layout,
    protects the gate condition, and classifies every top-level job.
    """

    try:
        workflow_text = workflow_path.read_text(encoding="utf-8")
    except OSError as error:
        _print_annotations([f"could not read `{workflow_path}`: {error}"])
        return 1

    try:
        inventory = parse_workflow(workflow_text, policy.gate_job)
    except WorkflowFormatError as error:
        _print_annotations([str(error)])
        return 1

    errors = _inventory_errors(inventory, policy.exemptions)
    if errors:
        _print_annotations(errors)
        return 1

    print(
        f"{policy.display_name} gate accounts for {len(inventory.jobs)} "
        f"top-level jobs ({len(inventory.gate_needs)} gated, "
        f"{len(policy.exemptions)} exempt)."
    )
    return 0


def _check_results(policy_name: str) -> int:
    """Check `NEEDS_JSON` and report invalid job results as annotations.

    Each dependency is printed for the Actions log. Returns zero only when the
    input is valid and every dependency passes `result_errors`.
    """

    needs_json = os.environ.get("NEEDS_JSON")
    if needs_json is None:
        _print_annotations(["`NEEDS_JSON` is not set"])
        return 1

    try:
        needs_context = json.loads(needs_json)
    except json.JSONDecodeError as error:
        _print_annotations([f"`NEEDS_JSON` is not valid JSON: {error}"])
        return 1
    if not isinstance(needs_context, Mapping):
        _print_annotations(["`NEEDS_JSON` must contain a JSON object"])
        return 1

    for job, details in sorted(needs_context.items()):
        result = details.get("result") if isinstance(details, Mapping) else None
        print(f"{job}: {result}")

    errors = result_errors(needs_context, policy_name)
    if errors:
        _print_annotations(errors)
        return 1

    print(
        f"All {POLICIES[policy_name].display_name} jobs succeeded or skipped "
        "for a recorded reason."
    )
    return 0


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    """Parse the selected check and its command-specific arguments."""

    parser = argparse.ArgumentParser(
        description="Check a CI final gate's job inventory and results."
    )
    commands = parser.add_subparsers(dest="command", required=True)

    inventory = commands.add_parser(
        "inventory", help="verify that every top-level job is gated or exempt"
    )
    inventory.add_argument(
        "--policy",
        choices=tuple(POLICIES),
        required=True,
        help="select the workflow's reviewed gate policy",
    )
    inventory.add_argument("workflow", type=Path)

    results = commands.add_parser(
        "results", help="evaluate the job results in `NEEDS_JSON`"
    )
    results.add_argument(
        "--policy",
        choices=tuple(POLICIES),
        required=True,
        help="select the workflow's reviewed gate policy",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    """Run the requested gate check."""

    args = _parse_args(argv)
    if args.command == "inventory":
        return _check_inventory(args.workflow, POLICIES[args.policy])
    return _check_results(args.policy)


if __name__ == "__main__":
    sys.exit(main())
