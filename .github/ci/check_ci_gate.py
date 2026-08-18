#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Keep every CI job accounted for by its final required check.

GitHub Actions makes `needs` a static list: it waits for the jobs named there,
but adding a new top-level job does not update a final gate or warn us that the
job was omitted. The `inventory` command reads the small part of the workflow
used by the selected gate policy and requires every job to be gated or
explicitly exempted. It also protects the gate's `if: always()` condition so a
failed dependency cannot skip the required check.

The `results` command evaluates `${{ toJson(needs) }}` from `NEEDS_JSON`.
`success` and `skipped` pass because conditional jobs legitimately omit work.
Every gated top-level job is listed independently, so an upstream failure stays
visible even when it makes downstream jobs skip. Any other or malformed result
fails closed.
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


# We only need the root job IDs plus the selected gate's `if` and `needs`
# fields. Keep this grammar deliberately narrow and reject unfamiliar
# formatting: silently skipping a line could let a job escape the required
# check.
JOB_KEY = re.compile(r"^  (?P<job>[A-Za-z_][A-Za-z0-9_-]*):(?:\s*#.*)?$")
NEEDS_ITEM = re.compile(r"^      - (?P<job>[A-Za-z_][A-Za-z0-9_-]*)(?:\s*#.*)?$")
GATE_IF = re.compile(r"^    if:\s*(?P<condition>.*)$")
PASSING_RESULTS = frozenset({"success", "skipped"})


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
    """Protect the gate condition and read its complete block-style `needs` list."""

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


def result_errors(needs_context: Mapping[str, object]) -> list[str]:
    """Return an error for every non-passing result in `needs_context`.

    The accepted status values are `success` and `skipped`. An empty context,
    malformed job entry, or any other status fails closed.
    """

    if not needs_context:
        return ["the gate received no job results"]

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
        elif result not in PASSING_RESULTS:
            errors.append(f"`{job}` returned unsupported result {result!r}")

    return errors


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


def _check_results() -> int:
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

    errors = result_errors(needs_context)
    if errors:
        _print_annotations(errors)
        return 1

    print("All required jobs succeeded or were intentionally skipped.")
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
    commands.add_parser("results", help="evaluate the job results in `NEEDS_JSON`")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    """Run the requested gate check."""

    args = _parse_args(argv)
    if args.command == "inventory":
        return _check_inventory(args.workflow, POLICIES[args.policy])
    return _check_results()


if __name__ == "__main__":
    sys.exit(main())
