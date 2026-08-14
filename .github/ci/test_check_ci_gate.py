#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for the shared CI final-gate inventory and result checks."""

from __future__ import annotations

import contextlib
import copy
import io
import json
import os
import tempfile
import textwrap
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

from check_ci_gate import (
    CORE_CANONICAL_JOB,
    CORE_POLICY,
    CORE_PREPARE_OUTPUTS,
    CORE_PR_ONLY_JOBS,
    JOB_KEY,
    POLICIES,
    REST_POLICY,
    inventory_errors,
    main,
    parse_workflow,
    result_errors,
)


CI_DIR = Path(__file__).resolve().parent
ROOT = CI_DIR.parents[1]
WORKFLOWS = {
    "core": ROOT / ".github/workflows/ci.yaml",
    "rest": ROOT / ".github/workflows/rest-ci.yml",
}

COMPLETE_WORKFLOW = textwrap.dedent(
    """\
    name: Core fixture

    jobs:
      changes:
        runs-on: ubuntu-latest
      build:
        runs-on: ubuntu-latest
      build-summary:
        runs-on: ubuntu-latest
      notify-build-status:
        runs-on: ubuntu-latest
      core-ci-pass:
        runs-on: ubuntu-latest
        if: always()
        needs:
          - changes
          - build
        steps:
          - run: true
    """
)

REST_WORKFLOW = textwrap.dedent(
    """\
    name: REST fixture

    jobs:
      changes:
        runs-on: ubuntu-latest
      prepare:
        runs-on: ubuntu-latest
      lint-and-test:
        runs-on: ubuntu-latest
      build-binaries:
        runs-on: ubuntu-latest
      security-secret-scan:
        runs-on: ubuntu-latest
      build-and-push:
        runs-on: ubuntu-latest
      build-and-push-pr:
        runs-on: ubuntu-latest
      helm:
        runs-on: ubuntu-latest
      rest-ci-pass:
        runs-on: ubuntu-latest
        if: always()
        needs:
          - changes
          - prepare
          - lint-and-test
          - build-binaries
          - security-secret-scan
          - build-and-push
          - build-and-push-pr
          - helm
        steps:
          - run: true
    """
)


def _workflow(policy_name: str) -> str:
    """Read one checked-in workflow."""

    return WORKFLOWS[policy_name].read_text(encoding="utf-8")


def _gate_jobs(policy_name: str) -> tuple[str, ...]:
    """Read the final gate's live dependencies instead of copying its list."""

    policy = POLICIES[policy_name]
    inventory = parse_workflow(_workflow(policy_name), policy.gate_job)
    return inventory.gate_needs


def _job_body(policy_name: str, job: str) -> str:
    """Return one live top-level job body for a narrow wiring assertion."""

    lines = _workflow(policy_name).splitlines()
    start = next(
        (
            index
            for index, line in enumerate(lines)
            if (match := JOB_KEY.fullmatch(line)) is not None
            and match.group("job") == job
        ),
        None,
    )
    if start is None:
        raise AssertionError(
            f"{policy_name} workflow does not declare job {job!r}"
        )
    body: list[str] = []
    for line in lines[start + 1 :]:
        if line.strip() and not line.startswith("    "):
            break
        body.append(line)
    return "\n".join(body)


def _environment(*, pull_request: bool, canonical: bool = True) -> dict[str, str]:
    """Build only the Actions facts used by the lane selectors."""

    return {
        "GITHUB_REF": (
            "refs/heads/pull-request/123" if pull_request else "refs/heads/main"
        ),
        "GITHUB_REPOSITORY": "NVIDIA/infra-controller" if canonical else "example/fork",
    }


def _context(
    policy_name: str,
    *,
    selected: bool = True,
    pull_request: bool = True,
    skipped: set[str] | frozenset[str] = frozenset(),
    canonical: bool = True,
) -> tuple[dict[str, object], dict[str, str]]:
    """Build one result context from the gate's live dependency list."""

    context: dict[str, object] = {
        job: {"result": "skipped" if job in skipped else "success", "outputs": {}}
        for job in _gate_jobs(policy_name)
    }
    selection = "run_core_ci" if policy_name == "core" else "run_rest_ci"
    context["changes"]["outputs"] = {selection: str(selected).lower()}
    if policy_name == "core":
        context["prepare"]["outputs"] = dict.fromkeys(CORE_PREPARE_OUTPUTS, "true")
    return context, _environment(pull_request=pull_request, canonical=canonical)


class InventoryTests(unittest.TestCase):
    """Verify that every workflow job has exactly one gate classification."""

    def test_live_inventories_and_conditional_wiring(self) -> None:
        for policy_name, policy in POLICIES.items():
            with self.subTest(policy_name):
                workflow = _workflow(policy_name)
                self.assertEqual(inventory_errors(workflow, policy), [])

        # Keep the small exception table tied to the selectors it summarizes;
        # this is deliberately a wiring check, not an Actions expression parser.
        for output_name, jobs in CORE_PREPARE_OUTPUTS.items():
            for job in jobs:
                with self.subTest(job=job, output=output_name):
                    self.assertIn(
                        f"needs.prepare.outputs.{output_name}",
                        _job_body("core", job),
                    )
        for job in CORE_PR_ONLY_JOBS:
            with self.subTest(job=job, condition="pull request"):
                self.assertIn("pull-request/", _job_body("core", job))
        self.assertIn("github.repository ==", _job_body("core", CORE_CANONICAL_JOB))
        self.assertIn(
            "!startsWith(github.ref, 'refs/heads/pull-request/')",
            _job_body("rest", "build-and-push"),
        )
        self.assertIn(
            "startsWith(github.ref, 'refs/heads/pull-request/')",
            _job_body("rest", "build-and-push-pr"),
        )

    def test_inventory_classification(self) -> None:
        cases = (
            {
                "name": "complete inventory",
                "workflow": COMPLETE_WORKFLOW,
                "policy": CORE_POLICY,
                "expected": [],
            },
            {
                "name": "missing gate dependency",
                "workflow": COMPLETE_WORKFLOW.replace("      - build\n", ""),
                "policy": CORE_POLICY,
                "expected": ["top-level jobs are not gated or exempt: build"],
            },
            {
                "name": "unknown exemption",
                "workflow": COMPLETE_WORKFLOW,
                "policy": replace(
                    CORE_POLICY,
                    exemptions={
                        **CORE_POLICY.exemptions,
                        "retired-job": "No longer used.",
                    },
                ),
                "expected": ["exemptions are not top-level jobs: retired-job"],
            },
            {
                "name": "unknown gate dependency",
                "workflow": COMPLETE_WORKFLOW.replace(
                    "      - build\n", "      - build\n      - retired-job\n"
                ),
                "policy": CORE_POLICY,
                "expected": [
                    "gate dependencies are not top-level jobs: retired-job"
                ],
            },
            {
                "name": "duplicate classification",
                "workflow": COMPLETE_WORKFLOW,
                "policy": replace(
                    CORE_POLICY,
                    exemptions={
                        **CORE_POLICY.exemptions,
                        "build": "Fixture duplicate.",
                    },
                ),
                "expected": ["jobs cannot be both gated and exempt: build"],
            },
            {
                "name": "duplicate gate dependency",
                "workflow": COMPLETE_WORKFLOW.replace(
                    "      - build\n", "      - build\n      - build\n"
                ),
                "policy": CORE_POLICY,
                "expected": ["gate dependencies are listed more than once: build"],
            },
            {
                "name": "empty exemption reason",
                "workflow": COMPLETE_WORKFLOW,
                "policy": replace(
                    CORE_POLICY,
                    exemptions={**CORE_POLICY.exemptions, "build-summary": ""},
                ),
                "expected": ["exemptions need a reason: build-summary"],
            },
        )

        for case in cases:
            with self.subTest(case["name"]):
                self.assertEqual(
                    inventory_errors(case["workflow"], case["policy"]),
                    case["expected"],
                )

    def test_lane_policies(self) -> None:
        cases = (
            {
                "name": "REST policy",
                "workflow": REST_WORKFLOW,
                "policy": REST_POLICY,
                "expected": [],
            },
            {
                "name": "missing REST dependency",
                "workflow": REST_WORKFLOW.replace("      - helm\n", ""),
                "policy": REST_POLICY,
                "expected": ["top-level jobs are not gated or exempt: helm"],
            },
            {
                "name": "wrong policy",
                "workflow": REST_WORKFLOW,
                "policy": CORE_POLICY,
                "expected": ["the workflow does not define `core-ci-pass`"],
            },
        )

        for case in cases:
            with self.subTest(case["name"]):
                self.assertEqual(
                    inventory_errors(case["workflow"], case["policy"]),
                    case["expected"],
                )

    def test_required_workflow_sections(self) -> None:
        cases = (
            {
                "name": "missing jobs block",
                "workflow": COMPLETE_WORKFLOW.replace("jobs:\n", "pipelines:\n"),
                "expected": "expected one root `jobs` block, found 0",
            },
            {
                "name": "missing gate job",
                "workflow": COMPLETE_WORKFLOW.replace("core-ci-pass:", "retired-gate:"),
                "expected": "the workflow does not define `core-ci-pass`",
            },
            {
                "name": "missing gate needs",
                "workflow": COMPLETE_WORKFLOW.replace("    needs:\n", "    dependencies:\n"),
                "expected": (
                    "expected one block-style `needs` list on `core-ci-pass`, found 0"
                ),
            },
            {
                "name": "missing gate condition",
                "workflow": COMPLETE_WORKFLOW.replace("    if: always()\n", ""),
                "expected": (
                    "expected one gate-level `if` on `core-ci-pass`, found 0"
                ),
            },
            {
                "name": "wrong gate condition",
                "workflow": COMPLETE_WORKFLOW.replace("if: always()", "if: success()"),
                "expected": "`core-ci-pass.if` must be `always()`, found 'success()'",
            },
            {
                "name": "duplicate gate condition",
                "workflow": COMPLETE_WORKFLOW.replace(
                    "    if: always()\n",
                    "    if: always()\n    if: always()\n",
                ),
                "expected": (
                    "expected one gate-level `if` on `core-ci-pass`, found 2"
                ),
            },
            {
                "name": "duplicate top-level job",
                "workflow": COMPLETE_WORKFLOW.replace(
                    "  build:\n    runs-on: ubuntu-latest\n",
                    "  build:\n    runs-on: ubuntu-latest\n"
                    "  build:\n    runs-on: ubuntu-latest\n",
                ),
                "expected": "top-level job `build` is declared more than once",
            },
            {
                "name": "malformed top-level job",
                "workflow": COMPLETE_WORKFLOW.replace(
                    "  build:\n    runs-on: ubuntu-latest\n",
                    "  build: {runs-on: ubuntu-latest}\n",
                ),
                "expected": (
                    "line 6 is not a supported top-level job declaration: "
                    "'  build: {runs-on: ubuntu-latest}'"
                ),
            },
            {
                "name": "malformed gate dependency",
                "workflow": COMPLETE_WORKFLOW.replace("      - build\n", "      - [build]\n"),
                "expected": (
                    "line 17 is not a supported `core-ci-pass.needs` item: "
                    "'      - [build]'"
                ),
            },
            {
                "name": "empty gate dependencies",
                "workflow": COMPLETE_WORKFLOW.replace(
                    "      - changes\n      - build\n", ""
                ),
                "expected": "`core-ci-pass.needs` contains no jobs",
            },
            {
                "name": "under-indented gate dependency",
                "workflow": COMPLETE_WORKFLOW.replace(
                    "      - changes\n", "    - changes\n"
                ),
                "expected": (
                    "line 16 must indent `core-ci-pass.needs` items by six spaces: "
                    "'    - changes'"
                ),
            },
        )

        for case in cases:
            with self.subTest(case["name"]):
                self.assertEqual(
                    inventory_errors(case["workflow"], CORE_POLICY),
                    [case["expected"]],
                )


class CommandTests(unittest.TestCase):
    """Verify policy selection and workflow-file handling at the CLI boundary."""

    def test_inventory_command_accepts_each_policy(self) -> None:
        cases = (
            {
                "name": "Core policy",
                "policy": "core",
                "workflow": COMPLETE_WORKFLOW,
                "expected": "Core CI gate accounts for 5",
            },
            {
                "name": "REST policy",
                "policy": "rest",
                "workflow": REST_WORKFLOW,
                "expected": "REST CI gate accounts for 9",
            },
        )

        for case in cases:
            with self.subTest(case["name"]):
                with tempfile.TemporaryDirectory() as directory:
                    workflow_path = Path(directory) / "workflow.yml"
                    workflow_path.write_text(case["workflow"], encoding="utf-8")
                    output = io.StringIO()
                    with contextlib.redirect_stdout(output):
                        return_code = main(
                            [
                                "inventory",
                                "--policy",
                                case["policy"],
                                str(workflow_path),
                            ]
                        )

                self.assertEqual(return_code, 0)
                self.assertIn(case["expected"], output.getvalue())

    def test_inventory_command_rejects_unknown_policy(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaisesRegex(SystemExit, "2"):
                main(["inventory", "--policy", "unknown", "workflow.yml"])

    def test_inventory_command_rejects_unreadable_workflow(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            return_code = main(
                ["inventory", "--policy", "core", "/missing/workflow.yml"]
            )

        self.assertEqual(return_code, 1)
        self.assertIn("::error::could not read", output.getvalue())


class ResultTests(unittest.TestCase):
    """Verify healthy lanes and every fail-closed result boundary."""

    def test_healthy_runtime_scenarios(self) -> None:
        core_jobs = set(_gate_jobs("core"))
        rest_jobs = set(_gate_jobs("rest"))
        cases = (
            ("core", True, True, set()),
            ("core", False, True, core_jobs - {"changes", "migration-police"}),
            ("core", True, False, set(CORE_PR_ONLY_JOBS)),
            ("rest", True, True, {"build-and-push"}),
            ("rest", False, True, rest_jobs - {"changes"}),
            ("rest", True, False, {"build-and-push-pr"}),
        )
        for policy_name, selected, pull_request, skipped in cases:
            with self.subTest(policy=policy_name, selected=selected, pr=pull_request):
                context, environment = _context(
                    policy_name,
                    selected=selected,
                    pull_request=pull_request,
                    skipped=skipped,
                )
                self.assertEqual(
                    result_errors(context, policy_name, environment=environment), []
                )

    def test_optional_success_and_canonical_promotion(self) -> None:
        context, environment = _context(
            "core", canonical=False, skipped={CORE_CANONICAL_JOB}
        )
        self.assertEqual(result_errors(context, "core", environment=environment), [])
        context[CORE_CANONICAL_JOB]["result"] = "success"
        self.assertEqual(result_errors(context, "core", environment=environment), [])

    def test_migration_police_still_applies_to_a_deselected_core_lane(self) -> None:
        context, environment = _context(
            "core",
            selected=False,
            skipped=set(_gate_jobs("core")) - {"changes"},
        )
        self.assertIn(
            "`migration-police` was unexpectedly skipped",
            result_errors(context, "core", environment=environment),
        )

    def test_prepare_outputs_are_authoritative(self) -> None:
        for output_name, jobs in CORE_PREPARE_OUTPUTS.items():
            with self.subTest(output_name):
                context, environment = _context("core")
                context["prepare"]["outputs"][output_name] = "false"
                for job in jobs:
                    context[job]["result"] = "skipped"
                self.assertEqual(result_errors(context, "core", environment=environment), [])

    def test_every_live_gated_job_rejects_an_unexpected_skip(self) -> None:
        core, core_environment = _context("core")
        for job in _gate_jobs("core"):
            with self.subTest(policy="core", job=job):
                mutated = copy.deepcopy(core)
                mutated[job]["result"] = "skipped"
                self.assertIn(
                    f"`{job}` was unexpectedly skipped",
                    result_errors(mutated, "core", environment=core_environment),
                )

        for job in _gate_jobs("rest"):
            # Pick the ref that makes `job` applicable; the opposite Docker
            # caller remains the one expected skip in the healthy baseline.
            pull_request = job != "build-and-push"
            rest, rest_environment = _context(
                "rest",
                pull_request=pull_request,
                skipped={"build-and-push" if pull_request else "build-and-push-pr"},
            )
            with self.subTest(policy="rest", job=job):
                rest[job]["result"] = "skipped"
                self.assertIn(
                    f"`{job}` was unexpectedly skipped",
                    result_errors(rest, "rest", environment=rest_environment),
                )

    def test_bad_terminal_and_malformed_results(self) -> None:
        cases = (
            ("failure", "failure", "failed"),
            ("cancellation", "cancelled", "was cancelled"),
            ("unknown", "waiting", "unsupported result 'waiting'"),
        )
        for name, result, expected in cases:
            with self.subTest(name):
                context = {"fixture-job": {"result": result}}
                errors = result_errors(context, "rest", environment={})
                self.assertIn(expected, errors[0])

        self.assertIn(
            "did not provide a job result object",
            result_errors({"fixture-job": "success"}, "rest", environment={})[0],
        )

    def test_malformed_and_missing_boolean_outputs_fail_closed(self) -> None:
        for output_name in (*CORE_PREPARE_OUTPUTS, "run_core_ci"):
            job = "changes" if output_name == "run_core_ci" else "prepare"
            for value in ("yes", None):
                with self.subTest(output=output_name, value=value):
                    context, environment = _context("core")
                    outputs = context[job]["outputs"]
                    if value is None:
                        outputs.pop(output_name)
                    else:
                        outputs[output_name] = value
                    errors = result_errors(context, "core", environment=environment)
                    self.assertIn(output_name, errors[0])

    def test_missing_runtime_context_and_invalid_lane_decisions(self) -> None:
        core, environment = _context("core")
        for variable, expected in (
            ("GITHUB_REF", "`GITHUB_REF` is not set"),
            ("GITHUB_REPOSITORY", "`GITHUB_REPOSITORY` is not set"),
        ):
            with self.subTest(variable=variable):
                runtime = environment | {variable: ""}
                self.assertEqual(
                    result_errors(core, "core", environment=runtime), [expected]
                )

        for policy_name in ("core", "rest"):
            with self.subTest(policy_name):
                context, runtime = _context(
                    policy_name, selected=False, pull_request=False
                )
                errors = result_errors(context, policy_name, environment=runtime)
                self.assertIn("must be selected for a non-pull-request run", errors[0])

        context, runtime = _context("core")
        context["prepare"]["result"] = "skipped"
        self.assertIn(
            "`prepare` was unexpectedly skipped",
            result_errors(context, "core", environment=runtime)[0],
        )

        context, runtime = _context("core")
        context["changes"].pop("outputs")
        self.assertIn(
            "did not provide a job outputs object",
            result_errors(context, "core", environment=runtime)[0],
        )

        self.assertEqual(
            result_errors(core, "retired", environment=environment),
            ["unknown gate policy 'retired'"],
        )

    def test_workflow_only_regression(self) -> None:
        # The source filter now records workflow-only changes as applicable;
        # this test protects the aggregate half of the #4324 regression.
        context, environment = _context("core")
        context["lint-police"]["result"] = "skipped"
        self.assertIn(
            "`lint-police` was unexpectedly skipped",
            result_errors(context, "core", environment=environment),
        )

    def test_result_command_accepts_healthy_context(self) -> None:
        context, environment = _context(
            "rest", pull_request=False, skipped={"build-and-push-pr"}
        )
        runtime = {**environment, "NEEDS_JSON": json.dumps(context)}
        output = io.StringIO()
        with mock.patch.dict(
            os.environ, runtime, clear=True
        ), contextlib.redirect_stdout(output):
            return_code = main(["results", "--policy", "rest"])

        self.assertEqual(return_code, 0)
        self.assertIn("All REST CI jobs succeeded or skipped", output.getvalue())

    def test_result_command_rejects_invalid_context(self) -> None:
        cases = (
            ("malformed", "{", "is not valid JSON"),
            ("empty", "{}", "received no job results"),
            ("non-mapping", "[]", "must contain a JSON object"),
        )
        for name, needs_json, expected in cases:
            with self.subTest(name):
                output = io.StringIO()
                with mock.patch.dict(
                    os.environ, {"NEEDS_JSON": needs_json}, clear=True
                ), contextlib.redirect_stdout(output):
                    return_code = main(["results", "--policy", "rest"])

                self.assertEqual(return_code, 1)
                self.assertIn(expected, output.getvalue())

    def test_result_command_rejects_missing_context(self) -> None:
        output = io.StringIO()
        with mock.patch.dict(
            os.environ, {}, clear=True
        ), contextlib.redirect_stdout(output):
            return_code = main(["results", "--policy", "core"])

        self.assertEqual(return_code, 1)
        self.assertIn("::error::`NEEDS_JSON` is not set", output.getvalue())


if __name__ == "__main__":
    unittest.main()
