#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for the shared CI final-gate inventory and result checks."""

from __future__ import annotations

import contextlib
import io
import os
import tempfile
import textwrap
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

from check_ci_gate import (
    CORE_POLICY,
    REST_POLICY,
    inventory_errors,
    main,
    result_errors,
)


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


class InventoryTests(unittest.TestCase):
    """Verify that every workflow job has exactly one gate classification."""

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
    """Verify the final gate's success, skip, and fail-closed result policy."""

    def test_gate_result_policy(self) -> None:
        cases = (
            {
                "name": "success",
                "result": "success",
                "expected": [],
            },
            {
                "name": "intentional skip",
                "result": "skipped",
                "expected": [],
            },
            {
                "name": "failure",
                "result": "failure",
                "expected": ["`fixture-job` failed"],
            },
            {
                "name": "cancellation",
                "result": "cancelled",
                "expected": ["`fixture-job` was cancelled"],
            },
        )

        for case in cases:
            with self.subTest(case["name"]):
                needs_context = {"fixture-job": {"result": case["result"]}}
                self.assertEqual(result_errors(needs_context), case["expected"])

    def test_non_mapping_job_result_is_rejected(self) -> None:
        self.assertEqual(
            result_errors({"fixture-job": "success"}),
            ["`fixture-job` did not provide a job result object"],
        )

    def test_result_command_accepts_healthy_context(self) -> None:
        needs_json = (
            '{"successful-job":{"result":"success"},'
            '"skipped-job":{"result":"skipped"}}'
        )
        output = io.StringIO()
        with mock.patch.dict(os.environ, {"NEEDS_JSON": needs_json}):
            with contextlib.redirect_stdout(output):
                return_code = main(["results"])

        self.assertEqual(return_code, 0)
        self.assertNotIn("::error::", output.getvalue())
        self.assertIn(
            "All required jobs succeeded or were intentionally skipped.",
            output.getvalue(),
        )

    def test_result_command_rejects_invalid_context(self) -> None:
        cases = (
            {
                "name": "malformed JSON",
                "needs_json": "{",
                "expected": "::error::`NEEDS_JSON` is not valid JSON:",
            },
            {
                "name": "empty context",
                "needs_json": "{}",
                "expected": "::error::the gate received no job results",
            },
            {
                "name": "non-mapping JSON",
                "needs_json": "[]",
                "expected": "::error::`NEEDS_JSON` must contain a JSON object",
            },
            {
                "name": "unsupported result",
                "needs_json": '{"fixture-job":{"result":"waiting"}}',
                "expected": (
                    "::error::`fixture-job` returned unsupported result 'waiting'"
                ),
            },
            {
                "name": "missing result",
                "needs_json": '{"fixture-job":{}}',
                "expected": (
                    "::error::`fixture-job` returned unsupported result None"
                ),
            },
            {
                "name": "null result",
                "needs_json": '{"fixture-job":{"result":null}}',
                "expected": (
                    "::error::`fixture-job` returned unsupported result None"
                ),
            },
        )

        for case in cases:
            with self.subTest(case["name"]):
                output = io.StringIO()
                with mock.patch.dict(os.environ, {"NEEDS_JSON": case["needs_json"]}):
                    with contextlib.redirect_stdout(output):
                        return_code = main(["results"])

                self.assertEqual(return_code, 1)
                self.assertIn(case["expected"], output.getvalue())

    def test_result_command_rejects_missing_context(self) -> None:
        output = io.StringIO()
        with mock.patch.dict(os.environ, {}, clear=True):
            with contextlib.redirect_stdout(output):
                return_code = main(["results"])

        self.assertEqual(return_code, 1)
        self.assertIn("::error::`NEEDS_JSON` is not set", output.getvalue())


if __name__ == "__main__":
    unittest.main()
