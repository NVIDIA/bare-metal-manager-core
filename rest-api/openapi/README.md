<!--
SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
-->

# NVIDIA Infra Controller REST OpenAPI Schema

This repo contains OpenAPI schema for NVIDIA Infra Controller REST endpoints. The latest rendered version is available at https://docs.nvidia.com/infra-controller/rest-api-reference/api-reference

# Development

OpenAPI schema must be updated whenever the API endpoints are added/updated.

Please ensure that the following tools are installed:
 - Docker
 - npm
 - A JDK, for SDK generation (For MacOS use `brew install openjdk`, for Linux use built in package manager or brew)

To lint schema after making changes, run:

    make lint-openapi

To view a rendered/browsable version of the schema locally, run:

    make preview-openapi

Then access the schema at:

    http://127.0.0.1:8090

# Generating the Go SDK

The Go client under `sdk/standard/` is generated from this schema, so schema changes
must be accompanied by a regenerated client:

    make generate-sdk

The generator version is pinned in `rest-api/Makefile`; its jar is downloaded to
`.tools/` and checksum-verified on first use, so there is nothing else to install.
Without the pin, the generator rewrites files the schema change never touched,
because its output is byte-for-byte version dependent. CI regenerates the client and
fails if the result differs from what was committed.

# Updating GitHub Pages

In order to update the GitHub pages to reflect schema changes, you must include rendered HTML changes in your PR.

To modify the rendered HTML, run:

    make publish-openapi
