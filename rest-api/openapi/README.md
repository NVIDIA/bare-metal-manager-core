<!--
SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
-->

# NVIDIA Infra Controller REST OpenAPI Schema

This repo contains OpenAPI schema for NVIDIA Infra Controller REST endpoints. The latest Redoc-rendered version is available at https://nvidia.github.io/infra-controller-rest/

# Development

OpenAPI schema must be updated whenever the API endpoints are added/updated.

Please ensure that the following tools are installed:
 - Docker
 - npm

To lint schema after making changes, run:

    make lint-openapi

To view a rendered/browsable version of the schema locally, run:

    make preview-openapi

Then access the schema at:

    http://127.0.0.1:8090

# Updating GitHub Pages

In order to update the GitHub pages to reflect schema changes, you must include rendered HTML changes in your PR.

To modify the rendered HTML, run:

    make publish-openapi
