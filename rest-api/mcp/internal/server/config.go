// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"cmp"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/sirupsen/logrus"
)

// Options carry the server-side defaults that every tool invocation
// starts from. Individual tool calls override these per request through
// resolveCallConfig.
type Options struct {
	// BaseURL is the NICo REST base URL (e.g. https://nico.example.com).
	BaseURL string
	// Org is the default organisation used in /v2/org/<org>/... paths.
	Org string
	// APIName is the API path segment between org and resource (default
	// "nico", overridable via api.name in config).
	APIName string
	// Token is the static bearer used when no inbound bearer or tool
	// arg token is provided.
	Token string
	// Debug enables logrus debug-level HTTP request/response logging
	// through to the appcli.Client.
	Debug bool
	// Log is the logrus entry used for client request/response logging.
	// If nil, a default entry wrapping the standard logger is used.
	Log *logrus.Entry
}

// withDefaults returns a copy of opts with empty optional fields filled
// in with package defaults. APIName falls back to "nico" and Log to
// logrus.StandardLogger() so callers can leave them unset.
func (o Options) withDefaults() Options {
	if o.APIName == "" {
		o.APIName = "nico"
	}
	if o.Log == nil {
		o.Log = logrus.NewEntry(logrus.StandardLogger())
	}
	return o
}

// commonConfigDescriptions documents the four per-call config overrides
// that are merged into every tool's input schema. Kept as a slice (not
// a map) so the schema render order is stable.
var commonConfigDescriptions = []struct {
	Name string
	Desc string
}{
	{"org", "Org used in /v2/org/<org>/... paths for this call. Overrides the server startup flag/env default when set."},
	{"base_url", "NICo REST base URL for this call. Overrides the server startup flag/env default when set; useful when one MCP server fronts multiple NICo REST deployments."},
	{"api_name", "Override the API path segment used in /v2/org/<org>/<name>/... (api.name; default \"nico\")."},
	{"token", "Bearer token for this call. Overrides the inbound Authorization header. Omit it when an upstream proxy injects the Authorization header, which is passed through to NICo REST unchanged."},
}

// resolvedConfig is the result of merging Options with the per-call
// overrides for one tool invocation. It is consumed by registerGET to
// construct a fresh appcli.Client.
type resolvedConfig struct {
	BaseURL string
	Org     string
	APIName string
	Token   string
}

// FromCallConfig populates cfg by resolving the precedence chain
// documented in the design plan:
//
//  1. Tool-call argument (org, base_url, api_name, token)
//  2. Inbound Authorization header (token only)
//  3. Server startup flag / Options (BaseURL, Org, APIName, Token)
//
// It returns an error when a required field (org, base_url) ends up
// empty so the tool handler can surface a JSON-RPC error instead of
// letting the call go out with an invalid URL.
func (cfg *resolvedConfig) FromCallConfig(in map[string]any, req *mcp.CallToolRequest, opts Options) error {
	cfg.BaseURL = normalizeBaseURL(cmp.Or(stringArg(in, "base_url"), opts.BaseURL))
	cfg.Org = cmp.Or(stringArg(in, "org"), opts.Org)
	cfg.APIName = cmp.Or(stringArg(in, "api_name"), opts.APIName)
	cfg.Token = normalizeToken(cmp.Or(
		stringArg(in, "token"),
		bearerFromExtra(req),
		opts.Token,
	))
	return cfg.requireNonEmpty()
}

// requireNonEmpty returns a descriptive error when org or BaseURL are
// blank. Token can be empty -- NICo REST will reject the request with
// 401 and the response surfaces to the caller as an MCP error result;
// that path is exercised by the bearer-passthrough integration test.
func (c resolvedConfig) requireNonEmpty() error {
	missing := []string{}
	if c.Org == "" {
		missing = append(missing, "org")
	}
	if c.BaseURL == "" {
		missing = append(missing, "base_url")
	}
	if len(missing) == 0 {
		return nil
	}
	return fmt.Errorf("missing required config value(s): %s; pass via tool-call arguments, server flags, or NICO_* environment variables",
		strings.Join(missing, ", "))
}
