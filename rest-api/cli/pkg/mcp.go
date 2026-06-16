// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"

	cli "github.com/urfave/cli/v2"
)

// MCPCommand returns the "mcp" command. The MCP server lives in a separate
// binary (nico-mcp) so that neither the MCP server code nor its MCP SDK
// dependency are linked into nicocli. Rather than locating and exec'ing that
// binary on the user's behalf, this command prints instructions for building
// and running it locally, so the CLI never executes a binary resolved from the
// environment.
func MCPCommand() *cli.Command {
	return &cli.Command{
		Name:   "mcp",
		Usage:  "Print instructions for building and running the NICo MCP server",
		Action: printMCPInstructions,
	}
}

const mcpInstructions = `The NICo MCP server is a standalone binary (nico-mcp). Its code and MCP SDK
dependency are intentionally not linked into nicocli, so build and run it
directly.

Build (from the rest-api directory):

  make nico-mcp                           # build and install nico-mcp
  go build -o nico-mcp ./mcp/cmd/nico-mcp # ...or build without installing

Run (listens on :8080 at /mcp by default):

  nico-mcp --base-url https://<nico-host> --org <org>

Common flags (each also reads its NICO_* environment variable):

  --listen            address:port to listen on (default ":8080")
  --path              HTTP path the MCP handler is mounted at (default "/mcp")
  --base-url          default NICo REST base URL
  --org               default org used in /v2/org/<org>/... paths
  --api-name          API path segment in /v2/org/<org>/<name>/... (default "nico")
  --token             default bearer token
  --shutdown-timeout  graceful shutdown timeout (default 10s)
  --debug             enable debug logging

The server is stateless: base_url, org, and token can be supplied per tool
call (token also via an inbound Authorization header), with the flags above as
defaults. Point your MCP client at http://<listen><path> (default
http://localhost:8080/mcp). Run "nico-mcp --help" for the full flag list.
`

func printMCPInstructions(c *cli.Context) error {
	fmt.Fprint(c.App.Writer, mcpInstructions)
	return nil
}
