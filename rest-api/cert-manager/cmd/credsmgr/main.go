// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package main is the command entry point
package main

import (
	"context"
	"os"

	"github.com/NVIDIA/infra-controller-rest/cert-manager/pkg/certs"
	"github.com/NVIDIA/infra-controller-rest/cert-manager/pkg/core"
	cli "github.com/urfave/cli/v2"
)

func main() {
	cmd := certs.NewCommand()
	app := &cli.App{
		Name:    cmd.Name,
		Usage:   cmd.Usage,
		Version: "0.1.0",
		Flags:   cmd.Flags,
		Action:  cmd.Action,
	}

	ctx := core.NewDefaultContext(context.Background())
	log := core.GetLogger(ctx)
	if err := app.RunContext(ctx, os.Args); err != nil {
		log.Fatal(err)
	}
}
