// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	stdlog "log"
	"os"
	"path"
	"strings"
	"text/template"
	_ "time/tzdata"

	"github.com/urfave/cli/v2"
	"go.temporal.io/server/common/authorization"
	"go.temporal.io/server/common/build"
	"go.temporal.io/server/common/config"
	"go.temporal.io/server/common/debug"
	"go.temporal.io/server/common/dynamicconfig"
	"go.temporal.io/server/common/headers"
	"go.temporal.io/server/common/log"
	"go.temporal.io/server/common/log/tag"
	_ "go.temporal.io/server/common/persistence/sql/sqlplugin/mysql"
	_ "go.temporal.io/server/common/persistence/sql/sqlplugin/postgresql"
	_ "go.temporal.io/server/common/persistence/sql/sqlplugin/sqlite"
	"go.temporal.io/server/temporal"
	"go.uber.org/automaxprocs/maxprocs"

	nicoauth "github.com/NVIDIA/infra-controller/rest-api/temporal-server/internal/auth"
)

func main() {
	app := buildCLI()
	if err := app.Run(os.Args); err != nil {
		os.Exit(1)
	}
}

func buildCLI() *cli.App {
	app := cli.NewApp()
	app.Name = "temporal"
	app.Usage = "Temporal server"
	app.Version = headers.ServerVersion
	app.ArgsUsage = " "
	app.Flags = []cli.Flag{
		&cli.StringFlag{
			Name:    "root",
			Aliases: []string{"r"},
			Value:   ".",
			Usage:   "root directory of execution environment",
			EnvVars: []string{config.EnvKeyRoot},
		},
		&cli.StringFlag{
			Name:    "config",
			Aliases: []string{"c"},
			Value:   "config",
			Usage:   "config dir path relative to root",
			EnvVars: []string{config.EnvKeyConfigDir},
		},
		&cli.StringFlag{
			Name:    "env",
			Aliases: []string{"e"},
			Value:   "development",
			Usage:   "runtime environment",
			EnvVars: []string{config.EnvKeyEnvironment},
		},
		&cli.StringFlag{
			Name:    "zone",
			Aliases: []string{"az"},
			Usage:   "availability zone",
			EnvVars: []string{config.EnvKeyAvailabilityZone, config.EnvKeyAvailabilityZoneTypo},
		},
		&cli.BoolFlag{
			Name:    "allow-no-auth",
			Usage:   "deprecated; authorization is always enabled",
			EnvVars: []string{config.EnvKeyAllowNoAuth},
		},
	}

	app.Commands = []*cli.Command{
		{
			Name:      "validate-dynamic-config",
			Usage:     "Validate a dynamic config file[s] with known keys and types",
			ArgsUsage: "<file> ...",
			Action: func(c *cli.Context) error {
				total := 0
				for _, fileName := range c.Args().Slice() {
					contents, err := os.ReadFile(fileName)
					if err != nil {
						return err
					}
					result := dynamicconfig.ValidateFile(contents)
					total += len(result.Errors)
					fmt.Println(fileName)
					tmpl := template.Must(template.New("").Parse(
						"{{range .Errors}}  error: {{.}}\n" +
							"{{end}}{{range .Warnings}}  warning: {{.}}\n" +
							"{{end}}",
					))
					_ = tmpl.Execute(os.Stdout, result)
				}
				if total > 0 {
					return fmt.Errorf("%d total errors", total)
				}
				return nil
			},
		},
		{
			Name:      "start",
			Usage:     "Start Temporal server",
			ArgsUsage: " ",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:    "services",
					Aliases: []string{"s"},
					Usage:   "comma separated list of services to start. Deprecated",
					Hidden:  true,
				},
				&cli.StringSliceFlag{
					Name:    "service",
					Aliases: []string{"svc"},
					Value:   cli.NewStringSlice(temporal.DefaultServices...),
					Usage:   "service(s) to start",
				},
			},
			Before: func(c *cli.Context) error {
				if c.Args().Len() > 0 {
					return cli.Exit("ERROR: start command doesn't support arguments. Use --service flag instead.", 1)
				}
				if _, err := maxprocs.Set(); err != nil {
					stdlog.Printf("WARNING: failed to set GOMAXPROCS: %v.\n", err)
				}
				return nil
			},
			Action: startServer,
		},
	}
	return app
}

func startServer(c *cli.Context) error {
	env := c.String("env")
	zone := c.String("zone")
	configDir := path.Join(c.String("root"), c.String("config"))
	services := c.StringSlice("service")
	if c.IsSet("services") {
		stdlog.Println("WARNING: --services flag is deprecated. Specify multiple --service flags instead.")
		services = strings.Split(c.String("services"), ",")
	}

	cfg, err := config.LoadConfig(env, configDir, zone)
	if err != nil {
		return cli.Exit(fmt.Sprintf("Unable to load configuration: %v.", err), 1)
	}

	logger := log.NewZapLogger(log.BuildZapLogger(cfg.Log))
	logger.Info("Build info.",
		tag.NewTimeTag("git-time", build.InfoData.GitTime),
		tag.NewStringTag("git-revision", build.InfoData.GitRevision),
		tag.NewBoolTag("git-modified", build.InfoData.GitModified),
		tag.NewStringTag("go-arch", build.InfoData.GoArch),
		tag.NewStringTag("go-os", build.InfoData.GoOs),
		tag.NewStringTag("go-version", build.InfoData.GoVersion),
		tag.NewBoolTag("cgo-enabled", build.InfoData.CgoEnabled),
		tag.NewStringTag("server-version", headers.ServerVersion),
		tag.NewBoolTag("debug-mode", debug.Enabled),
	)

	var dynamicConfigClient dynamicconfig.Client
	if cfg.DynamicConfigClient != nil {
		dynamicConfigClient, err = dynamicconfig.NewFileBasedClient(cfg.DynamicConfigClient, logger, temporal.InterruptCh())
		if err != nil {
			return cli.Exit(fmt.Sprintf("Unable to create dynamic config client. Error: %v", err), 1)
		}
	} else {
		dynamicConfigClient = dynamicconfig.NewNoopClient()
		logger.Info("Dynamic config client is not configured. Using noop client.")
	}

	claimMapper := nicoauth.NewClaimMapper()
	server, err := temporal.NewServer(
		temporal.ForServices(services),
		temporal.WithConfig(cfg),
		temporal.WithDynamicConfigClient(dynamicConfigClient),
		temporal.WithLogger(logger),
		temporal.InterruptOn(temporal.InterruptCh()),
		temporal.WithAuthorizer(nicoauth.NewAuthorizer()),
		temporal.WithClaimMapper(func(*config.Config) authorization.ClaimMapper {
			return claimMapper
		}),
	)
	if err != nil {
		return cli.Exit(fmt.Sprintf("Unable to create server. Error: %v.", err), 1)
	}
	if err := server.Start(); err != nil {
		return cli.Exit(fmt.Sprintf("Unable to start server. Error: %v", err), 1)
	}
	return cli.Exit("All services are stopped.", 0)
}
