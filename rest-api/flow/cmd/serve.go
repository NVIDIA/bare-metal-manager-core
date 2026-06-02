// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"go.temporal.io/sdk/worker"

	cdb "github.com/NVIDIA/infra-controller-rest/db/pkg/db"
	"github.com/NVIDIA/infra-controller-rest/flow/internal/config"
	"github.com/NVIDIA/infra-controller-rest/flow/internal/nicoapi"
	svc "github.com/NVIDIA/infra-controller-rest/flow/internal/service"
	"github.com/NVIDIA/infra-controller-rest/flow/internal/task/componentmanager"
	cmbuiltin "github.com/NVIDIA/infra-controller-rest/flow/internal/task/componentmanager/builtin"
	cmconfig "github.com/NVIDIA/infra-controller-rest/flow/internal/task/componentmanager/config"
	temporalmanager "github.com/NVIDIA/infra-controller-rest/flow/internal/task/executor/temporalworkflow/manager"
	pkgcerts "github.com/NVIDIA/infra-controller-rest/flow/pkg/certs"
	"github.com/NVIDIA/infra-controller-rest/flow/pkg/common/devicetypes"
)

const (
	defaultServicePort    = 50051
	componentMgrCfgEnvVar = "COMPONENT_MANAGER_CONFIG"
)

var (
	port               int
	componentMgrConfig string
	devMode            bool

	// clientOnlyFlags are the global persistent flags that apply only to
	// client commands. They are hidden from serve's help and rejected if set.
	clientOnlyFlags = []string{flagHost, flagPort}

	// serveCmd represents the serve command
	serveCmd = &cobra.Command{
		Use:   "serve",
		Short: "Start the Flow gRPC server",
		Long:  `Start the gRPC server to allow other services to manage the racks`,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			for _, name := range clientOnlyFlags {
				if cmd.Root().PersistentFlags().Changed(name) {
					return fmt.Errorf("--%s is not applicable to 'flow serve'", name)
				}
			}
			return nil
		},
		Run: func(cmd *cobra.Command, args []string) {
			doServe()
		},
	}
)

func init() {
	rootCmd.AddCommand(serveCmd)

	// Hide client-only persistent flags from serve's help output.
	for _, name := range clientOnlyFlags {
		_ = serveCmd.InheritedFlags().MarkHidden(name)
	}

	serveCmd.Flags().IntVarP(&port, "listen-port", "p", defaultServicePort, "Port for the gRPC server") //nolint:lll
	// Component manager config: priority is CLI flag > env var > service default config.
	serveCmd.Flags().StringVarP(&componentMgrConfig, "component-config", "c", "", "Path to component manager config file (YAML)")               //nolint:lll
	serveCmd.Flags().BoolVar(&devMode, "dev-mode", false, "Enable developer options (gRPC reflection, debug logging). Not for production use.") //nolint:lll
}

// loadComponentManagerConfig loads the component manager configuration with the following priority:
//
//  1. CLI flag: --component-config / -c <path>
//     Example: ./flow serve -c /etc/flow/custom.yaml
//
//  2. Environment variable: COMPONENT_MANAGER_CONFIG=<path>
//     Example: COMPONENT_MANAGER_CONFIG=/etc/flow/componentmanager.yaml
//
//  3. Embedded default: builtin service config
//     Used when no config file is provided. The primary production path.
//     Uses the component manager implementation map defined by builtin.
//
// The config specifies:
//   - Which component manager implementations to use (nico, psm, mock)
//   - Provider settings (timeouts, endpoints)
func loadComponentManagerConfig() (cmconfig.Config, error) {
	// Priority 1: CLI flag
	configPath := componentMgrConfig

	// Priority 2: Environment variable
	if configPath == "" {
		configPath = os.Getenv(componentMgrCfgEnvVar)
	}

	// Load from file if a path was specified
	if configPath != "" {
		log.Info().Str("config_path", configPath).Msg("Loading component manager config from file")
		return cmbuiltin.LoadConfig(configPath)
	}

	// Priority 3: Embedded service config
	log.Info().Msg("Using embedded component manager service config")
	return cmbuiltin.LoadConfig("")
}

// doServe is the main entry point for the serve subcommand. It loads all
// configuration, initialises provider and component manager registries, builds
// the service, and blocks until a termination signal is received.
func doServe() {
	if devMode {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	} else {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}

	if os.Getenv(svc.EnvVarName) == "" {
		log.Warn().Msgf("%s not set, defaulting to %q for local development", svc.EnvVarName, "development")
		os.Setenv(svc.EnvVarName, "development") //nolint:errcheck
	}

	flowEnv, err := svc.GetDeploymentEnv()
	if err != nil {
		log.Fatal().Err(err).Msg("Invalid deployment environment")
	}

	log.Info().Str(svc.EnvVarName, flowEnv).Msg("Deployment environment")

	flowConfig := config.ReadConfig()

	dbConf, err := cdb.ConfigFromEnv()
	if err != nil {
		log.Fatal().Msgf("failed to retrieve DB conn information: %v", err)
	}

	temporalConf, err := svc.BuildTemporalConfigFromEnv()
	if err != nil {
		log.Fatal().Msgf("failed to retrieve Temporal conn information: %v", err)
	}

	ctx := context.Background()

	// Load component manager configuration
	cmConfig, err := loadComponentManagerConfig()
	if err != nil {
		log.Fatal().Msgf("failed to load component manager config: %v", err)
	}

	// Initialize provider registry (creates API clients based on config)
	providerRegistry, err := cmbuiltin.NewProviderRegistry(ctx, cmConfig)
	if err != nil {
		log.Fatal().Msgf("failed to initialize provider registry: %v", err)
	}

	// Initialize component manager registry
	cmRegistry, err := cmbuiltin.NewComponentManagerRegistry(
		cmConfig,
		providerRegistry,
	)
	if err != nil {
		log.Fatal().Msgf("failed to initialize component manager registry: %v", err)
	}
	logComponentManagerRegistry(cmRegistry)

	temporalManagerConf := temporalmanager.Config{
		ClientConf: *temporalConf,
		WorkerOptions: map[string]worker.Options{
			temporalmanager.WorkflowQueue: {},
		},
		ComponentManagerRegistry: cmRegistry,
	}

	if os.Getenv("REPORT_NICO_API_VERSION") != "" {
		// Do some basic nico-api requests, mainly for early testing; this code can be removed when we're doing actual communication
		go func() {
			client, err := nicoapi.NewClient(time.Minute)
			if err != nil {
				log.Fatal().Msgf("Unable to create GRPC client: %v", err)
			}
			for {
				time.Sleep(time.Second * 10)
				if version, err := client.Version(ctx); err != nil {
					log.Error().Msgf("Unable to retrieve version from nico-core-api: %v", err)
					continue
				} else {
					log.Info().Msgf("nico-core-api version: %s", version)
					break
				}
			}
			for {
				time.Sleep(time.Second * 10)
				if machines, err := client.GetMachines(ctx); err != nil {
					log.Error().Msgf("Unable to retrieve machines from nico-core-api: %v", err)
					continue
				} else {
					log.Info().Msgf("nico-core-api machines: %v", machines)
					break
				}
			}
		}()
	}

	service, err := svc.New(
		ctx,
		svc.Config{
			Port:             port,
			DBConf:           dbConf,
			ExecutorConf:     &temporalManagerConf,
			FlowConfig:       flowConfig,
			CMConfig:         cmConfig,
			ProviderRegistry: providerRegistry,
			DevMode:          devMode,
			CertConfig: pkgcerts.Config{
				CACert:  globalCACert,
				TLSCert: globalTLSCert,
				TLSKey:  globalTLSKey,
			},
		},
	)

	if err != nil {
		log.Fatal().Msgf("failed to create the new gRPC server: %v", err)
	}

	log.Info().Msg("New Flow service is created\n")
	log.Info().Msgf("DB config: %+v", dbConf)
	log.Info().Msgf("Temporal config: %+v", temporalManagerConf)

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs // Block execution until signal from terminal gets triggered here.
		service.Stop(ctx)
	}()

	if err := service.Start(ctx); err != nil {
		log.Fatal().Msgf("failed to start the service: %v\n", err)
	}
}

func logComponentManagerRegistry(registry *componentmanager.Registry) {
	descriptors, err := registry.Descriptors()
	if err != nil {
		log.Warn().
			Err(err).
			Msg("Component manager registry report unavailable")
		return
	}

	for _, descriptor := range descriptors {
		log.Info().
			Str(
				"component_type",
				devicetypes.ComponentTypeToString(descriptor.Type),
			).
			Str("implementation", descriptor.Implementation).
			Strs("capabilities", descriptor.Capabilities.Strings()).
			Msg("Active component manager capabilities")
	}
}
