// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"

	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"

	cdb "github.com/NVIDIA/infra-controller/rest-api/db/pkg/db"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/certs"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/common/grpclog"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/db/migrations"
	inventorymanager "github.com/NVIDIA/infra-controller/rest-api/flow/internal/inventory/manager"
	inventorystore "github.com/NVIDIA/infra-controller/rest-api/flow/internal/inventory/store"
	operationrunmanager "github.com/NVIDIA/infra-controller/rest-api/flow/internal/operationrun/manager"
	operationrundispatcher "github.com/NVIDIA/infra-controller/rest-api/flow/internal/operationrun/manager/dispatcher"
	operationrunplanner "github.com/NVIDIA/infra-controller/rest-api/flow/internal/operationrun/manager/planner"
	operationrunstore "github.com/NVIDIA/infra-controller/rest-api/flow/internal/operationrun/manager/store"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/scheduler"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/scheduler/jobs/inventorysync"
	"github.com/NVIDIA/infra-controller/rest-api/flow/internal/scheduler/jobs/leakdetection"
	taskschedule "github.com/NVIDIA/infra-controller/rest-api/flow/internal/scheduler/taskschedule"
	schedtypes "github.com/NVIDIA/infra-controller/rest-api/flow/internal/scheduler/types"
	taskmanager "github.com/NVIDIA/infra-controller/rest-api/flow/internal/task/manager"
	taskstore "github.com/NVIDIA/infra-controller/rest-api/flow/internal/task/store"
	pb "github.com/NVIDIA/infra-controller/rest-api/flow/pkg/proto/v1"
)

// Service is the top-level Flow service. It owns the gRPC server, database
// session, inventory manager, and task manager and coordinates their lifecycles.
type Service struct {
	conf                   Config
	grpcServer             *grpc.Server
	session                *cdb.Session
	inventoryManager       inventorymanager.Manager
	taskStore              taskstore.Store
	operationRunStore      operationrundispatcher.Store
	taskManager            taskmanager.Manager
	operationRunManager    operationrunmanager.Manager
	operationRunDispatcher *operationrundispatcher.Dispatcher
	sched                  *scheduler.Scheduler
	taskScheduleStore      taskschedule.Store
	taskScheduleDispatcher *taskschedule.Dispatcher
}

// New creates and initialises a Service from the provided Config. It opens the
// database connection, runs pending migrations, and wires up the inventory and
// task managers. The returned service is ready to Start.
func New(ctx context.Context, c Config) (*Service, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}

	// 1. Create shared PostgreSQL connection
	session, err := cdb.NewSessionFromConfig(ctx, c.DBConf)
	if err != nil {
		return nil, fmt.Errorf("failed to create database connection: %w", err)
	}

	// Run migrations
	if err := migrations.MigrateWithDB(ctx, session.DB); err != nil {
		session.Close()

		return nil, fmt.Errorf("failed to run migrations: %w", err)
	}

	// 2. Create stores (Storage Layer)
	invStore := inventorystore.NewPostgres(session)
	tskStore := taskstore.NewPostgres(session)
	schedStore := taskschedule.NewPostgresStore(session)
	operationRunStore := operationrunstore.NewPostgresStore(session)

	// 3. Create InventoryManager (Business Logic Layer)
	invManager := inventorymanager.New(invStore)

	// 4. Create TaskManager (Business Logic Layer)
	// Note: Task manager creates its own rule resolver internally
	taskManager, err := taskmanager.New(
		ctx,
		&taskmanager.Config{
			InventoryStore: invStore,
			TaskStore:      tskStore,
			ExecutorConfig: c.ExecutorConf,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create task manager: %w", err)
	}

	// 5. Create OperationRunManager (Business Logic Layer)
	operationRunLookup := operationrunplanner.NewInventoryTargetLookup(
		invManager,
		operationRunStore,
	)
	operationRunPlanner := operationrunplanner.New(
		operationRunLookup,
		operationrunplanner.Config{
			MaxCandidateScopeTargets: operationrunplanner.DefaultMaxCandidateScopeTargets,
		},
	)
	operationRunManager, err := operationrunmanager.New(
		operationRunStore,
		operationRunPlanner,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create operation run manager: %w", err)
	}

	return &Service{
		conf:                c,
		session:             session,
		inventoryManager:    invManager,
		taskStore:           tskStore,
		operationRunStore:   operationRunStore,
		taskManager:         taskManager,
		operationRunManager: operationRunManager,
		taskScheduleStore:   schedStore,
	}, nil
}

// Start starts the inventory manager, task manager, and inventory sync
// goroutine, then begins serving gRPC requests on the configured port.
// It blocks until the gRPC server stops.
func (s *Service) Start(ctx context.Context) (retErr error) {
	log.Logger = log.With().Caller().Logger()

	certOpt := s.certOption()

	// On any error return, shut down every resource that was started, in
	// reverse start order. Boolean flags record which components are running
	// because inventoryManager and taskManager are always non-nil (set in New)
	// so a nil check cannot distinguish "created" from "started".
	var (
		invStarted  bool
		taskStarted bool
		lis         net.Listener
	)

	defer func() {
		if retErr == nil {
			return
		}

		// Stop the started resources in reverse start order.
		if s.operationRunDispatcher != nil {
			s.operationRunDispatcher.Stop()
		}
		if s.taskScheduleDispatcher != nil {
			s.taskScheduleDispatcher.Stop()
		}
		if s.sched != nil {
			s.sched.Stop(false) //nolint
		}
		if lis != nil {
			lis.Close()
		}
		if taskStarted {
			s.taskManager.Stop(ctx)
		}
		if invStarted {
			s.inventoryManager.Stop(ctx)
		}
		s.session.Close()
	}()

	// Rule resolver is ready immediately (queries DB for rules)
	log.Info().Msg("Rule resolver ready (will query DB for operation rules)")

	if err := s.inventoryManager.Start(ctx); err != nil {
		return fmt.Errorf("failed to start inventory manager: %w", err)
	}
	invStarted = true
	log.Info().Msg("Inventory manager started")

	if s.taskManager != nil {
		if err := s.taskManager.Start(ctx); err != nil {
			return fmt.Errorf("failed to start task manager: %w", err)
		}
		taskStarted = true
		log.Info().Msg("Task manager started")
	}

	// Pre-create the dispatcher without starting it. The listener and server
	// implementation are constructed next so that a failure there does not
	// leave a live background goroutine polling the DB.
	dispatcher := taskschedule.NewDispatcher(
		taskschedule.Config{
			Store:       s.taskScheduleStore,
			TaskManager: s.taskManager,
			TaskStore:   s.taskStore,
		},
	)
	var err error
	operationRunDispatcher, err := operationrundispatcher.New(
		operationrundispatcher.Dependencies{
			Store:       s.operationRunStore,
			TaskManager: s.taskManager,
			TaskStore:   s.taskStore,
		},
		operationrundispatcher.Config{},
	)
	if err != nil {
		return fmt.Errorf("failed to create operation run dispatcher: %w", err)
	}

	lis, err = net.Listen("tcp", fmt.Sprintf(":%v", s.conf.Port))
	if err != nil {
		return err
	}

	serverImpl, err := newServerImplementation(
		s.inventoryManager,
		s.taskManager,
		s.taskStore,
		s.taskScheduleStore,
		dispatcher,
		s.operationRunManager,
	)
	if err != nil {
		return err
	}

	// All construction succeeded — start background workers.
	if err := s.startScheduler(ctx); err != nil {
		return fmt.Errorf("failed to start system job scheduler: %w", err)
	}

	log.Info().Msg("Starting task schedule dispatcher")
	if err := dispatcher.Start(ctx); err != nil {
		return fmt.Errorf("failed to start task schedule dispatcher: %w", err)
	}
	s.taskScheduleDispatcher = dispatcher
	log.Info().Msg("Task schedule dispatcher started")

	log.Info().Msg("Starting operation run dispatcher")
	if err := operationRunDispatcher.Start(ctx); err != nil {
		return fmt.Errorf("failed to start operation run dispatcher: %w", err)
	}
	s.operationRunDispatcher = operationRunDispatcher
	log.Info().Msg("Operation run dispatcher started")

	s.grpcServer = grpc.NewServer(
		certOpt,
		grpc.ChainUnaryInterceptor(grpclog.UnaryServerInterceptor()),
	)

	log.Info().Msg("gRPC server is running")

	// Block the main runtime loop for accepting and processing gRPC requests.
	pb.RegisterFlowServer(s.grpcServer, serverImpl)
	if s.conf.DevMode {
		reflection.Register(s.grpcServer)
		log.Debug().Msg("Dev mode: gRPC reflection enabled")
	}

	// Serve blocks until Stop/GracefulStop is called. GracefulStop returns
	// grpc.ErrServerStopped, which is a sentinel for intentional shutdown, not
	// a failure. Normalize it to nil so the deferred cleanup block (which fires
	// on any non-nil retErr) does not incorrectly tear down resources that are
	// already being shut down by Stop().
	if err := s.grpcServer.Serve(lis); err != nil &&
		!errors.Is(err, grpc.ErrServerStopped) {
		return err
	}

	return nil
}

// Stop gracefully shuts down the service in dependency order:
//  1. Background producers (dispatcher, system scheduler) — stop submitting new work.
//  2. gRPC server — drain in-flight RPCs; no new requests accepted after this.
//  3. Task and inventory managers — safe to stop once no new submissions can arrive.
//  4. Database session.
func (s *Service) Stop(ctx context.Context) {
	log.Info().Msg("Starting graceful shutdown now...")

	// Stop background producers first so they cannot submit new tasks during
	// the gRPC drain window.
	if s.operationRunDispatcher != nil {
		s.operationRunDispatcher.Stop()
		log.Info().Msg("Operation run dispatcher stopped")
	}

	if s.taskScheduleDispatcher != nil {
		s.taskScheduleDispatcher.Stop()
		log.Info().Msg("Task schedule dispatcher stopped")
	}

	if s.sched != nil {
		s.sched.Stop(false) //nolint
		log.Info().Msg("System job scheduler stopped")
	}

	if s.grpcServer != nil {
		s.grpcServer.GracefulStop()
		log.Info().Msg("gRPC server stopped")
	}

	if s.taskManager != nil {
		s.taskManager.Stop(ctx)
		log.Info().Msg("Task manager stopped")
	}

	if s.inventoryManager != nil {
		s.inventoryManager.Stop(ctx)
		log.Info().Msg("Inventory manager stopped")
	}

	// Rule resolver has no cleanup needed (cache is GC'd automatically)
	if s.session != nil {
		s.session.Close()
		log.Info().Msg("Database session closed")
	}

	log.Info().Msg("Graceful shutdown completed")
}

// certOption resolves the TLS configuration for the gRPC server listener.
// If explicit certificate paths are set in the config they take precedence;
// otherwise CERTDIR / the k8s SPIFFE default is used. The service refuses to
// start without certificates unless ALLOW_INSECURE_GRPC=true is set.
func (s *Service) certOption() grpc.ServerOption {
	tlsConfig, source, err := certs.ResolveServer(s.conf.CertConfig)
	if err != nil {
		if errors.Is(err, certs.ErrNotPresent) {
			if os.Getenv("ALLOW_INSECURE_GRPC") == "true" {
				log.Warn().Msg("TLS certs not present, running without mTLS")
				return grpc.EmptyServerOption{}
			}
			log.Fatal().Msg("TLS certificates required but not found; set ALLOW_INSECURE_GRPC=true for local development")
		}
		log.Fatal().Msg(err.Error())
	}

	log.Info().Msgf("Using certificates from %s", source)
	return grpc.Creds(credentials.NewTLS(tlsConfig))
}

func (s *Service) startScheduler(ctx context.Context) error {
	log.Info().Msg("Starting system job scheduler")

	if s.taskManager == nil {
		return fmt.Errorf("task manager not initialized")
	}

	sched := scheduler.New()

	// Create and register the inventory sync job
	invJob, err := inventorysync.New(
		ctx,
		&s.conf.DBConf,
		s.conf.ProviderRegistry,
		s.conf.FlowConfig,
	)
	if err != nil {
		return fmt.Errorf("failed to create inventory sync job: %w", err)
	}

	if invJob != nil {
		invTrigger, err := schedtypes.NewIntervalTrigger(s.conf.FlowConfig.InventoryRunFrequency)
		if err != nil {
			return fmt.Errorf("invalid inventory sync interval: %w", err)
		}
		if err := sched.Schedule(invJob, invTrigger, schedtypes.Skip); err != nil {
			return fmt.Errorf("failed to schedule inventory sync job: %w", err)
		}
	}

	// Create and register the leak detection job
	leakJob, err := leakdetection.New(
		ctx,
		&s.conf.DBConf,
		s.taskManager,
		s.conf.ProviderRegistry,
		s.conf.FlowConfig,
	)
	if err != nil {
		return fmt.Errorf("failed to create leak detection job: %w", err)
	}

	if leakJob != nil {
		leakTrigger, err := schedtypes.NewIntervalTrigger(s.conf.FlowConfig.LeakDetectionInterval)
		if err != nil {
			return fmt.Errorf("invalid leak detection interval: %w", err)
		}
		if err := sched.Schedule(leakJob, leakTrigger, schedtypes.Skip); err != nil {
			return fmt.Errorf("failed to schedule leak detection job: %w", err)
		}
	}

	if err := sched.Start(ctx); err != nil {
		return fmt.Errorf("failed to start system job scheduler: %w", err)
	}

	s.sched = sched

	log.Info().Msg("System job scheduler started")

	return nil
}
