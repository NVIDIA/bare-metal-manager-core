// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	cdb "github.com/NVIDIA/infra-controller-rest/db/pkg/db"
	"github.com/NVIDIA/infra-controller-rest/flow/internal/db/migrations"
)

var (
	rollBack string

	// migrateCmd is the subcommand that runs database migrations.
	migrateCmd = &cobra.Command{
		Use:   "migrate",
		Short: "Run the db migration",
		Long:  `Run the db migration`,
		Run: func(cmd *cobra.Command, args []string) {
			doMigration()
		},
	}
)

func init() {
	dbCmd.AddCommand(migrateCmd)

	migrateCmd.Flags().StringVarP(&rollBack, "rollback", "r", "", "Roll back the schema to the way it was at the specified time.  This is the application time, not from the ID.  Format 2006-01-02T15:04:05")
}

// doMigration connects to the database and runs pending migrations. If the
// --rollback flag is set, it rolls back the schema to the specified time
// instead of migrating forward.
func doMigration() {
	dbConf, err := cdb.ConfigFromEnv()
	if err != nil {
		log.Fatal().Msgf("Unable to build database configuration: %v", err)
	}

	ctx := context.Background()

	session, err := cdb.NewSessionFromConfig(ctx, dbConf)
	if err != nil {
		log.Fatal().Msgf("failed to connect to DB: %v", err)
	}
	defer session.Close()

	if rollBack != "" {
		rollbackTime, err := time.Parse("2006-01-02T15:04:05", rollBack)
		if err != nil {
			log.Fatal().Msg("Bad rollback time")
		}
		if err := migrations.RollbackWithDB(ctx, session.DB, rollbackTime); err != nil {
			log.Fatal().Msgf("Failed to roll back migrations: %v", err)
		}
	} else {
		if err := migrations.MigrateWithDB(ctx, session.DB); err != nil {
			log.Fatal().Msgf("Failed to run migrations: %v", err)
		}
	}
}
