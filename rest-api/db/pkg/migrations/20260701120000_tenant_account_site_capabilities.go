// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/NVIDIA/infra-controller/rest-api/db/pkg/db/model"
	"github.com/uptrace/bun"
)

func init() {
	Migrations.MustRegister(func(ctx context.Context, db *bun.DB) error {
		tx, terr := db.BeginTx(ctx, &sql.TxOptions{})
		if terr != nil {
			handlePanic(terr, "failed to begin transaction")
		}

		_, err := tx.NewAddColumn().Model((*model.TenantAccount)(nil)).IfNotExists().
			ColumnExpr("config JSONB NOT NULL DEFAULT '{}'::jsonb").Exec(ctx)
		handleError(tx, err)

		_, err = tx.Exec(`
			UPDATE tenant_account ta
			SET config = jsonb_set(COALESCE(ta.config, '{}'::jsonb), '{targetedInstanceCreation}', 'true'::jsonb, true)
			FROM tenant t
			WHERE ta.tenant_id = t.id
			  AND ta.status = ?
			  AND COALESCE(t.config->>'targetedInstanceCreation', 'false') = 'true'
		`, model.TenantAccountStatusReady)
		handleError(tx, err)

		terr = tx.Commit()
		if terr != nil {
			handlePanic(terr, "failed to commit transaction")
		}

		fmt.Print(" [up migration] Added tenant_account.config and backfilled targetedInstanceCreation from tenant.config")
		return nil
	}, func(ctx context.Context, db *bun.DB) error {
		fmt.Print(" [down migration] tenant_account.config")
		return nil
	})
}
