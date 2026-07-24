// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/uptrace/bun"
)

// Drops the operating_system.ipxe_os_scope column. The Local/Global/Limited scope
// concept is removed: synchronization direction for Templated iPXE OS definitions is
// now derived from the number of associated sites (a single site is bidirectional /
// core-driven, more than one makes carbide-rest the source of truth), so the stored
// scope is no longer needed.
func init() {
	Migrations.MustRegister(func(ctx context.Context, db *bun.DB) error {
		tx, terr := db.BeginTx(ctx, &sql.TxOptions{})
		if terr != nil {
			handlePanic(terr, "failed to begin transaction")
		}

		_, err := tx.ExecContext(ctx, `ALTER TABLE operating_system DROP COLUMN IF EXISTS ipxe_os_scope`)
		handleError(tx, err)

		terr = tx.Commit()
		if terr != nil {
			handlePanic(terr, "failed to commit transaction")
		}

		fmt.Print(" [up migration] Dropped 'ipxe_os_scope' column from 'operating_system' table successfully. ")
		return nil
	}, func(ctx context.Context, db *bun.DB) error {
		tx, terr := db.BeginTx(ctx, &sql.TxOptions{})
		if terr != nil {
			handlePanic(terr, "failed to begin transaction")
		}

		// Structural rollback only: the column is restored as a nullable TEXT column.
		// The original per-row scope values cannot be recovered.
		_, err := tx.ExecContext(ctx, `ALTER TABLE operating_system ADD COLUMN IF NOT EXISTS ipxe_os_scope TEXT NULL`)
		handleError(tx, err)

		terr = tx.Commit()
		if terr != nil {
			handlePanic(terr, "failed to commit transaction")
		}

		fmt.Print(" [down migration] Restored 'ipxe_os_scope' column on 'operating_system' table (values not restored). ")
		return nil
	})
}
