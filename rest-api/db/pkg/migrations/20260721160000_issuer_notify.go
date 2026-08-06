// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/uptrace/bun"
)

func init() {
	Migrations.MustRegister(func(ctx context.Context, db *bun.DB) error {
		tx, terr := db.BeginTx(ctx, &sql.TxOptions{})
		if terr != nil {
			handlePanic(terr, "failed to begin transaction")
		}

		// Wake every API replica the moment an issuer row is committed, so a
		// change converges in sub-second time instead of waiting for the
		// periodic reload (which stays as the correctness floor).
		//
		// The payload is empty on purpose: a notification only means "the table
		// changed, re-read it". The replica responds by rebuilding from
		// committed state, so nothing needs to be carried in the message and
		// there is no ordering, dedupe, or lost-notification handling to get
		// wrong.
		_, err := tx.Exec(`
			CREATE OR REPLACE FUNCTION notify_issuer_changed() RETURNS trigger AS $$
			BEGIN
				PERFORM pg_notify('issuer_changed', '');
				RETURN NULL;
			END;
			$$ LANGUAGE plpgsql`)
		handleError(tx, err)

		// FOR EACH STATEMENT, not FOR EACH ROW: one UPDATE touching many rows
		// wakes each replica once rather than once per row.
		_, err = tx.Exec("DROP TRIGGER IF EXISTS issuer_changed_tg ON issuer")
		handleError(tx, err)

		_, err = tx.Exec(`
			CREATE TRIGGER issuer_changed_tg
			AFTER INSERT OR UPDATE OR DELETE ON issuer
			FOR EACH STATEMENT EXECUTE FUNCTION notify_issuer_changed()`)
		handleError(tx, err)

		terr = tx.Commit()
		if terr != nil {
			handlePanic(terr, "failed to commit transaction")
		}
		fmt.Print(" [up migration] ")
		return nil
	}, func(ctx context.Context, db *bun.DB) error {
		return nil
	})
}
