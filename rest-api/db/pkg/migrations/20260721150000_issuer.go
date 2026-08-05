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

		// The `issuer` table is a persistent, runtime-editable mirror of the
		// static ConfigMap `IssuerConfig` shape. Each row is one external JWT
		// issuer; `claim_mappings` is the same JSONB array the in-memory
		// JwksConfig already holds. DB issuers are loaded into the exact same
		// auth registry as ConfigMap issuers; static ConfigMap issuers always
		// win (a DB row with a conflicting URL/name is rejected/skipped).
		_, err := tx.Exec(`
			CREATE TABLE IF NOT EXISTS issuer (
				id     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
				name   TEXT NOT NULL,
				origin                           TEXT NOT NULL DEFAULT 'custom',
				issuer_url                       TEXT NOT NULL,
				jwks_url                         TEXT NOT NULL,
				jwks_timeout                     TEXT NOT NULL DEFAULT '5s',
				service_account                  BOOLEAN NOT NULL DEFAULT false,
				audiences      TEXT[] NOT NULL DEFAULT '{}',
				scopes         TEXT[] NOT NULL DEFAULT '{}',
				claim_mappings JSONB NOT NULL DEFAULT '[]',
				created_at                       TIMESTAMPTZ NOT NULL DEFAULT current_timestamp,
				updated_at                       TIMESTAMPTZ NOT NULL DEFAULT current_timestamp,
				created_by                       UUID,
				updated_by                       UUID,
				deleted                          TIMESTAMPTZ
			)`)
		handleError(tx, err)

		// issuer_url is the token `iss` and the registry key: unique among live rows.
		_, err = tx.Exec("CREATE UNIQUE INDEX IF NOT EXISTS issuer_issuer_url_idx ON public.issuer(issuer_url) WHERE deleted IS NULL")
		handleError(tx, err)

		// name mirrors the ConfigMap uniqueness rule.
		_, err = tx.Exec("CREATE UNIQUE INDEX IF NOT EXISTS issuer_name_idx ON public.issuer(name) WHERE deleted IS NULL")
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
