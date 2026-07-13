// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/NVIDIA/infra-controller/rest-api/db/pkg/db/model"
	"github.com/google/uuid"
	"github.com/uptrace/bun"
)

type legacyTenantSiteConfigRow struct {
	bun.BaseModel `bun:"table:tenant_site,alias:ts"`
	ID            uuid.UUID              `bun:"id,pk,type:uuid"`
	Config        map[string]interface{} `bun:"config,type:jsonb"`
}

func tenantSiteConfigFromLegacy(raw map[string]interface{}) model.TenantSiteConfig {
	cfg := model.TenantSiteConfig{}
	if raw == nil {
		return cfg
	}

	if v, ok := raw["targetedInstanceCreation"]; ok {
		if enabled, ok := v.(bool); ok {
			cfg.TargetedInstanceCreation = &enabled
		}
	}

	return cfg
}

func normalizeTenantSiteConfigUpMigration(ctx context.Context, tx bun.Tx) error {
	legacyRows := []legacyTenantSiteConfigRow{}
	err := tx.NewSelect().Model(&legacyRows).Scan(ctx)
	if err != nil {
		return err
	}

	for _, row := range legacyRows {
		normalized := tenantSiteConfigFromLegacy(row.Config)
		_, err = tx.NewUpdate().Model(&model.TenantSite{
			ID:     row.ID,
			Config: normalized,
		}).Column("config").WherePK().Exec(ctx)
		if err != nil {
			return err
		}
	}

	return nil
}

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
			  AND COALESCE(t.config->>'targetedInstanceCreation', 'false') = 'true'
		`)
		handleError(tx, err)

		_, err = tx.Exec(`
			UPDATE tenant_account ta
			SET config = jsonb_set(COALESCE(ta.config, '{}'::jsonb), '{enableSshAccess}', 'true'::jsonb, true)
			FROM tenant t
			WHERE ta.tenant_id = t.id
			  AND COALESCE(t.config->>'enableSshAccess', 'false') = 'true'
			  AND COALESCE(ta.config->>'enableSshAccess', 'false') != 'true'
		`)
		handleError(tx, err)

		err = normalizeTenantSiteConfigUpMigration(ctx, tx)
		handleError(tx, err)

		_, err = tx.NewDropColumn().Model((*model.Tenant)(nil)).Column("config").Exec(ctx)
		handleError(tx, err)

		terr = tx.Commit()
		if terr != nil {
			handlePanic(terr, "failed to commit transaction")
		}

		fmt.Print(" [up migration] Moved tenant capabilities to tenant_account.config, normalized tenant_site.config, and dropped tenant.config")
		return nil
	}, func(ctx context.Context, db *bun.DB) error {
		fmt.Print(" [down migration] tenant_account.config")
		return nil
	})
}
