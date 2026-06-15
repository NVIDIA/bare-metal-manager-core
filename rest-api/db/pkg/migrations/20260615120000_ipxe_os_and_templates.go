/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package migrations

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/NVIDIA/infra-controller/rest-api/db/pkg/db/model"
	"github.com/uptrace/bun"
)

// 20260615120000_ipxe_os_and_templates
//
// Introduces the iPXE Template + OS Template support in REST:
//   - Global `ipxe_template` table, keyed by the stable template UUID assigned
//     by nico-core (the same UUID is used on both sides).
//   - `ipxe_template_site_association` (ITSA) table tracking which sites
//     currently report each global template.
//   - iPXE-template related columns on `operating_system` and
//     `operating_system_site_association`.
func init() {
	Migrations.MustRegister(func(ctx context.Context, db *bun.DB) error {
		tx, terr := db.BeginTx(ctx, &sql.TxOptions{})
		if terr != nil {
			handlePanic(terr, "failed to begin transaction")
		}

		// ── iPXE Template table (global) ─────────────────────────────────

		_, err := tx.NewCreateTable().Model((*model.IpxeTemplate)(nil)).IfNotExists().Exec(ctx)
		handleError(tx, err)

		_, err = tx.Exec("ALTER TABLE ipxe_template DROP CONSTRAINT IF EXISTS ipxe_template_name_key")
		handleError(tx, err)
		_, err = tx.Exec("ALTER TABLE ipxe_template ADD CONSTRAINT ipxe_template_name_key UNIQUE (name)")
		handleError(tx, err)

		_, err = tx.Exec("DROP INDEX IF EXISTS ipxe_template_name_idx")
		handleError(tx, err)
		_, err = tx.Exec("CREATE INDEX ipxe_template_name_idx ON ipxe_template(name)")
		handleError(tx, err)

		_, err = tx.Exec("DROP INDEX IF EXISTS ipxe_template_scope_idx")
		handleError(tx, err)
		_, err = tx.Exec("CREATE INDEX ipxe_template_scope_idx ON ipxe_template(scope)")
		handleError(tx, err)

		_, err = tx.Exec("DROP INDEX IF EXISTS ipxe_template_created_idx")
		handleError(tx, err)
		_, err = tx.Exec("CREATE INDEX ipxe_template_created_idx ON ipxe_template(created)")
		handleError(tx, err)

		_, err = tx.Exec("DROP INDEX IF EXISTS ipxe_template_updated_idx")
		handleError(tx, err)
		_, err = tx.Exec("CREATE INDEX ipxe_template_updated_idx ON ipxe_template(updated)")
		handleError(tx, err)

		// ── iPXE Template ↔ Site association ─────────────────────────────

		_, err = tx.NewCreateTable().Model((*model.IpxeTemplateSiteAssociation)(nil)).IfNotExists().Exec(ctx)
		handleError(tx, err)

		_, err = tx.Exec(`
			ALTER TABLE ipxe_template_site_association
			DROP CONSTRAINT IF EXISTS ipxe_template_site_association_template_id_site_id_key
		`)
		handleError(tx, err)
		_, err = tx.Exec(`
			ALTER TABLE ipxe_template_site_association
			ADD CONSTRAINT ipxe_template_site_association_template_id_site_id_key
			UNIQUE (ipxe_template_id, site_id)
		`)
		handleError(tx, err)

		_, err = tx.Exec("DROP INDEX IF EXISTS itsa_ipxe_template_id_idx")
		handleError(tx, err)
		_, err = tx.Exec("CREATE INDEX itsa_ipxe_template_id_idx ON ipxe_template_site_association(ipxe_template_id)")
		handleError(tx, err)

		_, err = tx.Exec("DROP INDEX IF EXISTS itsa_site_id_idx")
		handleError(tx, err)
		_, err = tx.Exec("CREATE INDEX itsa_site_id_idx ON ipxe_template_site_association(site_id)")
		handleError(tx, err)

		// ── Operating System: iPXE definition columns ────────────────────

		_, err = tx.Exec("ALTER TABLE operating_system ADD COLUMN IF NOT EXISTS ipxe_template_id TEXT NULL")
		handleError(tx, err)

		_, err = tx.Exec("ALTER TABLE operating_system ADD COLUMN IF NOT EXISTS ipxe_template_parameters JSONB NULL")
		handleError(tx, err)

		_, err = tx.Exec("ALTER TABLE operating_system ADD COLUMN IF NOT EXISTS ipxe_template_artifacts JSONB NULL")
		handleError(tx, err)

		_, err = tx.Exec("ALTER TABLE operating_system ADD COLUMN IF NOT EXISTS ipxe_template_definition_hash TEXT NULL")
		handleError(tx, err)

		// controller_operating_system_id is no longer needed: the primary key is the same on
		// both sides, so drop the column and its index if they still exist.
		_, err = tx.Exec("DROP INDEX IF EXISTS operating_system_controller_os_id_idx")
		handleError(tx, err)

		_, err = tx.Exec("ALTER TABLE operating_system DROP COLUMN IF EXISTS controller_operating_system_id")
		handleError(tx, err)

		// ── Operating System: scope column ───────────────────────────────

		_, err = tx.Exec("ALTER TABLE operating_system ADD COLUMN IF NOT EXISTS ipxe_os_scope TEXT NULL")
		handleError(tx, err)

		// ── Operating System Site Association: controller state ──────────

		_, err = tx.Exec("ALTER TABLE operating_system_site_association ADD COLUMN IF NOT EXISTS controller_state TEXT NULL")
		handleError(tx, err)

		// ── Backfill ipxe_os_scope for existing iPXE-type OS records ────
		//
		// Tenant-owned raw iPXE → Global (preserves legacy behavior: tenant
		// can use it for any Instance at any accessible site).
		// Provider-owned iPXE (from nico-core inventory) → Local (single
		// site, bidirectional sync).
		// Image-type OS entries are left as NULL since scope does not apply.

		_, err = tx.Exec(`
			UPDATE operating_system
			SET ipxe_os_scope = 'Global'
			WHERE ipxe_os_scope IS NULL
			  AND type = 'iPXE'
			  AND tenant_id IS NOT NULL
			  AND deleted IS NULL
		`)
		handleError(tx, err)

		terr = tx.Commit()
		if terr != nil {
			handlePanic(terr, "failed to commit transaction")
		}

		fmt.Print(" [up migration] ")
		return nil
	}, func(ctx context.Context, db *bun.DB) error {
		fmt.Print(" [down migration] No action taken")
		return nil
	})
}
