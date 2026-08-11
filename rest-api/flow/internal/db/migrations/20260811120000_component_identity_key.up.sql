-- SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
-- SPDX-License-Identifier: Apache-2.0

-- Give component an explicit identity column so the expected-inventory mirror
-- has one authoritative match key instead of deriving identity from whichever
-- descriptive columns happen to be populated.
--
-- identity_key holds the value of the current derivation (see
-- identityKeyForSpec). The derivation is expected to change; the schema
-- deliberately says nothing about what composes the value so that a change
-- is a backfill rather than a migration of constraints and match logic.
--
-- Nullable, with a partial unique index, because the three ingestion gRPC
-- paths (CreateExpectedRack, AddComponent, PatchRack) create components
-- outside the mirror and have no derivation to apply.
--
-- Unique globally rather than per type. identity_key is a denormalised copy of
-- a value that is already unique at its source -- today bmc.mac_address, a
-- primary key -- but the copy inherits none of that, so only the index makes
-- the column carry the guarantee its value already has. Scoping it by type
-- would instead permit one MAC under two component types, which no valid
-- inventory can produce; a Core payload that reports one aborts the type's
-- reconciliation with a named constraint error, which is the right response to
-- input that broken and far easier to spot than the component the mirror would
-- otherwise duplicate.
ALTER TABLE component
    ADD COLUMN identity_key character varying;

CREATE UNIQUE INDEX component_identity_key_idx
    ON component (identity_key)
    WHERE identity_key IS NOT NULL;

-- The derivation reads a component's host BMC, so the 1:1 it assumes has to
-- be real. Extra type='Host' rows are an ingestion bug that
-- planBMCReconciliation already hard-deletes on the next mirror cycle; this
-- brings that cleanup forward so the index can be created. Keeping the lowest
-- MAC is arbitrary but deterministic — the mirror re-attaches whichever MAC
-- Core reports on the next cycle regardless of which row survives here.
DELETE FROM bmc a
    USING bmc b
    WHERE a.type = 'Host'
      AND b.type = 'Host'
      AND a.component_id = b.component_id
      AND a.mac_address > b.mac_address;

CREATE UNIQUE INDEX bmc_one_host_per_component_idx
    ON bmc (component_id)
    WHERE type = 'Host';

-- With identity in its own column, manufacturer and serial are descriptive
-- metadata, so a Core site whose chassis labels are incomplete no longer has
-- its rows skipped. UNIQUE (manufacturer, serial_number) stays: Postgres
-- treats NULLs as distinct, so incomplete rows simply stop occupying a slot,
-- and GetRackInfoBySerial / GetComponentInfoBySerial keep their
-- at-most-one-match guarantee for fully-labelled rows.
ALTER TABLE component
    ALTER COLUMN manufacturer DROP NOT NULL,
    ALTER COLUMN serial_number DROP NOT NULL;

ALTER TABLE rack
    ALTER COLUMN serial_number DROP NOT NULL;
