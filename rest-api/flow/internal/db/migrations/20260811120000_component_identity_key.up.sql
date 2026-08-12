-- SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
-- SPDX-License-Identifier: Apache-2.0

-- identity_key is the identity the expected-inventory mirror matches a Core row
-- against. The schema only enforces that it is unique; what composes the value
-- is the mirror's to define.
ALTER TABLE component
    ADD COLUMN identity_key character varying;

CREATE UNIQUE INDEX component_identity_key_idx
    ON component (identity_key)
    WHERE identity_key IS NOT NULL;

-- A component has at most one host BMC. Delete the duplicates an ingestion bug
-- allowed so the index can be created; the lowest MAC survives.
DELETE FROM bmc a
    USING bmc b
    WHERE a.type = 'Host'
      AND b.type = 'Host'
      AND a.component_id = b.component_id
      AND a.mac_address > b.mac_address;

CREATE UNIQUE INDEX bmc_one_host_per_component_idx
    ON bmc (component_id)
    WHERE type = 'Host';

-- manufacturer and serial_number are descriptive metadata now, not identity.
-- UNIQUE (manufacturer, serial_number) stays useful because Postgres treats
-- NULLs as distinct: an incomplete row occupies no slot.
ALTER TABLE component
    ALTER COLUMN manufacturer DROP NOT NULL,
    ALTER COLUMN serial_number DROP NOT NULL;

ALTER TABLE rack
    ALTER COLUMN manufacturer DROP NOT NULL,
    ALTER COLUMN serial_number DROP NOT NULL;
