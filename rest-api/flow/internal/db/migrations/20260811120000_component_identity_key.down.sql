-- SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
-- SPDX-License-Identifier: Apache-2.0

-- The host BMC rows the up migration deleted are not restored.
--
-- Both SET NOT NULL statements fail if a row still carries a NULL, which needs
-- a manufacturer / serial (or deletion) before the schema can be narrowed.
ALTER TABLE rack
    ALTER COLUMN manufacturer SET NOT NULL,
    ALTER COLUMN serial_number SET NOT NULL;

ALTER TABLE component
    ALTER COLUMN manufacturer SET NOT NULL,
    ALTER COLUMN serial_number SET NOT NULL;

DROP INDEX IF EXISTS bmc_one_host_per_component_idx;

DROP INDEX IF EXISTS component_identity_key_idx;

ALTER TABLE component
    DROP COLUMN identity_key;
