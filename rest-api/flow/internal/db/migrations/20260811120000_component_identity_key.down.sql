-- SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
-- SPDX-License-Identifier: Apache-2.0

-- The duplicate host BMC rows the up migration deleted are not restored:
-- the bmc table has no soft-delete and the rows carried no state beyond the
-- MAC/IP the mirror re-derives from Core.
--
-- Both SET NOT NULL statements fail if any row mirrored while the column was
-- nullable still carries a NULL. Such rows need a manufacturer / serial (or
-- deletion) before the schema can be narrowed again.
ALTER TABLE rack
    ALTER COLUMN serial_number SET NOT NULL;

ALTER TABLE component
    ALTER COLUMN manufacturer SET NOT NULL,
    ALTER COLUMN serial_number SET NOT NULL;

DROP INDEX IF EXISTS bmc_one_host_per_component_idx;

DROP INDEX IF EXISTS component_identity_key_idx;

ALTER TABLE component
    DROP COLUMN identity_key;
