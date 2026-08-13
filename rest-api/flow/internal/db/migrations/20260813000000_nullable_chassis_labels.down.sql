-- SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
-- SPDX-License-Identifier: Apache-2.0

-- The empty string is how a missing label was represented while these columns
-- were NOT NULL, so it is the inverse of the model's nullzero mapping. Rows
-- that collide on a unique constraint once collapsed to it must be resolved by
-- hand before this migration can complete.
UPDATE component SET manufacturer = '' WHERE manufacturer IS NULL;
UPDATE component SET serial_number = '' WHERE serial_number IS NULL;

ALTER TABLE component
    ALTER COLUMN manufacturer SET NOT NULL,
    ALTER COLUMN serial_number SET NOT NULL;

UPDATE rack SET manufacturer = '' WHERE manufacturer IS NULL;
UPDATE rack SET serial_number = '' WHERE serial_number IS NULL;

ALTER TABLE rack
    ALTER COLUMN manufacturer SET NOT NULL,
    ALTER COLUMN serial_number SET NOT NULL;
