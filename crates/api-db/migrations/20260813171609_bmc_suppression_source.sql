-- Give each suppression requester its own row so independent workflows can
-- suppress and clear without racing on a shared (mac, subsystem) key.
-- A subsystem treats a MAC as suppressed while any source still has a row.
ALTER TABLE bmc_suppressions
    ADD COLUMN source TEXT NOT NULL DEFAULT 'decommissioning'
        CHECK (source IN ('decommissioning'));

ALTER TABLE bmc_suppressions
    ALTER COLUMN source DROP DEFAULT;

ALTER TABLE bmc_suppressions
    DROP CONSTRAINT bmc_suppressions_pkey;

ALTER TABLE bmc_suppressions
    ADD PRIMARY KEY (bmc_mac_address, subsystem, source);
