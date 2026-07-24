ALTER TABLE site_explorer_run_status
    ADD COLUMN endpoint_explorations_skipped bigint NOT NULL DEFAULT 0,
    ADD CONSTRAINT site_explorer_run_status_endpoint_explorations_skipped_non_negative
        CHECK (endpoint_explorations_skipped >= 0);
