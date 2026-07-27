-- Track the selected boot-interface generation separately from the interface
-- row so an assigned-host authorization cannot be reused after A -> B -> A.
ALTER TABLE machines
    ADD COLUMN boot_interface_selection_version VARCHAR(64)
        NOT NULL DEFAULT 'V1-T1666644937952267',
    ADD COLUMN boot_config_synchronization_requested JSONB;
