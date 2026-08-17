ALTER TABLE machine_validation_tests
    ADD COLUMN plugin JSONB;

ALTER TABLE machine_validation_run_items
    ADD COLUMN plugin JSONB;
