ALTER TABLE machine_validation_tests
    ADD COLUMN full_host_approved BOOLEAN NOT NULL DEFAULT FALSE;
