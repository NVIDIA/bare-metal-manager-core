-- Add migration script here
ALTER TABLE machines
    ADD COLUMN last_reboot_requested_time TIMESTAMPTZ NULL
;

