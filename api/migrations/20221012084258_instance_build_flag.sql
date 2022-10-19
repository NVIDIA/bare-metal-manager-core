-- Add migration script here
ALTER TABLE IF EXISTS instances
    ADD COLUMN use_custom_pxe_on_boot bool NOT NULL DEFAULT false
;
