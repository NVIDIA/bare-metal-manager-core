-- Add migration script here
ALTER TABLE spdm_machine_devices_attestation
ADD COLUMN IF NOT EXISTS completed_at timestamptz,
ADD COLUMN IF NOT EXISTS started_at timestamptz NOT NULL,
ADD COLUMN IF NOT EXISTS cancelled_at timestamptz;

ALTER TABLE spdm_machine_attestation_history
ADD COLUMN IF NOT EXISTS device_id VARCHAR NOT NULL;

ALTER TABLE spdm_machine_attestation_history
RENAME TO spdm_device_attestation_history;