-- Track the RMS firmware-object job ID dispatched via --bypass-state-controller.
-- When nico-api is restarted the in-memory firmware_jobs map is lost; this column
-- lets get_firmware_status fall back to the DB and keep querying RMS correctly.
ALTER TABLE machines
    ADD COLUMN rms_firmware_object_job_id TEXT;
