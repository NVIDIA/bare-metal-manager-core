-- Durable backend job handle for an accepted NVOS password-rotation request, so
-- the controller can resume polling it after its own restart. Nullable: a target
-- staged before dispatch has no job ID yet.
--
-- This is a resume hint and anti-stale token, never proof of success: promotion
-- to converged requires an authoritative credential readback, not a completed
-- job (see record_device_rotation_reconciled_to_target). A late or recycled job
-- ID cannot cross-attach to a newer operation because every transition also
-- matches the monotonic rotate_attempts CAS token, not the job ID alone.

ALTER TABLE device_credential_rotation
    ADD COLUMN rotate_job_id text;
