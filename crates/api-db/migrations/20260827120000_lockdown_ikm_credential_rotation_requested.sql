-- Add lockdown_ikm_credential_rotation_requested column to machines table.
-- lockdown_ikm_credential_rotation_requested: an operator "force-converge this
-- host's SuperNIC lockdown keys now" escape hatch. Set on the host machine that
-- owns the SuperNICs. When true, the machine state controller enters
-- RotatingNicLockdown for an otherwise-idle host and rekeys every lagging SVPC
-- card to the site-wide target IKM, bypassing the passive site-wide gate
-- (lockdown_ikm_rotation_enabled) and each card's backoff quarantine. The rekey
-- still never runs under active tenancy, so a forced request against a busy host
-- is honored on its next idle window. Mirrors machines.bmc_credential_rotation_requested.

ALTER TABLE machines
    ADD COLUMN lockdown_ikm_credential_rotation_requested BOOLEAN NOT NULL DEFAULT false;
