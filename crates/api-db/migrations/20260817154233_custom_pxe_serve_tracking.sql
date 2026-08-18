-- Track how often the tenant's iPXE script has been served for the provisioning
-- boot currently being awaited, so the machine controller can tell a successful
-- install from a host that keeps returning to network boot.
--
-- Both columns are reset when a new provisioning boot is armed, so they describe
-- the attempt in flight rather than the instance's lifetime. The CHECK keeps the
-- count decodable as an unsigned value in the instance snapshot.
ALTER TABLE instances
ADD COLUMN custom_pxe_serve_count INTEGER NOT NULL DEFAULT 0
    CHECK (custom_pxe_serve_count >= 0),
ADD COLUMN custom_pxe_last_served_at TIMESTAMPTZ;
