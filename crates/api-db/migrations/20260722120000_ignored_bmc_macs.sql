-- BMC MAC addresses that must be hidden from Site Explorer discovery, DHCP, or
-- both. The acknowledgement timestamps record when each subsystem observed
-- active suppression and completed the corresponding handoff.
CREATE TABLE ignored_bmc_macs (
    bmc_mac_address MACADDR PRIMARY KEY,
    reason TEXT NOT NULL,
    suppress_site_explorer BOOLEAN NOT NULL DEFAULT FALSE,
    site_explorer_suppressed_at TIMESTAMPTZ,
    suppress_dhcp BOOLEAN NOT NULL DEFAULT FALSE,
    dhcp_discover_suppressed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
