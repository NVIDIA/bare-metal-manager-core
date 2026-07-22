-- BMC MAC addresses that must be hidden from Site Explorer discovery, DHCP, or
-- both. dhcp_discover_suppressed_at records the first DHCPDISCOVER ignored while
-- DHCP suppression is active, used to confirm the BMC has withdrawn its lease.
CREATE TABLE ignored_bmc_macs (
    bmc_mac_address MACADDR PRIMARY KEY,
    reason TEXT NOT NULL,
    suppress_site_explorer BOOLEAN NOT NULL DEFAULT FALSE,
    suppress_dhcp BOOLEAN NOT NULL DEFAULT FALSE,
    dhcp_discover_suppressed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
