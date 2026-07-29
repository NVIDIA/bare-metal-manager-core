-- BMC MAC addresses that NICo is actively suppressing during decommissioning.
--
-- suppress_site_explorer: Site Explorer must not start new exploration for this
--   MAC. Once it has drained all queued/in-flight work it writes
--   site_explorer_suppressed_at as an acknowledgement.
--
-- suppress_dhcp: the DHCP server must return DHCPNAK to DHCPREQUEST and no
--   offer to DHCPDISCOVER. On the first suppressed DHCPDISCOVER it writes
--   dhcp_discover_suppressed_at, proving the BMC DHCP client has returned to
--   the INIT state.
CREATE TABLE ignored_bmc_macs (
    bmc_mac_address             macaddr     NOT NULL PRIMARY KEY,
    reason                      text        NOT NULL,
    suppress_site_explorer      boolean     NOT NULL DEFAULT FALSE,
    site_explorer_suppressed_at timestamptz,
    suppress_dhcp               boolean     NOT NULL DEFAULT FALSE,
    dhcp_discover_suppressed_at timestamptz,
    created_at                  timestamptz NOT NULL DEFAULT now(),
    updated_at                  timestamptz NOT NULL DEFAULT now()
);
