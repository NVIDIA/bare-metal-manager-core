-- MAC addresses that the DHCP server should ignore.
--
-- When a BMC is decommissioned its MAC is inserted here so the DHCP server:
--   * silently drops DHCPDISCOVER packets from the address, and
--   * responds with DHCPNAK to any outstanding DHCPREQUEST.
--
-- machine_id is nullable: a MAC may be marked ignored before or after the
-- corresponding machine record is removed from the database.
CREATE TABLE ignored_macs (
    mac_address  macaddr     NOT NULL PRIMARY KEY,
    machine_id   uuid,
    reason       text        NOT NULL DEFAULT '',
    created_at   timestamptz NOT NULL DEFAULT now()
);
