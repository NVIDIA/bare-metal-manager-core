DROP VIEW IF EXISTS machine_dhcp_responses;
ALTER TABLE network_segments DROP COLUMN subdomain;

CREATE VIEW machine_dhcp_responses AS (
    SELECT m.id as machine_id, n.id as segment_id, mi.mac_address, mi.address_ipv4, mi.address_ipv6,  n.mtu, n.gateway_ipv4, m.fqdn
    FROM machines m
    INNER JOIN machine_interfaces mi ON mi.machine_id = m.id
    INNER JOIN network_segments n ON mi.segment_id = n.id
);

ALTER TABLE network_segments ADD COLUMN subdomain_id uuid NOT NULL;

ALTER TABLE network_segments ADD CONSTRAINT network_segments_domain_fkey FOREIGN KEY (subdomain_id) REFERENCES domains(id);

