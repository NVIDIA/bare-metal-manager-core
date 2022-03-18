DROP VIEW IF EXISTS machine_dhcp_responses;
ALTER TABLE network_segments DROP COLUMN subdomain;
ALTER TABLE network_segments ADD COLUMN subdomain_id uuid;

ALTER TABLE network_segments ADD FOREIGN KEY (subdomain_id) REFERENCES domains(id);

ALTER TABLE machines DROP COLUMN fqdn;
ALTER TABLE machine_interfaces ADD COLUMN domain_id uuid;
ALTER TABLE machine_interfaces ADD COLUMN hostname VARCHAR(63) NOT NULL;
ALTER TABLE machine_interfaces ADD FOREIGN KEY (domain_id) REFERENCES domains(id);
ALTER TABLE machine_interfaces ADD primary_interface bool NOT NULL;

ALTER TABLE machine_interfaces ADD CONSTRAINT fqdn_must_be_unique UNIQUE (domain_id, hostname);
ALTER TABLE machine_interfaces ADD CONSTRAINT one_primary_interface UNIQUE (machine_id, primary_interface);

CREATE VIEW fqdn_view AS (
    SELECT hostname, domain_id
    FROM machine_interfaces
    INNER JOIN domains ON domains.id = machine_interfaces.domain_id
);


CREATE VIEW machine_dhcp_responses AS (
    SELECT m.id as machine_id, n.id as segment_id, mi.mac_address, mi.address_ipv4, mi.address_ipv6, n.subdomain_id, n.mtu, n.gateway_ipv4
    FROM machine_interfaces m
    INNER JOIN machine_interfaces mi ON mi.machine_id = m.id
    INNER JOIN network_segments n ON mi.segment_id = n.id
    INNER JOIN fqdn_view f on mi.domain_id = m.domain_id
);