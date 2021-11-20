DROP TABLE IF EXISTS network_segments;
CREATE TABLE network_segments(
	id uuid DEFAULT gen_random_uuid() NOT NULL PRIMARY KEY,
	name VARCHAR NOT NULL UNIQUE,
	subdomain VARCHAR NOT NULL,

	mtu INTEGER NOT NULL DEFAULT 1500 CHECK(mtu >= 576 AND mtu <= 9000),

	subnet_ipv4 cidr CHECK (family(subnet_ipv4) = 4),
	reserve_first_ipv4 INTEGER NOT NULL DEFAULT 1, -- always a gateway address
	gateway_ipv4 cidr CHECK (family(gateway_ipv4) = 4),

	subnet_ipv6 cidr CHECK (family(subnet_ipv6) = 6),
	reserve_first_ipv6 INTEGER NOT NULL DEFAULT 0 -- not always a gateway address (i.e. link-local)
);

DROP TABLE IF EXISTS machine_interfaces;
CREATE TABLE machine_interfaces(
	id uuid DEFAULT gen_random_uuid() NOT NULL,

	machine_id uuid NOT NULL,
	segment_id uuid NOT NULL,

	mac_address macaddr NOT NULL,

	address_ipv4 inet CHECK(family(address_ipv4) = 4),

	address_ipv6 inet CHECK(family(address_ipv6) = 6),

	FOREIGN KEY (machine_id) REFERENCES machines(id),
	FOREIGN KEY (segment_id) REFERENCES network_segments(id)
);

DROP VIEW IF EXISTS machine_dhcp_responses;
CREATE VIEW machine_dhcp_responses AS (
	SELECT m.id as machine_id, n.id as segment_id, mi.mac_address, mi.address_ipv4, mi.address_ipv6, n.subdomain, n.mtu, n.gateway_ipv4, m.fqdn
	FROM machines m 
	INNER JOIN machine_interfaces mi ON mi.machine_id = m.id
	INNER JOIN network_segments n ON mi.segment_id = n.id
);
