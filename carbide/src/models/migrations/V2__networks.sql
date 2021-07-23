-- 576 is the RFC lowest possible IPv4 MTU (IPv6 is 1280)
DROP DOMAIN IF EXISTS mtu_int;
CREATE DOMAIN mtu_int AS SMALLINT CHECK(VALUE >= 576 AND VALUE <= 9000);

DROP TABLE IF EXISTS network_segments;
CREATE TABLE network_segments(
	id uuid DEFAULT gen_random_uuid() NOT NULL PRIMARY KEY,
	name VARCHAR NOT NULL UNIQUE,
	subdomain VARCHAR NOT NULL,

	mtu mtu_int NOT NULL DEFAULT 1500,

	subnet_ipv4 cidr CHECK (family(subnet_ipv4) = 4),
	reserve_first_ipv4 SMALLINT NOT NULL DEFAULT 1, -- always a gateway address

	subnet_ipv6 cidr CHECK (family(subnet_ipv6) = 6),
	reserve_first_ipv6 SMALLINT NOT NULL DEFAULT 0 -- not always a gateway address (i.e. link-local)
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
