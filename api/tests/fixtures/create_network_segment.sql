INSERT INTO network_segments (id, name, subdomain_id, mtu, vpc_id, version) VALUES (
	'91609f10-c91d-470d-a260-6293ea0c1200',
	'integration_test',
	'1ebec7c1-114f-4793-a9e4-63f3d22b5b5e',
	1500,
	'60cef902-9779-4666-8362-c9bb4b37184f',
	'V1-T1666644937952267'
);

INSERT INTO network_prefixes (segment_id, prefix, gateway, num_reserved) VALUES (
	'91609f10-c91d-470d-a260-6293ea0c1200',
	'2001:db8:f::/64',
	NULL,
	100);

INSERT INTO network_prefixes (segment_id, prefix, gateway, num_reserved) VALUES (
	'91609f10-c91d-470d-a260-6293ea0c1200',
	'192.0.2.0/24',
	'192.0.2.1',
	3);

INSERT INTO network_segments (id, name, mtu, version) VALUES (
	'4de5bdd6-1f28-4ed4-aba7-f52e292f0fe8',
	'integration_tests_no_vpe_no_domain',
	1500,
	'V1-T1666644937952267'
);
