INSERT INTO network_segments (id, name, subdomain_id, mtu, vpc_id, version, controller_state_version, controller_state) VALUES (
	'91609f10-c91d-470d-a260-6293ea0c1200',
	'integration_test',
	'1ebec7c1-114f-4793-a9e4-63f3d22b5b5e',
	1500,
	'60cef902-9779-4666-8362-c9bb4b37184f',
	'V1-T1666644937952267',
	'V1-T1666644937952267',
	'{"state":"ready"}'
);

INSERT INTO network_prefixes (segment_id, prefix, gateway, num_reserved, circuit_id) VALUES (
	'91609f10-c91d-470d-a260-6293ea0c1200',
	'192.0.2.0/24',
	'192.0.2.1',
	3,
  'vlan_100');

INSERT INTO network_segments (id, name, mtu, version, controller_state_version, controller_state) VALUES (
	'4de5bdd6-1f28-4ed4-aba7-f52e292f0fe8',
	'integration_tests_no_vpe_no_domain',
	1500,
	'V1-T1666644937952267',
	'V1-T1666644937952267',
	'{"state":"ready"}'
);

INSERT INTO network_prefixes (segment_id, prefix, gateway, num_reserved, circuit_id) VALUES (
	'4de5bdd6-1f28-4ed4-aba7-f52e292f0fe8',
	'192.0.4.0/24',
	'192.0.4.1',
	3,
  'vlan_121');

INSERT INTO network_segments (id, name, mtu, vpc_id, version, controller_state_version, controller_state) VALUES (
	'4de5bdd6-1f28-4ed4-aba7-f52e292f0fe9',
	'integration_tests_no_domain',
	1500,
	'60cef902-9779-4666-8362-c9bb4b37184f',
	'V1-T1666644937952267',
	'V1-T1666644937952267',
	'{"state":"ready"}'
);

INSERT INTO network_prefixes (segment_id, prefix, gateway, num_reserved, circuit_id) VALUES (
	'4de5bdd6-1f28-4ed4-aba7-f52e292f0fe9',
	'192.0.3.0/24',
	'192.0.3.1',
	3,
  'vlan_101');
