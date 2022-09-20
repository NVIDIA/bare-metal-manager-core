INSERT INTO machines (id) VALUES ('52dfecb4-8070-4f4b-ba95-f66d0f51fd98');
INSERT INTO machine_interfaces (id, segment_id, machine_id, mac_address, hostname, domain_id, primary_interface) VALUES (
	'ad871735-efaa-406e-a83e-9ff63b1bc145',
	'91609f10-c91d-470d-a260-6293ea0c1200',
	'52dfecb4-8070-4f4b-ba95-f66d0f51fd98',
	'ff:ff:ff:ff:ff:ff',
	'foobar',
	'1ebec7c1-114f-4793-a9e4-63f3d22b5b5e',
	't');

INSERT INTO machine_interface_addresses (interface_id, address) VALUES ('ad871735-efaa-406e-a83e-9ff63b1bc145', '192.0.2.3');
INSERT INTO machine_topologies (machine_id, topology) VALUES ('52dfecb4-8070-4f4b-ba95-f66d0f51fd98', '{}');
