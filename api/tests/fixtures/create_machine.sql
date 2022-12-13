INSERT INTO vpc_resource_leafs 
VALUES
  ('52dfecb4-8070-4f4b-ba95-f66d0f51fd98', '192.168.0.1')
;

INSERT INTO machines (id, vpc_leaf_id) 
VALUES 
          ('52dfecb4-8070-4f4b-ba95-f66d0f51fd98', '52dfecb4-8070-4f4b-ba95-f66d0f51fd98'), 
          ('52dfecb4-8070-4f4b-ba95-f66d0f51fd99', NULL)
;

INSERT INTO machine_interfaces (id, segment_id, attached_dpu_machine_id, machine_id, mac_address, hostname, domain_id, primary_interface) 
VALUES 
  (
    'ad871735-efaa-406e-a83e-9ff63b1bc145',
    '91609f10-c91d-470d-a260-6293ea0c1200',
    '52dfecb4-8070-4f4b-ba95-f66d0f51fd98',
    '52dfecb4-8070-4f4b-ba95-f66d0f51fd98',
    'ff:ff:ff:ff:ff:ff',
    'foobar',
    '1ebec7c1-114f-4793-a9e4-63f3d22b5b5e',
    't'
  ),
  (
    'ad871735-efaa-406e-a83e-9ff63b1bc146',
    '91609f10-c91d-470d-a260-6293ea0c1200',
    '52dfecb4-8070-4f4b-ba95-f66d0f51fd98',
    '52dfecb4-8070-4f4b-ba95-f66d0f51fd99',
    'ff:ff:ff:ff:ff:1f',
    'foobar1',
    '1ebec7c1-114f-4793-a9e4-63f3d22b5b5e',
    't'
  )
;

INSERT INTO machine_interface_addresses (interface_id, address) 
VALUES 
  ('ad871735-efaa-406e-a83e-9ff63b1bc145', '192.0.2.3'),
  ('ad871735-efaa-406e-a83e-9ff63b1bc146', '192.0.2.4')
;

INSERT INTO machine_topologies (machine_id, topology) 
VALUES 
  (
    '52dfecb4-8070-4f4b-ba95-f66d0f51fd98',
    '{"machine_id": "52dfecb4-8070-4f4b-ba95-f66d0f51fd98", "discovery_data": {"Info": {"cpus": [{"core": 0, "node": 0, "model": "Intel(R) Core(TM) i9-10920X CPU @ 3.50GHz", "number": 0, "socket": 0, "vendor": "GenuineIntel", "frequency": "3503.998"}], "machine_type": "aarch64", "nvme_devices": [{ "model": "test_model","firmware_rev":"firmware_rev" } ], "dmi_devices": [ { "board_name": "board_name", "board_version": "board_version", "bios_version": "bios_version" } ], "block_devices": [{"model": "QEMU_DVD-ROM", "serial": "QM00003", "revision": "2.5+"}, {"model": "NO_MODEL", "serial": "NO_SERIAL", "revision": "NO_REVISION"}], "network_interfaces": [{"mac_address": "52:54:00:12:34:56", "pci_properties": {"path": "/devices/pci0000:00/0000:00:04.0/virtio1/net/ens4", "device": "0x1000", "vendor": "0x1af4", "numa_node": 2147483647, "description": "Virtio network device"}}]}}}'
  ),
  (
    '52dfecb4-8070-4f4b-ba95-f66d0f51fd99',
    '{"machine_id": "52dfecb4-8070-4f4b-ba95-f66d0f51fd99", "discovery_data": {"Info": {"cpus": [{"core": 0, "node": 0, "model": "Intel(R) Core(TM) i9-10920X CPU @ 3.50GHz", "number": 0, "socket": 0, "vendor": "GenuineIntel", "frequency": "3503.998"}], "machine_type": "x86_64", "nvme_devices": [{ "model": "test_model","firmware_rev":"firmware_rev" } ], "dmi_devices": [ { "board_name": "board_name", "board_version": "board_version", "bios_version": "bios_version" } ], "block_devices": [{"model": "QEMU_DVD-ROM", "serial": "QM00003", "revision": "2.5+"}, {"model": "NO_MODEL", "serial": "NO_SERIAL", "revision": "NO_REVISION"}], "network_interfaces": [{"mac_address": "52:54:00:12:34:56", "pci_properties": {"path": "/devices/pci0000:00/0000:00:04.0/virtio1/net/ens4", "device": "0x1000", "vendor": "0x1af4", "numa_node": 2147483647, "description": "Virtio network device"}}]}}}'
  )
;
