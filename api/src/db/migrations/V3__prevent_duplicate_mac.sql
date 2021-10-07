ALTER TABLE machine_interfaces ADD CONSTRAINT prevent_duplicate_mac_for_network UNIQUE (segment_id, mac_address);
