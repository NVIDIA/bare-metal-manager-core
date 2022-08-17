CREATE TABLE dhcp_entries
(
    machine_interface_id uuid NOT NULL,
    vendor_string VARCHAR NOT NULL,

    PRIMARY KEY(machine_interface_id, vendor_string),
    FOREIGN KEY(machine_interface_id) REFERENCES machine_interfaces(id)
);
