DROP VIEW IF EXISTS machine_dhcp_responses;
ALTER TABLE network_segments DROP COLUMN subdomain;
ALTER TABLE network_segments ADD COLUMN subdomain_id uuid;

ALTER TABLE network_segments ADD FOREIGN KEY (subdomain_id) REFERENCES domains(id);

ALTER TABLE machine_interfaces ADD COLUMN domain_id uuid;
ALTER TABLE machine_interfaces ADD COLUMN hostname VARCHAR(63) NOT NULL;
ALTER TABLE machine_interfaces ADD FOREIGN KEY (domain_id) REFERENCES domains(id);
ALTER TABLE machine_interfaces ADD primary_interface bool NOT NULL;

ALTER TABLE machine_interfaces ADD CONSTRAINT fqdn_must_be_unique UNIQUE (domain_id, hostname);
ALTER TABLE machine_interfaces ADD CONSTRAINT one_primary_interface_per_machine UNIQUE (machine_id, primary_interface);


CREATE OR REPLACE function fqdn(machine_uuid uuid)
  RETURNS varchar
  LANGUAGE plpgsql
  AS
  $$
  DECLARE
    fqdn_result varchar;
  begin
    SELECT CONCAT_WS('.', hostname, name) INTO fqdn_result
    FROM machine_interfaces
    INNER JOIN domains on domains.id = machine_interfaces.domain_id
    WHERE machine_id = machine_uuid AND primary_interface=true;

    return fqdn_result;
  end;
$$;

CREATE OR REPLACE function update_fqdn()
  RETURNS TRIGGER
  LANGUAGE PLPGSQL
  AS
  $$
  BEGIN
    UPDATE machines SET fqdn = (fqdn(NEW.machine_id)) WHERE id = new.machine_id;

  RETURN NEW;
  END;
$$;

CREATE OR REPLACE TRIGGER trigger_update_fqdn
  AFTER INSERT OR UPDATE
  ON machine_interfaces
  FOR EACH row
  EXECUTE PROCEDURE update_fqdn();

CREATE VIEW machine_dhcp_responses AS (
    SELECT m.id as machine_id, n.id as segment_id, mi.mac_address, mi.address_ipv4, mi.address_ipv6, n.subdomain_id, n.mtu, n.gateway_ipv4, fqdn(mi.machine_id)
    FROM machines m
    INNER JOIN machine_interfaces mi ON mi.machine_id = m.id
    INNER JOIN network_segments n ON mi.segment_id = n.id
);
