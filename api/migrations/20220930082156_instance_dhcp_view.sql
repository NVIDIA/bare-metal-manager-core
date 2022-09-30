-- Add migration script here
DROP VIEW IF EXISTS instance_dhcp_records;    
CREATE OR REPLACE VIEW instance_dhcp_records AS (    
   SELECT    
   machines.id as machine_id,
   machine_interfaces.id as machine_interface_id,
   network_segments.id as segment_id,
   network_segments.subdomain_id as subdomain_id,    
   CONCAT(machine_interfaces.hostname,'.', domains.name) as fqdn,    
   machine_interfaces.mac_address as mac_address,    
   instance_subnet_addresses.address as address,    
   network_segments.mtu as mtu,    
   network_prefixes.prefix as prefix,    
   instance_subnets.vfid as vfid,
   network_prefixes.gateway as gateway
   FROM machine_interfaces    
   LEFT JOIN machines ON machine_interfaces.machine_id=machines.id    
   INNER JOIN domains on domains.id = machine_interfaces.domain_id    
   INNER JOIN instances ON instances.machine_id = machines.id    
   INNER JOIN instance_subnets ON instance_subnets.instance_id = instances.id    
   INNER JOIN network_segments ON network_segments.id=instance_subnets.network_segment_id    
   INNER JOIN network_prefixes ON network_prefixes.segment_id=network_segments.id    
   INNER JOIN instance_subnet_addresses ON instance_subnet_addresses.instance_subnet_id = instance_subnets.id    
   WHERE address << prefix
);    

