ALTER TABLE IF EXISTS instance_subnets_events RENAME to instance_subnet_events;
-- instance subnets and instance_subnet_addresses = ManagedResource in forge-fpc
CREATE TABLE IF NOT EXISTS instance_subnet_events(
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  instance_subnet_id uuid NOT NULL,
  action vpc_resource_action NOT NULL,
  timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  FOREIGN KEY (instance_subnet_id) REFERENCES instance_subnets(id)
);
