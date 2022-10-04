-- Add migration script here
ALTER TABLE network_prefixes ADD EXCLUDE USING gist (prefix inet_ops WITH &&);
