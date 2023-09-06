--
-- FOR LOCAL DEVELOPMENT ONLY
--
-- Delete everything that `cargo make bootstrap-forge-docker` puts in the database, so that we
-- can re-run it without a full env restart.
--
-- Handy SQL to select * from all tables:
--  SELECT schemaname,relname,n_live_tup FROM pg_stat_user_tables ORDER BY n_live_tup DESC;
--
-- Usage: PGPASSWORD=<thing> psql -h 172.20.0.16 -U carbide_development < cleanup_bootstrap.sql

DELETE FROM instance_addresses;
DELETE FROM instances;
DELETE FROM machine_topologies;
DELETE FROM machine_interface_addresses;
DELETE FROM machine_interfaces;
DELETE FROM machine_state_history;
DELETE FROM machines;
DELETE FROM network_prefixes;
DELETE FROM network_segment_state_history;
DELETE FROM network_segments;
DELETE FROM resource_pool;
DELETE FROM domains;
DELETE FROM vpcs;
