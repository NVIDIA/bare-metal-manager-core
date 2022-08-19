-- Add migration script here

ALTER TABLE IF EXISTS vpcs ALTER COLUMN organization_id TYPE VARCHAR;
