-- First-class lifecycle for on-demand rack maintenance.
--
-- The request row is the durable coordination point between API/monitor
-- callers, the external credential store, and the rack state controller.
-- Secret material remains outside Postgres.

CREATE TYPE rack_maintenance_request_status AS ENUM
    ('preparing', 'ready', 'running', 'completed', 'failed', 'cancelled');

CREATE TABLE rack_maintenance_requests (
    id                    uuid PRIMARY KEY,
    rack_id               varchar(64) NOT NULL REFERENCES racks(id) ON DELETE CASCADE,
    scope                 jsonb NOT NULL,
    status                rack_maintenance_request_status NOT NULL,
    requires_access_token boolean NOT NULL DEFAULT false,
    error_message         text,
    created               timestamptz NOT NULL DEFAULT now(),
    updated               timestamptz NOT NULL DEFAULT now(),
    started               timestamptz,
    completed             timestamptz
);

-- A rack can have at most one request being prepared, queued, or executed.
-- Terminal rows are retained for audit and do not block future requests.
CREATE UNIQUE INDEX rack_maintenance_requests_one_active_per_rack
    ON rack_maintenance_requests (rack_id)
    WHERE status IN ('preparing', 'ready', 'running');

CREATE INDEX rack_maintenance_requests_rack_created
    ON rack_maintenance_requests (rack_id, created DESC);

