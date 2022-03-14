DROP TABLE IF EXISTS projects;
CREATE TABLE projects(
                        id uuid DEFAULT gen_random_uuid() NOT NULL,
                        name VARCHAR NOT NULL UNIQUE,
                        organization_id uuid,

                        created TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                        updated TIMESTAMPTZ NOT NULL DEFAULT NOW(),

                        PRIMARY KEY(id)
);

--  https://github.com/c-hive/guides/blob/79f7ddde35706f85b2844998a16d1e5ecaf1bb39/etc/regex.md#domain
--  https://doc.powerdns.com/authoritative/backends/generic-postgresql.html
