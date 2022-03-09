DROP TABLE IF EXISTS domains;
CREATE TABLE domains(
        id uuid DEFAULT gen_random_uuid() NOT NULL,
        name VARCHAR NOT NULL UNIQUE,

        created TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated TIMESTAMPTZ NOT NULL DEFAULT NOW(),

        PRIMARY KEY(id)
);