DROP TABLE IF EXISTS domains;
CREATE TABLE domains(
        id uuid DEFAULT gen_random_uuid() NOT NULL,
        name VARCHAR NOT NULL UNIQUE,
        machine_interface_id uuid,

        created TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated TIMESTAMPTZ NOT NULL DEFAULT NOW(),

        PRIMARY KEY(id),
        FOREIGN KEY(machine_interface_id) REFERENCES machine_interfaces(id),

        CONSTRAINT fqdn_is_unique UNIQUE (name,  machine_interface_id),
        CONSTRAINT domain_name_lower_case CHECK (((name)::TEXT = LOWER((name)::TEXT))),
        CONSTRAINT valid_domain_name_regex CHECK ( name ~ '^(?!.*?_.*?)(?!(?:[\w]+?\.)?\-[\w\.\-]*?)(?![\w]+?\-\.(?:[\w\.\-]+?))(?=[\w])(?=[\w\.\-]*?\.+[\w\.\-]*?)(?![\w\.\-]{254})(?!(?:\.?[\w\-\.]*?[\w\-]{64,}\.)+?)[\w\.\-]+?(?<![\w\-\.]*?\.[\d]+?)(?<=[\w\-]{2,})(?<![\w\-]{25})$')
);

--  https://github.com/c-hive/guides/blob/79f7ddde35706f85b2844998a16d1e5ecaf1bb39/etc/regex.md#domain
--  https://doc.powerdns.com/authoritative/backends/generic-postgresql.html
