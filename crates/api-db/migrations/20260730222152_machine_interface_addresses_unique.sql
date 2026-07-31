-- A machine-interface address identifies one interface across the site. The
-- existing `(interface_id, address)` constraint only protects one interface
-- from storing the same address twice, so concurrent writers can still give
-- the same IP to different interfaces.
--
-- `inet` equality includes the mask. Group by `host(address)` before changing
-- anything so a legacy `/24` and the normal `/32` form of the same IPv4 host
-- cannot slip past the audit (and likewise for IPv6).
--
-- Take the strongest lock this migration will need before the audit starts.
-- That avoids a lock-upgrade deadlock with an older API transaction that reads
-- the table and then waits to write. API reads and writes resume after this
-- migration commits, at which point the database applies the same invariant.
LOCK TABLE machine_interface_addresses IN ACCESS EXCLUSIVE MODE;

DO $$
DECLARE
    duplicate_addresses text;
    duplicate_address_count bigint;
BEGIN
    SELECT count(*)
    INTO duplicate_address_count
    FROM (
        SELECT host(address)
        FROM machine_interface_addresses
        GROUP BY host(address)
        HAVING count(*) > 1
    ) duplicate_groups;

    SELECT string_agg(
        format('%s: %s', host_address, owners),
        E'\n' ORDER BY host_address
    )
    INTO duplicate_addresses
    FROM (
        SELECT
            host(mia.address) AS host_address,
            string_agg(
                format(
                    'interface %s (MAC %s, segment %s)',
                    mi.id,
                    mi.mac_address,
                    mi.segment_id
                ),
                ', ' ORDER BY mi.id
            ) AS owners
        FROM machine_interface_addresses mia
        JOIN machine_interfaces mi ON mi.id = mia.interface_id
        GROUP BY host(mia.address)
        HAVING count(*) > 1
        ORDER BY host(mia.address)
        LIMIT 20
    ) duplicates;

    IF duplicate_addresses IS NOT NULL THEN
        RAISE EXCEPTION
            'machine_interface_addresses contains duplicate host addresses (% total; showing at most 20): %',
            duplicate_address_count,
            duplicate_addresses
            USING HINT = 'Resolve each duplicate owner before retrying this migration.';
    END IF;
END
$$;

-- Rust writes `IpAddr`, and the legacy admin-network procedure already uses
-- `host(address)::inet`, so normal rows are `/32` or `/128`. Normalize any
-- single-owner legacy rows before requiring that form from every future writer.
UPDATE machine_interface_addresses
SET address = host(address)::inet
WHERE address != host(address)::inet;

-- This is a storage-representation invariant: the unique key and prefix-range
-- lookups both require host-form `inet` values even when rows arrive outside
-- the Rust model boundary.
ALTER TABLE machine_interface_addresses
    ADD CONSTRAINT machine_interface_addresses_host_address_check
    CHECK (address = host(address)::inet);

-- The unique index created by this constraint covers the address lookups that
-- used the older non-unique index.
DROP INDEX IF EXISTS machine_interface_addresses_address_idx;

ALTER TABLE machine_interface_addresses
    ADD CONSTRAINT machine_interface_addresses_address_key UNIQUE (address);

-- `update_admin_network` used to rewrite addresses one interface at a time.
-- An overlapping range can temporarily place one interface on an address that
-- a later interface still owns. Stage the complete mapping, remove the old
-- rows, and then insert the final addresses under the global constraint.
CREATE OR REPLACE PROCEDURE update_admin_network(
    admin_network uuid,
    new_range inet,
    new_gw inet
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_prefix_id uuid;
    v_previous_prefix inet;
    v_num_reserved integer;
BEGIN
    -- A dual-stack segment selects its matching family. The legacy procedure
    -- could also replace the only prefix with a different family, so keep that
    -- behavior when there is exactly one unambiguous prefix.
    SELECT candidate.id, candidate.prefix, candidate.num_reserved
    INTO v_prefix_id, v_previous_prefix, v_num_reserved
    FROM (
        SELECT
            p.id,
            p.prefix,
            p.num_reserved,
            count(*) OVER () AS prefix_count,
            count(*) FILTER (
                WHERE family(p.prefix) = family(new_range)
            ) OVER () AS matching_family_count
        FROM network_segments s
        JOIN network_prefixes p ON p.segment_id = s.id
        WHERE s.network_segment_type = 'admin'
          AND s.id = admin_network
    ) candidate
    WHERE (
        family(candidate.prefix) = family(new_range)
        AND candidate.matching_family_count = 1
    ) OR (
        candidate.matching_family_count = 0
        AND candidate.prefix_count = 1
    )
    LIMIT 1;

    IF v_prefix_id IS NULL THEN
        RAISE NOTICE 'Could not select one admin network prefix for the requested range';
        RETURN;
    END IF;

    IF NOT masklen(new_range) <= masklen(v_previous_prefix) THEN
        RAISE NOTICE 'New range is smaller than old range, aborting because it cannot be guaranteed to have enough space';
        RETURN;
    END IF;

    -- Keep the legacy NULL gateway behavior, which IPv6 prefixes require.
    IF new_gw IS NOT NULL AND NOT host(new_range + 1) = host(new_gw) THEN
        RAISE NOTICE 'new range first IP is not the gateway, exiting';
        RETURN;
    END IF;

    IF v_num_reserved = 0 THEN
        RAISE NOTICE 'num_reserved is zero but we need to at least reserve the network and gateway, so making it 2';
        v_num_reserved := 2;
    END IF;

    CREATE TEMP TABLE IF NOT EXISTS tmp_admin_network_address_mapping (
        address_id uuid PRIMARY KEY,
        interface_id uuid NOT NULL,
        address inet NOT NULL,
        allocation_type text NOT NULL,
        domain_id uuid,
        hostname varchar(63) NOT NULL
    ) ON COMMIT DROP;
    TRUNCATE tmp_admin_network_address_mapping;

    INSERT INTO tmp_admin_network_address_mapping (
        address_id,
        interface_id,
        address,
        allocation_type,
        domain_id,
        hostname
    )
    SELECT
        address_id,
        interface_id,
        address,
        allocation_type,
        domain_id,
        CASE
            -- The procedure cannot read the process-wide naming strategy. A
            -- name matching the old address is IP-derived, so move it with the
            -- address. `fun`, `serial_number`, `mac_address`, and operator-set
            -- names stay as-is.
            WHEN previous_hostname IN (
                previous_ip_hostname,
                previous_legacy_ip_hostname
            ) THEN ip_hostname
            ELSE previous_hostname
        END
    FROM (
        SELECT
            preferred_addresses.*,
            -- Keep these equivalent to
            -- `host_naming::address_to_hostname`: dotted IPv4 becomes dashed,
            -- while IPv6 uses eight zero-padded groups.
            CASE
                WHEN family(previous_address) = 4 THEN
                    replace(host(previous_address), '.', '-')
                ELSE
                    rtrim(
                        regexp_replace(
                            encode(
                                substring(inet_send(previous_address) FROM 5),
                                'hex'
                            ),
                            '(.{4})',
                            '\1-',
                            'g'
                        ),
                        '-'
                    )
            END AS previous_ip_hostname,
            -- The older procedure only replaced dots. Accept that stored form
            -- too, then write the canonical name on this remap.
            replace(
                host(previous_address),
                '.',
                '-'
            ) AS previous_legacy_ip_hostname,
            CASE
                WHEN family(hostname_address) = 4 THEN
                    replace(host(hostname_address), '.', '-')
                ELSE
                    rtrim(
                        regexp_replace(
                            encode(
                                substring(inet_send(hostname_address) FROM 5),
                                'hex'
                            ),
                            '(.{4})',
                            '\1-',
                            'g'
                        ),
                        '-'
                    )
            END AS ip_hostname
        FROM (
            SELECT
                mapped_addresses.*,
                CASE
                    -- Rust naming prefers an interface's IPv4 address. Keep
                    -- that name when only its IPv6 half is being remapped.
                    WHEN family(address) = 6 THEN
                        COALESCE(surviving_ipv4_address, address)
                    ELSE address
                END AS hostname_address
            FROM (
                SELECT
                    mia.id AS address_id,
                    mia.interface_id,
                    mi.domain_id,
                    mia.address AS previous_address,
                    mi.hostname AS previous_hostname,
                    (
                        SELECT existing.address
                        FROM machine_interface_addresses existing
                        WHERE existing.interface_id = mia.interface_id
                          AND existing.id != mia.id
                          AND family(existing.address) = 4
                          -- Reuse only an address that survives this remap.
                          AND family(existing.address) != family(v_previous_prefix)
                        LIMIT 1
                    ) AS surviving_ipv4_address,
                    host(
                        new_range
                        + (v_num_reserved + row_number() OVER (ORDER BY mi.id, mia.id) - 1)
                    )::inet AS address,
                    mia.allocation_type
                FROM machine_interface_addresses mia
                JOIN machine_interfaces mi ON mi.id = mia.interface_id
                WHERE mi.segment_id = admin_network
                  AND family(mia.address) = family(v_previous_prefix)
            ) mapped_addresses
        ) preferred_addresses
    ) named_addresses;

    DELETE FROM machine_interface_addresses mia
    USING tmp_admin_network_address_mapping mapped
    WHERE mia.id = mapped.address_id;

    INSERT INTO machine_interface_addresses (
        id,
        interface_id,
        address,
        allocation_type
    )
    SELECT
        address_id,
        interface_id,
        address,
        allocation_type
    FROM tmp_admin_network_address_mapping
    ORDER BY address;

    -- Remove affected rows from the active FQDN namespace while applying the
    -- final names. This lets two interfaces swap IP-derived hostnames without
    -- tripping the immediate `(domain_id, hostname)` constraint halfway
    -- through the update. Restoring each saved domain below still rejects a
    -- real conflict with an interface outside this remap.
    UPDATE machine_interfaces mi
    SET domain_id = NULL,
        hostname = mapped.hostname
    FROM tmp_admin_network_address_mapping mapped
    WHERE mi.id = mapped.interface_id;

    UPDATE machine_interfaces mi
    SET domain_id = mapped.domain_id
    FROM tmp_admin_network_address_mapping mapped
    WHERE mi.id = mapped.interface_id;

    UPDATE network_prefixes
    SET gateway = new_gw,
        prefix = new_range
    WHERE id = v_prefix_id;
END
$$;
