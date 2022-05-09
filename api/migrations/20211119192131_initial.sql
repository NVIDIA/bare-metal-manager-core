-- Modeled after https://raphael.medaer.me/2019/06/12/pgfsm.html
CREATE TYPE machine_state AS ENUM (
	'init',
	'new',
	'adopted',
	'tested',
	'ready',
	'assigned',
	'broken',
	'decommissioned',
	'error'
);
CREATE TYPE machine_action AS ENUM (
	'discover',
	'adopt',
	'test',
	'commission',
	'assign',
	'fail',
	'decommission',
	'recommission',
	'unassign',
	'release'
);
-- State Machine versioning
CREATE TYPE machine_fsm_version_status AS ENUM (
	'current',
	'previous',
	'obsolete'
);
CREATE TABLE machine_state_machine_versions (
	version integer GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
	status machine_fsm_version_status NOT NULL DEFAULT 'current'
);
CREATE FUNCTION machine_state_machine_current_version() RETURNS integer LANGUAGE SQL AS $$
	SELECT version from machine_state_machine_versions WHERE status='current' ORDER BY version DESC LIMIT 1;
$$;
--
CREATE TABLE machine_transition (
	state machine_state NOT NULL,
	event machine_action NOT NULL,
	version integer NOT NULL DEFAULT machine_state_machine_current_version(),
	next_state machine_state NOT NULL,

	PRIMARY KEY (state, event, version, next_state),
	FOREIGN KEY (version) REFERENCES machine_state_machine_versions(version)
);
CREATE FUNCTION machine_transition(_state machine_state, _event machine_action, _version integer DEFAULT machine_state_machine_current_version())
	RETURNS machine_state LANGUAGE sql as $$
	SELECT COALESCE(
		(SELECT next_state FROM machine_transition WHERE state=_state AND event=_event AND version=_version),
		'error'::machine_state
	);
$$;

CREATE AGGREGATE machine_state_machine(machine_action, integer) (
	SFUNC = machine_transition,
	STYPE = machine_state,
	INITCOND = 'init'
);

CREATE FUNCTION machine_action_trigger() RETURNS trigger
	LANGUAGE plpgsql as $$
	DECLARE
	next_state machine_state;
	transition_status machine_fsm_version_status;
	current_state machine_state;
	BEGIN
		SELECT status FROM machine_state_machine_versions WHERE version=new.version INTO transition_status;

		IF transition_status = 'previous'::machine_fsm_version_status THEN
			RAISE NOTICE 'version % of machine state machine is deprecated', new.version;
		END IF;

		IF transition_status = 'obsolete'::machine_fsm_version_status THEN
			RAISE EXCEPTION 'version % of machine state machine is obsolete', new.version;
		END IF;

		SELECT machine_state_machine(action, version) OVER (PARTITION BY machine_id ORDER BY ID) FROM machine_events WHERE machine_id=new.machine_id INTO current_state;

		SELECT machine_state_machine(action, version ORDER by id)
		FROM (
			SELECT id, action, version FROM machine_events WHERE machine_id=new.machine_id
			UNION
			SELECT new.id, new.action, new.version
		) s INTO next_state;

		IF next_state = 'error'::machine_state THEN
			RAISE EXCEPTION 'invalid state transision from % using %', current_state, new.action USING ERRCODE='T0100', HINT=(SELECT CONCAT('Possible transitions from ', current_state, ' are ', (SELECT string_agg(event::text, ', ') FROM machine_transition WHERE state=current_state)));
		END IF;

		RETURN new;
	END
$$;

CREATE TYPE instance_type_capabilities as ENUM (
	'default'
);

CREATE TABLE instance_types (
	id uuid DEFAULT gen_random_uuid() NOT NULL,
	short_name VARCHAR(32) NOT NULL,
	description TEXT NOT NULL,
	capabilities instance_type_capabilities NOT NULL DEFAULT 'default',
	active BOOLEAN NOT NULL DEFAULT 't',
	created TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	updated TIMESTAMPTZ NOT NULL DEFAULT NOW(),

	PRIMARY KEY (id)
);

CREATE TABLE machines (
	id uuid DEFAULT gen_random_uuid() NOT NULL,

	supported_instance_type uuid NULL,

	fqdn VARCHAR(64) UNIQUE,

	created TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	updated TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	deployed TIMESTAMPTZ NULL,

	PRIMARY KEY (id),
	FOREIGN KEY (supported_instance_type) REFERENCES instance_types(id)
);

CREATE TABLE instances (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    machine_id uuid NOT NULL,
    requested TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finished TIMESTAMPTZ NULL,

    PRIMARY KEY (id),
    FOREIGN KEY (machine_id) REFERENCES machines(id)
);

CREATE TABLE machine_topologies (
    machine_id uuid NOT NULL,
    topology jsonb NOT NULL,

    created TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    PRIMARY KEY (machine_id),
    FOREIGN KEY (machine_id) REFERENCES machines(id)
);

CREATE TABLE machine_events (
	id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
	machine_id uuid NOT NULL,
	action machine_action NOT NULL,
	version INTEGER NOT NULL DEFAULT machine_state_machine_current_version(),
	timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	FOREIGN KEY (version) REFERENCES machine_state_machine_versions(version),
	FOREIGN KEY (machine_id) REFERENCES machines(id)
);

DELETE FROM machine_transition;
DELETE FROM machine_state_machine_versions;

INSERT INTO machine_state_machine_versions DEFAULT VALUES;
INSERT INTO machine_transition (state, event, next_state) VALUES
('init', 'discover', 'new'),
('new', 'adopt', 'adopted'),
('adopted', 'test', 'tested'),
('tested', 'commission', 'ready'),
('ready', 'assign', 'assigned'),
('new', 'fail', 'broken'),
('adopted', 'fail', 'broken'),
('tested', 'fail', 'broken'),
('ready', 'fail', 'broken'),
('assigned', 'fail', 'broken'),
('broken', 'recommission', 'tested'),
('decommissioned', 'recommission', 'tested'),
('decommissioned', 'release', 'new');

CREATE FUNCTION update_machine_updated_trigger() RETURNS TRIGGER
LANGUAGE plpgsql as $$
BEGIN
	NEW.updated := NOW();
	RETURN NEW;
END
$$;

CREATE FUNCTION set_machine_state_to_new() RETURNS TRIGGER
LANGUAGE plpgsql as $$
BEGIN
	INSERT INTO machine_events (machine_id, action) VALUES (NEW.id, 'discover');
	RETURN NEW;
END
$$;

CREATE TRIGGER start_machine_state_machine AFTER INSERT ON machines FOR EACH ROW EXECUTE PROCEDURE set_machine_state_to_new();
CREATE TRIGGER machine_last_updated BEFORE UPDATE ON machines FOR EACH ROW EXECUTE PROCEDURE update_machine_updated_trigger();
CREATE TRIGGER machine_event_trigger BEFORE INSERT on machine_events FOR EACH ROW EXECUTE PROCEDURE machine_action_trigger();

CREATE TABLE domains(
	id uuid DEFAULT gen_random_uuid() NOT NULL,
	name VARCHAR NOT NULL UNIQUE,

	created TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	updated TIMESTAMPTZ NOT NULL DEFAULT NOW(),

	PRIMARY KEY(id),

	CONSTRAINT domain_name_lower_case CHECK (((name)::TEXT = LOWER((name)::TEXT))),
	CONSTRAINT valid_domain_name_regex CHECK ( name ~ '^(?!.*?_.*?)(?!(?:[\w]+?\.)?\-[\w\.\-]*?)(?![\w]+?\-\.(?:[\w\.\-]+?))(?=[\w])(?=[\w\.\-]*?\.+[\w\.\-]*?)(?![\w\.\-]{254})(?!(?:\.?[\w\-\.]*?[\w\-]{64,}\.)+?)[\w\.\-]+?(?<![\w\-\.]*?\.[\d]+?)(?<=[\w\-]{2,})(?<![\w\-]{25})$')
);

DROP TABLE IF EXISTS vpcs;
CREATE TABLE vpcs(
	id uuid DEFAULT gen_random_uuid() NOT NULL,
	name VARCHAR NOT NULL UNIQUE,
	organization_id uuid,

	created TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	updated TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	deleted TIMESTAMPTZ,

	PRIMARY KEY(id)
);

CREATE TABLE network_segments(
	id uuid DEFAULT gen_random_uuid() NOT NULL,
	name VARCHAR NOT NULL UNIQUE,
	subdomain_id uuid,
	vpc_id uuid,

	mtu INTEGER NOT NULL DEFAULT 1500 CHECK(mtu >= 576 AND mtu <= 9000),

	created TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	updated TIMESTAMPTZ NOT NULL DEFAULT NOW(),

	PRIMARY KEY(id),
	FOREIGN KEY(subdomain_id) REFERENCES domains(id),
	FOREIGN KEY(vpc_id) REFERENCES vpcs(id)
);

CREATE TABLE network_prefixes(
	id uuid DEFAULT gen_random_uuid() NOT NULL,
	segment_id uuid NOT NULL,

	prefix cidr NOT NULL,
	gateway inet,

	num_reserved INTEGER NOT NULL DEFAULT 0,

	PRIMARY KEY(id),
	FOREIGN KEY(segment_id) REFERENCES network_segments(id),

	-- Gateway addresses for IPv6 networks are provided by RAs and not DHCP.
	-- Gateway addresses for IPv4 networks are optional (may be a private network)
	CONSTRAINT no_gateway_on_ipv6 CHECK ((family(prefix) = 6 AND gateway IS NULL) OR family(prefix) = 4),

	-- Make sure the gateway is actually on the network
	CONSTRAINT gateway_within_network CHECK (gateway << prefix)
);

-- Make sure there's at most one IPv4 prefix or one IPv6 prefix on a network segment
CREATE UNIQUE INDEX network_prefix_family ON network_prefixes (family(prefix), segment_id);

CREATE TABLE machine_interfaces(
	id uuid DEFAULT gen_random_uuid() NOT NULL,

	machine_id uuid,
	segment_id uuid NOT NULL,

	mac_address macaddr NOT NULL,

	domain_id uuid,
	primary_interface bool NOT NULL,
	hostname VARCHAR(63) NOT NULL,

	PRIMARY KEY(id),
	FOREIGN KEY(machine_id) REFERENCES machines(id),
	FOREIGN KEY(segment_id) REFERENCES network_segments(id),
	FOREIGN KEY(domain_id) REFERENCES domains(id),

	UNIQUE (segment_id, mac_address),

	CONSTRAINT fqdn_must_be_unique UNIQUE (domain_id, hostname),
	CONSTRAINT one_primary_interface_per_machine UNIQUE (machine_id, primary_interface)
);

CREATE TABLE machine_interface_addresses(
	id uuid DEFAULT gen_random_uuid() NOT NULL,

	interface_id uuid NOT NULL,
	address inet NOT NULL,

	PRIMARY KEY(id),
	FOREIGN KEY(interface_id) REFERENCES machine_interfaces(id),

	UNIQUE (interface_id, address)
);

-- Make sure there's at most one IPv4 address or one IPv6 address on an interface, i guess?
CREATE UNIQUE INDEX unique_address_family_on_interface ON machine_interface_addresses (family(address), interface_id);

DROP VIEW IF EXISTS machine_dhcp_records;
CREATE OR REPLACE VIEW machine_dhcp_records AS (
	SELECT
	machines.id as machine_id,
	machine_interfaces.id as machine_interface_id,
	network_segments.id as segment_id,
	network_segments.subdomain_id as subdomain_id,
	COALESCE(machines.fqdn,'NOHOSTNAME') as fqdn,
	machine_interfaces.mac_address as mac_address,
	machine_interface_addresses.address as address,
	network_segments.mtu as mtu,
	network_prefixes.prefix as prefix,
	network_prefixes.gateway as gateway
	FROM machine_interfaces
	LEFT JOIN machines ON machine_interfaces.machine_id=machines.id
	INNER JOIN network_segments ON network_segments.id=machine_interfaces.segment_id
	INNER JOIN network_prefixes ON network_prefixes.segment_id=network_segments.id
	INNER JOIN machine_interface_addresses ON machine_interface_addresses.interface_id=machine_interfaces.id
	WHERE address << prefix
);

CREATE OR REPLACE function fqdn(machine_uuid uuid)
	RETURNS varchar
	LANGUAGE plpgsql AS $$
	DECLARE
	fqdn_result varchar;
begin
	SELECT CONCAT_WS('.', hostname, name) INTO fqdn_result
	FROM machine_interfaces
	INNER JOIN domains on domains.id = machine_interfaces.domain_id
	WHERE machine_id = machine_uuid AND primary_interface=true;

	return fqdn_result;
end;
$$;

CREATE OR REPLACE function update_fqdn()
RETURNS TRIGGER
LANGUAGE PLPGSQL
AS
$$
BEGIN
	UPDATE machines SET fqdn = (fqdn(NEW.machine_id)) WHERE id = new.machine_id;

	RETURN NEW;
  END;
$$;

CREATE OR REPLACE TRIGGER trigger_update_fqdn
AFTER INSERT OR UPDATE
ON machine_interfaces
FOR EACH row EXECUTE PROCEDURE update_fqdn();

DROP VIEW IF EXISTS dns_records;
CREATE OR REPLACE VIEW dns_records AS (
  SELECT
  CONCAT(CONCAT(hostname,'.', name), '.') as q_name, address as resource_record
  from machine_interfaces
  INNER JOIN machine_interface_addresses on machine_interface_addresses.interface_id = interface_id
  INNER JOIN domains on domains.id = machine_interfaces.domain_id AND primary_interface=true
);
