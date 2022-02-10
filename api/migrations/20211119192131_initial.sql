-- Modeled after https://raphael.medaer.me/2019/06/12/pgfsm.html
CREATE TYPE machine_state AS ENUM (
	'init',
	'new',
	'adopted',
	'tested',
	'commissioned',
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

	fqdn VARCHAR(64) NOT NULL UNIQUE,

	created TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	updated TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	deployed TIMESTAMPTZ NULL,

	PRIMARY KEY (id),
	FOREIGN KEY (supported_instance_type) REFERENCES instance_types(id)
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
('tested', 'commission', 'commissioned'),
('commissioned', 'assign', 'assigned'),
('new', 'fail', 'broken'),
('adopted', 'fail', 'broken'),
('tested', 'fail', 'broken'),
('commissioned', 'fail', 'broken'),
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
