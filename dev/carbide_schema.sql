-- Last updated Aug 03 2023

--
-- Carbide database schema with all migrations applied.
--
-- Created like this and then maintained manually
-- PGPASSWORD=notforprod pg_dump -h 172.20.0.16 --schema-only -U carbide_development > ~/carbide_schema.sql

DROP DATABASE IF EXISTS carbide_development;
CREATE DATABASE carbide_development WITH OWNER = carbide_development;
\c carbide_development

--
-- PostgreSQL database dump
--

-- Dumped from database version 14.1
-- Dumped by pg_dump version 15.1

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: public; Type: SCHEMA; Schema: -; Owner: carbide_development
--

-- *not* creating schema, since initdb creates it


ALTER SCHEMA public OWNER TO carbide_development;

--
-- Name: pgcrypto; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;


--
-- Name: EXTENSION pgcrypto; Type: COMMENT; Schema: -; Owner:
--

COMMENT ON EXTENSION pgcrypto IS 'cryptographic functions';


--
-- Name: uuid-ossp; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS "uuid-ossp" WITH SCHEMA public;


--
-- Name: EXTENSION "uuid-ossp"; Type: COMMENT; Schema: -; Owner:
--

COMMENT ON EXTENSION "uuid-ossp" IS 'generate universally unique identifiers (UUIDs)';


--
-- Name: console_type; Type: TYPE; Schema: public; Owner: carbide_development
--

CREATE TYPE public.console_type AS ENUM (
    'ipmi',
    'redfish'
);


ALTER TYPE public.console_type OWNER TO carbide_development;

--
-- Name: instance_type_capabilities; Type: TYPE; Schema: public; Owner: carbide_development
--

CREATE TYPE public.instance_type_capabilities AS ENUM (
    'default'
);


ALTER TYPE public.instance_type_capabilities OWNER TO carbide_development;

--
-- Name: machine_action; Type: TYPE; Schema: public; Owner: carbide_development
--

CREATE TYPE public.machine_action AS ENUM (
    'discover',
    'adopt',
    'test',
    'commission',
    'assign',
    'fail',
    'decommission',
    'recommission',
    'unassign',
    'release',
    'cleanup'
);


ALTER TYPE public.machine_action OWNER TO carbide_development;

--
-- Name: machine_state; Type: TYPE; Schema: public; Owner: carbide_development
--

CREATE TYPE public.machine_state AS ENUM (
    'init',
    'new',
    'adopted',
    'tested',
    'ready',
    'reset',
    'assigned',
    'broken',
    'decommissioned',
    'error',
    'unknown'
);


ALTER TYPE public.machine_state OWNER TO carbide_development;

--
-- Name: mq_new_t; Type: TYPE; Schema: public; Owner: carbide_development
--

CREATE TYPE public.mq_new_t AS (
	id uuid,
	delay interval,
	retries integer,
	retry_backoff interval,
	channel_name text,
	channel_args text,
	commit_interval interval,
	ordered boolean,
	name text,
	payload_json text,
	payload_bytes bytea
);


ALTER TYPE public.mq_new_t OWNER TO carbide_development;

--
-- Name: network_segment_type_t; Type: TYPE; Schema: public; Owner: carbide_development
--

CREATE TYPE public.network_segment_type_t AS ENUM (
    'tenant',
    'admin',
    'underlay'
);


ALTER TYPE public.network_segment_type_t OWNER TO carbide_development;

--
-- Name: network_virtualization_type_t; Type: TYPE; Schema: public; Owner: carbide_development
--

CREATE TYPE public.network_virtualization_type_t AS ENUM (
    'etv',
    'fnn'
);


ALTER TYPE public.network_virtualization_type_t OWNER TO carbide_development;

--
-- Name: resource_pool_type; Type: TYPE; Schema: public; Owner: carbide_development
--

CREATE TYPE public.resource_pool_type AS ENUM (
    'integer',
    'ipv4'
);


ALTER TYPE public.resource_pool_type OWNER TO carbide_development;

--
-- Name: user_roles; Type: TYPE; Schema: public; Owner: carbide_development
--

CREATE TYPE public.user_roles AS ENUM (
    'user',
    'administrator',
    'operator',
    'noaccess'
);


ALTER TYPE public.user_roles OWNER TO carbide_development;

--
-- Name: cleanup_machine(character varying); Type: PROCEDURE; Schema: public; Owner: carbide_development
--

CREATE PROCEDURE public.cleanup_machine(IN host character varying)
    LANGUAGE plpgsql
    AS $$
declare
  delete_id VARCHAR(64);
begin
  select machine_id into delete_id from machine_interfaces where hostname = host;
  call cleanup_machine_by_id(delete_id);
end
$$;


ALTER PROCEDURE public.cleanup_machine(IN host character varying) OWNER TO carbide_development;

--
-- Name: cleanup_machine_by_id(uuid); Type: PROCEDURE; Schema: public; Owner: carbide_development
--

CREATE PROCEDURE public.cleanup_machine_by_id(IN deletion_machine_id uuid)
    LANGUAGE plpgsql
    AS $$
 begin
  update machine_interfaces set machine_id = null, attached_dpu_machine_id = null where machine_id = deletion_machine_id;
  delete from machine_topologies where machine_id = deletion_machine_id;
  delete from machines where id = deletion_machine_id;
  delete from vpc_resource_leafs where id = deletion_machine_id;
end
$$;


ALTER PROCEDURE public.cleanup_machine_by_id(IN deletion_machine_id uuid) OWNER TO carbide_development;

--
-- Name: cleanup_machine_by_id(character varying); Type: PROCEDURE; Schema: public; Owner: carbide_development
--

CREATE PROCEDURE public.cleanup_machine_by_id(IN deletion_machine_id character varying)
    LANGUAGE plpgsql
    AS $$
 begin
  update machine_interfaces set machine_id = null where machine_id = deletion_machine_id;
  update machine_interfaces set attached_dpu_machine_id = null where attached_dpu_machine_id = deletion_machine_id;
  delete from machine_topologies where machine_id = deletion_machine_id;
  delete from machines where id = deletion_machine_id;
end
$$;


ALTER PROCEDURE public.cleanup_machine_by_id(IN deletion_machine_id character varying) OWNER TO carbide_development;

--
-- Name: delete_old_rows(); Type: FUNCTION; Schema: public; Owner: carbide_development
--

CREATE FUNCTION public.delete_old_rows() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  DELETE FROM bg_status WHERE last_updated < CURRENT_TIMESTAMP - INTERVAL '2 days';
  RETURN NULL;
END;
$$;


ALTER FUNCTION public.delete_old_rows() OWNER TO carbide_development;

--
-- Name: machine_state_history_keep_limit(); Type: FUNCTION; Schema: public; Owner: carbide_development
--

CREATE FUNCTION public.machine_state_history_keep_limit() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
	DELETE FROM machine_state_history WHERE machine_id=NEW.machine_id AND id NOT IN (SELECT id from machine_state_history where machine_id=NEW.machine_id ORDER BY id DESC LIMIT 250);
	RETURN NULL;
END;
$$;


ALTER FUNCTION public.machine_state_history_keep_limit() OWNER TO carbide_development;

--
-- Name: mq_active_channels(text[], integer); Type: FUNCTION; Schema: public; Owner: carbide_development
--

CREATE FUNCTION public.mq_active_channels(channel_names text[], batch_size integer) RETURNS TABLE(name text, args text)
    LANGUAGE sql STABLE
    AS $$
    SELECT channel_name, channel_args
    FROM mq_msgs
    WHERE id != uuid_nil()
    AND attempt_at <= NOW()
    AND (channel_names IS NULL OR channel_name = ANY(channel_names))
    AND NOT mq_uuid_exists(after_message_id)
    GROUP BY channel_name, channel_args
    ORDER BY RANDOM()
    LIMIT batch_size
$$;


ALTER FUNCTION public.mq_active_channels(channel_names text[], batch_size integer) OWNER TO carbide_development;

--
-- Name: mq_checkpoint(uuid, interval, text, bytea, integer); Type: FUNCTION; Schema: public; Owner: carbide_development
--

CREATE FUNCTION public.mq_checkpoint(msg_id uuid, duration interval, new_payload_json text, new_payload_bytes bytea, extra_retries integer) RETURNS void
    LANGUAGE sql
    AS $$
    UPDATE mq_msgs
    SET
        attempt_at = GREATEST(attempt_at, NOW() + duration),
        attempts = attempts + COALESCE(extra_retries, 0)
    WHERE id = msg_id;

    UPDATE mq_payloads
    SET
        payload_json = COALESCE(new_payload_json::JSONB, payload_json),
        payload_bytes = COALESCE(new_payload_bytes, payload_bytes)
    WHERE
        id = msg_id;
$$;


ALTER FUNCTION public.mq_checkpoint(msg_id uuid, duration interval, new_payload_json text, new_payload_bytes bytea, extra_retries integer) OWNER TO carbide_development;

--
-- Name: mq_clear(text[]); Type: FUNCTION; Schema: public; Owner: carbide_development
--

CREATE FUNCTION public.mq_clear(channel_names text[]) RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
    WITH deleted_ids AS (
        DELETE FROM mq_msgs WHERE channel_name = ANY(channel_names) RETURNING id
    )
    DELETE FROM mq_payloads WHERE id IN (SELECT id FROM deleted_ids);
END;
$$;


ALTER FUNCTION public.mq_clear(channel_names text[]) OWNER TO carbide_development;

--
-- Name: mq_clear_all(); Type: FUNCTION; Schema: public; Owner: carbide_development
--

CREATE FUNCTION public.mq_clear_all() RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
    WITH deleted_ids AS (
        DELETE FROM mq_msgs RETURNING id
    )
    DELETE FROM mq_payloads WHERE id IN (SELECT id FROM deleted_ids);
END;
$$;


ALTER FUNCTION public.mq_clear_all() OWNER TO carbide_development;

--
-- Name: mq_commit(uuid[]); Type: FUNCTION; Schema: public; Owner: carbide_development
--

CREATE FUNCTION public.mq_commit(msg_ids uuid[]) RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
    UPDATE mq_msgs
    SET
        attempt_at = attempt_at - commit_interval,
        commit_interval = NULL
    WHERE id = ANY(msg_ids)
    AND commit_interval IS NOT NULL;
END;
$$;


ALTER FUNCTION public.mq_commit(msg_ids uuid[]) OWNER TO carbide_development;

--
-- Name: mq_delete(uuid[]); Type: FUNCTION; Schema: public; Owner: carbide_development
--

CREATE FUNCTION public.mq_delete(msg_ids uuid[]) RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
    PERFORM pg_notify(CONCAT('mq_', channel_name), '')
    FROM mq_msgs
    WHERE id = ANY(msg_ids)
    AND after_message_id = uuid_nil()
    GROUP BY channel_name;

    IF FOUND THEN
        PERFORM pg_notify('mq', '');
    END IF;

    DELETE FROM mq_msgs WHERE id = ANY(msg_ids);
    DELETE FROM mq_payloads WHERE id = ANY(msg_ids);
END;
$$;


ALTER FUNCTION public.mq_delete(msg_ids uuid[]) OWNER TO carbide_development;

--
-- Name: mq_insert(public.mq_new_t[]); Type: FUNCTION; Schema: public; Owner: carbide_development
--

CREATE FUNCTION public.mq_insert(new_messages public.mq_new_t[]) RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
    PERFORM pg_notify(CONCAT('mq_', channel_name), '')
    FROM unnest(new_messages) AS new_msgs
    GROUP BY channel_name;

    IF FOUND THEN
        PERFORM pg_notify('mq', '');
    END IF;

    INSERT INTO mq_payloads (
        id,
        name,
        payload_json,
        payload_bytes
    ) SELECT
        id,
        name,
        payload_json::JSONB,
        payload_bytes
    FROM UNNEST(new_messages);

    INSERT INTO mq_msgs (
        id,
        attempt_at,
        attempts,
        retry_backoff,
        channel_name,
        channel_args,
        commit_interval,
        after_message_id
    )
    SELECT
        id,
        NOW() + delay + COALESCE(commit_interval, INTERVAL '0'),
        retries + 1,
        retry_backoff,
        channel_name,
        channel_args,
        commit_interval,
        CASE WHEN ordered
            THEN
                LAG(id, 1, mq_latest_message(channel_name, channel_args))
                OVER (PARTITION BY channel_name, channel_args, ordered ORDER BY id)
            ELSE
                NULL
            END
    FROM UNNEST(new_messages);
END;
$$;


ALTER FUNCTION public.mq_insert(new_messages public.mq_new_t[]) OWNER TO carbide_development;

--
-- Name: mq_keep_alive(uuid[], interval); Type: FUNCTION; Schema: public; Owner: carbide_development
--

CREATE FUNCTION public.mq_keep_alive(msg_ids uuid[], duration interval) RETURNS void
    LANGUAGE sql
    AS $$
    UPDATE mq_msgs
    SET
        attempt_at = NOW() + duration,
        commit_interval = commit_interval + ((NOW() + duration) - attempt_at)
    WHERE id = ANY(msg_ids)
    AND attempt_at < NOW() + duration;
$$;


ALTER FUNCTION public.mq_keep_alive(msg_ids uuid[], duration interval) OWNER TO carbide_development;

--
-- Name: mq_latest_message(text, text); Type: FUNCTION; Schema: public; Owner: carbide_development
--

CREATE FUNCTION public.mq_latest_message(from_channel_name text, from_channel_args text) RETURNS uuid
    LANGUAGE sql STABLE
    AS $$
    SELECT COALESCE(
        (
            SELECT id FROM mq_msgs
            WHERE channel_name = from_channel_name
            AND channel_args = from_channel_args
            AND after_message_id IS NOT NULL
            AND id != uuid_nil()
            AND NOT EXISTS(
                SELECT * FROM mq_msgs AS mq_msgs2
                WHERE mq_msgs2.after_message_id = mq_msgs.id
            )
            ORDER BY created_at DESC
            LIMIT 1
        ),
        uuid_nil()
    )
$$;


ALTER FUNCTION public.mq_latest_message(from_channel_name text, from_channel_args text) OWNER TO carbide_development;

--
-- Name: mq_poll(text[], integer); Type: FUNCTION; Schema: public; Owner: carbide_development
--

CREATE FUNCTION public.mq_poll(channel_names text[], batch_size integer DEFAULT 1) RETURNS TABLE(id uuid, is_committed boolean, name text, payload_json text, payload_bytes bytea, retry_backoff interval, wait_time interval)
    LANGUAGE plpgsql
    AS $$
BEGIN
    RETURN QUERY UPDATE mq_msgs
    SET
        attempt_at = CASE WHEN mq_msgs.attempts = 1 THEN NULL ELSE NOW() + mq_msgs.retry_backoff END,
        attempts = mq_msgs.attempts - 1,
        retry_backoff = mq_msgs.retry_backoff * 2
    FROM (
        SELECT
            msgs.id
        FROM mq_active_channels(channel_names, batch_size) AS active_channels
        INNER JOIN LATERAL (
            SELECT mq_msgs.id FROM mq_msgs
            WHERE mq_msgs.id != uuid_nil()
            AND mq_msgs.attempt_at <= NOW()
            AND mq_msgs.channel_name = active_channels.name
            AND mq_msgs.channel_args = active_channels.args
            AND NOT mq_uuid_exists(mq_msgs.after_message_id)
            ORDER BY mq_msgs.attempt_at ASC
            LIMIT batch_size
        ) AS msgs ON TRUE
        LIMIT batch_size
    ) AS messages_to_update
    LEFT JOIN mq_payloads ON mq_payloads.id = messages_to_update.id
    WHERE mq_msgs.id = messages_to_update.id
    AND mq_msgs.attempt_at <= NOW()
    RETURNING
        mq_msgs.id,
        mq_msgs.commit_interval IS NULL,
        mq_payloads.name,
        mq_payloads.payload_json::TEXT,
        mq_payloads.payload_bytes,
        mq_msgs.retry_backoff / 2,
        interval '0' AS wait_time;

    IF NOT FOUND THEN
        RETURN QUERY SELECT
            NULL::UUID,
            NULL::BOOLEAN,
            NULL::TEXT,
            NULL::TEXT,
            NULL::BYTEA,
            NULL::INTERVAL,
            MIN(mq_msgs.attempt_at) - NOW()
        FROM mq_msgs
        WHERE mq_msgs.id != uuid_nil()
        AND NOT mq_uuid_exists(mq_msgs.after_message_id)
        AND (channel_names IS NULL OR mq_msgs.channel_name = ANY(channel_names));
    END IF;
END;
$$;


ALTER FUNCTION public.mq_poll(channel_names text[], batch_size integer) OWNER TO carbide_development;

--
-- Name: mq_uuid_exists(uuid); Type: FUNCTION; Schema: public; Owner: carbide_development
--

CREATE FUNCTION public.mq_uuid_exists(id uuid) RETURNS boolean
    LANGUAGE sql IMMUTABLE
    AS $$
	SELECT id IS NOT NULL AND id != uuid_nil()
$$;


ALTER FUNCTION public.mq_uuid_exists(id uuid) OWNER TO carbide_development;

--
-- Name: network_segment_state_history_keep_limit(); Type: FUNCTION; Schema: public; Owner: carbide_development
--

CREATE FUNCTION public.network_segment_state_history_keep_limit() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
	DELETE FROM network_segment_state_history WHERE segment_id=NEW.segment_id AND id NOT IN (SELECT id from network_segment_state_history where segment_id=NEW.segment_id ORDER BY id DESC LIMIT 250);
	RETURN NULL;
END;
$$;


ALTER FUNCTION public.network_segment_state_history_keep_limit() OWNER TO carbide_development;

--
-- Name: update_machine_updated_trigger(); Type: FUNCTION; Schema: public; Owner: carbide_development
--

CREATE FUNCTION public.update_machine_updated_trigger() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
	NEW.updated := NOW();
	RETURN NEW;
END
$$;


ALTER FUNCTION public.update_machine_updated_trigger() OWNER TO carbide_development;

--
-- Name: update_timestamp_bg_status(); Type: FUNCTION; Schema: public; Owner: carbide_development
--

CREATE FUNCTION public.update_timestamp_bg_status() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
   NEW.last_updated = now();
   RETURN NEW;
END;
$$;


ALTER FUNCTION public.update_timestamp_bg_status() OWNER TO carbide_development;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: _sqlx_migrations; Type: TABLE; Schema: public; Owner: carbide_development
--

CREATE TABLE public._sqlx_migrations (
    version bigint NOT NULL,
    description text NOT NULL,
    installed_on timestamp with time zone DEFAULT now() NOT NULL,
    success boolean NOT NULL,
    checksum bytea NOT NULL,
    execution_time bigint NOT NULL
);


ALTER TABLE public._sqlx_migrations OWNER TO carbide_development;

--
-- Name: bg_status; Type: TABLE; Schema: public; Owner: carbide_development
--

CREATE TABLE public.bg_status (
    id uuid NOT NULL,
    status jsonb,
    last_updated timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.bg_status OWNER TO carbide_development;

--
-- Name: dhcp_entries; Type: TABLE; Schema: public; Owner: carbide_development
--

CREATE TABLE public.dhcp_entries (
    machine_interface_id uuid NOT NULL,
    vendor_string character varying NOT NULL
);


ALTER TABLE public.dhcp_entries OWNER TO carbide_development;

--
-- Name: domains; Type: TABLE; Schema: public; Owner: carbide_development
--

CREATE TABLE public.domains (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name character varying NOT NULL,
    created timestamp with time zone DEFAULT now() NOT NULL,
    updated timestamp with time zone DEFAULT now() NOT NULL,
    deleted timestamp with time zone,
    CONSTRAINT domain_name_lower_case CHECK (((name)::text = lower((name)::text))),
    CONSTRAINT valid_domain_name_regex CHECK (((name)::text ~ '^(?!.*?_.*?)(?!(?:[\w]+?\.)?\-[\w\.\-]*?)(?![\w]+?\-\.(?:[\w\.\-]+?))(?=[\w])(?=[\w\.\-]*?\.+[\w\.\-]*?)(?![\w\.\-]{254})(?!(?:\.?[\w\-\.]*?[\w\-]{64,}\.)+?)[\w\.\-]+?(?<![\w\-\.]*?\.[\d]+?)(?<=[\w\-]{2,})(?<![\w\-]{25})$'::text))
);


ALTER TABLE public.domains OWNER TO carbide_development;

--
-- Name: machine_interface_addresses; Type: TABLE; Schema: public; Owner: carbide_development
--

CREATE TABLE public.machine_interface_addresses (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    interface_id uuid NOT NULL,
    address inet NOT NULL
);


ALTER TABLE public.machine_interface_addresses OWNER TO carbide_development;

--
-- Name: machine_interfaces; Type: TABLE; Schema: public; Owner: carbide_development
--

CREATE TABLE public.machine_interfaces (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    attached_dpu_machine_id character varying(64),
    machine_id character varying(64),
    segment_id uuid NOT NULL,
    mac_address macaddr NOT NULL,
    domain_id uuid,
    primary_interface boolean NOT NULL,
    hostname character varying(63) NOT NULL
);


ALTER TABLE public.machine_interfaces OWNER TO carbide_development;

--
-- Name: dns_records; Type: VIEW; Schema: public; Owner: carbide_development
--

CREATE VIEW public.dns_records AS
 SELECT concat(concat(machine_interfaces.hostname, '.', domains.name), '.') AS q_name,
    machine_interface_addresses.address AS resource_record
   FROM ((public.machine_interfaces
     JOIN public.machine_interface_addresses ON ((machine_interface_addresses.interface_id = machine_interfaces.id)))
     JOIN public.domains ON (((domains.id = machine_interfaces.domain_id) AND (machine_interfaces.primary_interface = true))));


ALTER TABLE public.dns_records OWNER TO carbide_development;

--
-- Name: machines; Type: TABLE; Schema: public; Owner: carbide_development
--

CREATE TABLE public.machines (
    id character varying(64) DEFAULT 'INVALID_MACHINE'::character varying NOT NULL,
    supported_instance_type uuid,
    created timestamp with time zone DEFAULT now() NOT NULL,
    updated timestamp with time zone DEFAULT now() NOT NULL,
    deployed timestamp with time zone,
    controller_state_version character varying(64) DEFAULT 'V1-T1666644937952268'::character varying NOT NULL,
    controller_state jsonb DEFAULT '{"state": "created"}'::jsonb NOT NULL,
    last_reboot_time timestamp with time zone,
    last_cleanup_time timestamp with time zone,
    last_discovery_time timestamp with time zone,
    network_status_observation jsonb,
    network_config_version character varying(64) DEFAULT 'V1-T1666644937952267'::character varying NOT NULL,
    network_config jsonb DEFAULT '{}'::jsonb NOT NULL
);


ALTER TABLE public.machines OWNER TO carbide_development;

--
-- Name: dpu_machines; Type: VIEW; Schema: public; Owner: carbide_development
--

CREATE VIEW public.dpu_machines AS
 SELECT machines.id AS machine_id,
    machine_interfaces.id AS machine_interfaces_id,
    machine_interfaces.mac_address,
    machine_interface_addresses.address,
    machine_interfaces.hostname
   FROM ((public.machine_interfaces
     LEFT JOIN public.machines ON (((machine_interfaces.machine_id)::text = (machines.id)::text)))
     JOIN public.machine_interface_addresses ON ((machine_interface_addresses.interface_id = machine_interfaces.id)))
  WHERE ((machine_interfaces.attached_dpu_machine_id IS NOT NULL) AND ((machine_interfaces.attached_dpu_machine_id)::text = (machine_interfaces.machine_id)::text));


ALTER TABLE public.dpu_machines OWNER TO carbide_development;

--
-- Name: host_machines; Type: VIEW; Schema: public; Owner: carbide_development
--

CREATE VIEW public.host_machines AS
 SELECT machines.id AS machine_id,
    machine_interfaces.id AS machine_interfaces_id,
    machine_interfaces.mac_address,
    machine_interface_addresses.address,
    machine_interfaces.hostname
   FROM ((public.machine_interfaces
     LEFT JOIN public.machines ON (((machine_interfaces.machine_id)::text = (machines.id)::text)))
     JOIN public.machine_interface_addresses ON ((machine_interface_addresses.interface_id = machine_interfaces.id)))
  WHERE ((machine_interfaces.attached_dpu_machine_id IS NOT NULL) AND (machine_interfaces.machine_id IS NOT NULL) AND ((machine_interfaces.attached_dpu_machine_id)::text <> (machine_interfaces.machine_id)::text));


ALTER TABLE public.host_machines OWNER TO carbide_development;

--
-- Name: ib_subnets; Type: TABLE; Schema: public; Owner: carbide_development
--

CREATE TABLE public.ib_subnets (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name character varying NOT NULL,
    vpc_id uuid NOT NULL,
    config_version character varying(64) NOT NULL,
    status jsonb,
    created timestamp with time zone DEFAULT now() NOT NULL,
    updated timestamp with time zone DEFAULT now() NOT NULL,
    deleted timestamp with time zone,
    controller_state_version character varying(64) DEFAULT 'V1-T1666644937952268'::character varying NOT NULL,
    controller_state jsonb DEFAULT '{"state": "provisioning"}'::jsonb NOT NULL,
    pkey smallint NOT NULL,
    mtu integer NOT NULL,
    rate_limit integer NOT NULL,
    service_level integer NOT NULL
);


ALTER TABLE public.ib_subnets OWNER TO carbide_development;

--
-- Name: ibsubnet_controller_lock; Type: TABLE; Schema: public; Owner: carbide_development
--

CREATE TABLE public.ibsubnet_controller_lock (
    id uuid DEFAULT gen_random_uuid() NOT NULL
);


ALTER TABLE public.ibsubnet_controller_lock OWNER TO carbide_development;

--
-- Name: instance_addresses; Type: TABLE; Schema: public; Owner: carbide_development
--

CREATE TABLE public.instance_addresses (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    instance_id uuid NOT NULL,
    circuit_id text NOT NULL,
    address inet NOT NULL
);


ALTER TABLE public.instance_addresses OWNER TO carbide_development;

--
-- Name: instances; Type: TABLE; Schema: public; Owner: carbide_development
--

CREATE TABLE public.instances (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    machine_id character varying(64) NOT NULL,
    requested timestamp with time zone DEFAULT now() NOT NULL,
    started timestamp with time zone DEFAULT now() NOT NULL,
    finished timestamp with time zone,
    user_data text,
    custom_ipxe text DEFAULT 'need a proper string'::text NOT NULL,
    ssh_keys text[],
    use_custom_pxe_on_boot boolean DEFAULT false NOT NULL,
    network_config_version character varying(64) DEFAULT 'V1-T1666644937952267'::character varying NOT NULL,
    network_config jsonb DEFAULT '{}'::jsonb NOT NULL,
    network_status_observation jsonb DEFAULT 'null'::jsonb NOT NULL,
    tenant_org text DEFAULT 'UNKNOWN'::text,
    deleted timestamp with time zone
);


ALTER TABLE public.instances OWNER TO carbide_development;

--
-- Name: network_prefixes; Type: TABLE; Schema: public; Owner: carbide_development
--

CREATE TABLE public.network_prefixes (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    segment_id uuid NOT NULL,
    prefix cidr NOT NULL,
    gateway inet,
    num_reserved integer DEFAULT 0 NOT NULL,
    circuit_id text,
    CONSTRAINT gateway_within_network CHECK ((gateway << (prefix)::inet)),
    CONSTRAINT no_gateway_on_ipv6 CHECK ((((family((prefix)::inet) = 6) AND (gateway IS NULL)) OR (family((prefix)::inet) = 4)))
);


ALTER TABLE public.network_prefixes OWNER TO carbide_development;

--
-- Name: network_segments; Type: TABLE; Schema: public; Owner: carbide_development
--

CREATE TABLE public.network_segments (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name character varying NOT NULL,
    subdomain_id uuid,
    vpc_id uuid,
    mtu integer DEFAULT 1500 NOT NULL,
    version character varying(64) NOT NULL,
    created timestamp with time zone DEFAULT now() NOT NULL,
    updated timestamp with time zone DEFAULT now() NOT NULL,
    deleted timestamp with time zone,
    vni_id integer,
    controller_state_version character varying(64) DEFAULT 'V1-T1666644937952268'::character varying NOT NULL,
    controller_state jsonb DEFAULT '{"state": "provisioning"}'::jsonb NOT NULL,
    vlan_id smallint,
    network_segment_type public.network_segment_type_t DEFAULT 'tenant'::public.network_segment_type_t NOT NULL,
    CONSTRAINT network_segments_mtu_check CHECK (((mtu >= 576) AND (mtu <= 9000))),
    CONSTRAINT network_segments_vlan_id_check CHECK (((0 <= vlan_id) AND (vlan_id < 4096)))
);


ALTER TABLE public.network_segments OWNER TO carbide_development;

--
-- Name: instance_dhcp_records; Type: VIEW; Schema: public; Owner: carbide_development
--

CREATE VIEW public.instance_dhcp_records AS
 SELECT machines.id AS machine_id,
    machine_interfaces.id AS machine_interface_id,
    network_segments.id AS segment_id,
    network_segments.subdomain_id,
        CASE
            WHEN (network_segments.subdomain_id IS NOT NULL) THEN concat(machine_interfaces.hostname, '.', ( SELECT domains_1.name
               FROM public.domains domains_1
              WHERE (domains_1.id = network_segments.subdomain_id)))
            ELSE concat(machine_interfaces.hostname, '.unknowndomain')
        END AS fqdn,
    instance_addresses.address,
    network_segments.mtu,
    network_prefixes.prefix,
    network_prefixes.gateway,
    network_prefixes.circuit_id
   FROM (((((((public.instances i
     JOIN LATERAL jsonb_array_elements((i.network_config -> 'interfaces'::text)) netconf(element) ON (true))
     JOIN public.machines ON (((i.machine_id)::text = (machines.id)::text)))
     JOIN public.machine_interfaces ON (((machine_interfaces.machine_id)::text = (machines.id)::text)))
     JOIN public.domains ON ((domains.id = machine_interfaces.domain_id)))
     JOIN public.network_segments ON ((network_segments.id = ((netconf.element ->> 'network_segment_id'::text))::uuid)))
     JOIN public.network_prefixes ON ((network_prefixes.segment_id = network_segments.id)))
     JOIN public.instance_addresses ON ((instance_addresses.instance_id = i.id)))
  WHERE (instance_addresses.address << (network_prefixes.prefix)::inet);


ALTER TABLE public.instance_dhcp_records OWNER TO carbide_development;

--
-- Name: instance_types; Type: TABLE; Schema: public; Owner: carbide_development
--

CREATE TABLE public.instance_types (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    short_name character varying(32) NOT NULL,
    description text NOT NULL,
    capabilities public.instance_type_capabilities DEFAULT 'default'::public.instance_type_capabilities NOT NULL,
    active boolean DEFAULT true NOT NULL,
    created timestamp with time zone DEFAULT now() NOT NULL,
    updated timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.instance_types OWNER TO carbide_development;

--
-- Name: machine_console_metadata; Type: TABLE; Schema: public; Owner: carbide_development
--

CREATE TABLE public.machine_console_metadata (
    machine_id character varying(64) NOT NULL,
    username character varying NOT NULL,
    role public.user_roles NOT NULL,
    password character varying(16) NOT NULL,
    bmctype public.console_type DEFAULT 'ipmi'::public.console_type NOT NULL
);


ALTER TABLE public.machine_console_metadata OWNER TO carbide_development;

--
-- Name: machine_dhcp_records; Type: VIEW; Schema: public; Owner: carbide_development
--

CREATE VIEW public.machine_dhcp_records AS
 SELECT machines.id AS machine_id,
    machine_interfaces.id AS machine_interface_id,
    network_segments.id AS segment_id,
    network_segments.subdomain_id,
    concat(machine_interfaces.hostname, '.', domains.name) AS fqdn,
    machine_interfaces.mac_address,
    machine_interface_addresses.address,
    network_segments.mtu,
    network_prefixes.prefix,
    network_prefixes.gateway
   FROM (((((public.machine_interfaces
     LEFT JOIN public.machines ON (((machine_interfaces.machine_id)::text = (machines.id)::text)))
     JOIN public.network_segments ON ((network_segments.id = machine_interfaces.segment_id)))
     JOIN public.network_prefixes ON ((network_prefixes.segment_id = network_segments.id)))
     JOIN public.machine_interface_addresses ON ((machine_interface_addresses.interface_id = machine_interfaces.id)))
     JOIN public.domains ON ((domains.id = machine_interfaces.domain_id)))
  WHERE (machine_interface_addresses.address << (network_prefixes.prefix)::inet);


ALTER TABLE public.machine_dhcp_records OWNER TO carbide_development;

--
-- Name: machine_state_controller_lock; Type: TABLE; Schema: public; Owner: carbide_development
--

CREATE TABLE public.machine_state_controller_lock (
    id uuid DEFAULT gen_random_uuid() NOT NULL
);


ALTER TABLE public.machine_state_controller_lock OWNER TO carbide_development;

--
-- Name: machine_state_history; Type: TABLE; Schema: public; Owner: carbide_development
--

CREATE TABLE public.machine_state_history (
    id bigint NOT NULL,
    machine_id character varying(64) NOT NULL,
    state jsonb NOT NULL,
    state_version character varying(64) NOT NULL,
    "timestamp" timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.machine_state_history OWNER TO carbide_development;

--
-- Name: machine_state_history_id_seq; Type: SEQUENCE; Schema: public; Owner: carbide_development
--

ALTER TABLE public.machine_state_history ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME public.machine_state_history_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: machine_topologies; Type: TABLE; Schema: public; Owner: carbide_development
--

CREATE TABLE public.machine_topologies (
    machine_id character varying(64) NOT NULL,
    topology jsonb NOT NULL,
    created timestamp with time zone DEFAULT now() NOT NULL,
    updated timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.machine_topologies OWNER TO carbide_development;

--
-- Name: mq_msgs; Type: TABLE; Schema: public; Owner: carbide_development
--

CREATE TABLE public.mq_msgs (
    id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    attempt_at timestamp with time zone DEFAULT now(),
    attempts integer DEFAULT 5 NOT NULL,
    retry_backoff interval DEFAULT '00:00:01'::interval NOT NULL,
    channel_name text NOT NULL,
    channel_args text NOT NULL,
    commit_interval interval,
    after_message_id uuid DEFAULT public.uuid_nil()
);


ALTER TABLE public.mq_msgs OWNER TO carbide_development;

--
-- Name: mq_payloads; Type: TABLE; Schema: public; Owner: carbide_development
--

CREATE TABLE public.mq_payloads (
    id uuid NOT NULL,
    name text NOT NULL,
    payload_json jsonb,
    payload_bytes bytea
);


ALTER TABLE public.mq_payloads OWNER TO carbide_development;

--
-- Name: network_segment_state_history; Type: TABLE; Schema: public; Owner: carbide_development
--

CREATE TABLE public.network_segment_state_history (
    id bigint NOT NULL,
    segment_id uuid NOT NULL,
    state jsonb NOT NULL,
    state_version character varying(64) NOT NULL,
    "timestamp" timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.network_segment_state_history OWNER TO carbide_development;

--
-- Name: network_segment_state_history_id_seq; Type: SEQUENCE; Schema: public; Owner: carbide_development
--

ALTER TABLE public.network_segment_state_history ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME public.network_segment_state_history_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: network_segments_controller_lock; Type: TABLE; Schema: public; Owner: carbide_development
--

CREATE TABLE public.network_segments_controller_lock (
    id uuid DEFAULT gen_random_uuid() NOT NULL
);


ALTER TABLE public.network_segments_controller_lock OWNER TO carbide_development;

--
-- Name: resource_pool; Type: TABLE; Schema: public; Owner: carbide_development
--

CREATE TABLE public.resource_pool (
    id bigint NOT NULL,
    name character varying(32) NOT NULL,
    value character varying(64) NOT NULL,
    created timestamp with time zone DEFAULT now() NOT NULL,
    allocated timestamp with time zone,
    state jsonb DEFAULT '{}'::jsonb NOT NULL,
    state_version character varying(64) DEFAULT '1'::character varying NOT NULL,
    value_type public.resource_pool_type NOT NULL
);


ALTER TABLE public.resource_pool OWNER TO carbide_development;

--
-- Name: resource_pool_id_seq; Type: SEQUENCE; Schema: public; Owner: carbide_development
--

ALTER TABLE public.resource_pool ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME public.resource_pool_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: ssh_public_keys; Type: TABLE; Schema: public; Owner: carbide_development
--

CREATE TABLE public.ssh_public_keys (
    username character varying NOT NULL,
    role public.user_roles NOT NULL,
    pubkeys character varying[]
);


ALTER TABLE public.ssh_public_keys OWNER TO carbide_development;

--
-- Name: tags; Type: TABLE; Schema: public; Owner: carbide_development
--

CREATE TABLE public.tags (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    slug character varying(50) NOT NULL,
    name character varying(50) NOT NULL
);


ALTER TABLE public.tags OWNER TO carbide_development;

--
-- Name: tags_machine; Type: TABLE; Schema: public; Owner: carbide_development
--

CREATE TABLE public.tags_machine (
    tag_id uuid,
    target_id character varying(64)
);


ALTER TABLE public.tags_machine OWNER TO carbide_development;

--
-- Name: tags_networksegment; Type: TABLE; Schema: public; Owner: carbide_development
--

CREATE TABLE public.tags_networksegment (
    tag_id uuid,
    target_id uuid
);


ALTER TABLE public.tags_networksegment OWNER TO carbide_development;

--
-- Name: tenant_keysets; Type: TABLE; Schema: public; Owner: carbide_development
--

CREATE TABLE public.tenant_keysets (
    organization_id text NOT NULL,
    keyset_id text NOT NULL,
    content jsonb NOT NULL,
    version character varying(64) NOT NULL
);


ALTER TABLE public.tenant_keysets OWNER TO carbide_development;

--
-- Name: tenants; Type: TABLE; Schema: public; Owner: carbide_development
--

CREATE TABLE public.tenants (
    organization_id text NOT NULL,
    version character varying(64) NOT NULL
);


ALTER TABLE public.tenants OWNER TO carbide_development;

--
-- Name: vpcs; Type: TABLE; Schema: public; Owner: carbide_development
--

CREATE TABLE public.vpcs (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name character varying NOT NULL,
    organization_id character varying,
    version character varying(64) NOT NULL,
    created timestamp with time zone DEFAULT now() NOT NULL,
    updated timestamp with time zone DEFAULT now() NOT NULL,
    deleted timestamp with time zone,
    network_virtualization_type public.network_virtualization_type_t DEFAULT 'etv'::public.network_virtualization_type_t NOT NULL,
    vni integer
);


ALTER TABLE public.vpcs OWNER TO carbide_development;

--
-- Name: _sqlx_migrations _sqlx_migrations_pkey; Type: CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public._sqlx_migrations
    ADD CONSTRAINT _sqlx_migrations_pkey PRIMARY KEY (version);


--
-- Name: bg_status bg_status_pkey; Type: CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.bg_status
    ADD CONSTRAINT bg_status_pkey PRIMARY KEY (id);


--
-- Name: dhcp_entries dhcp_entries_pkey; Type: CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.dhcp_entries
    ADD CONSTRAINT dhcp_entries_pkey PRIMARY KEY (machine_interface_id, vendor_string);


--
-- Name: domains domains_pkey; Type: CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.domains
    ADD CONSTRAINT domains_pkey PRIMARY KEY (id);


--
-- Name: machine_interfaces fqdn_must_be_unique; Type: CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.machine_interfaces
    ADD CONSTRAINT fqdn_must_be_unique UNIQUE (domain_id, hostname);

--
-- Name: ib_subnets ib_subnets_pkey; Type: CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.ib_subnets
    ADD CONSTRAINT ib_subnets_pkey PRIMARY KEY (id);


--
-- Name: ib_subnets ib_subnets_pkey_key; Type: CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.ib_subnets
    ADD CONSTRAINT ib_subnets_pkey_key UNIQUE (pkey);


--
-- Name: instance_types instance_types_pkey; Type: CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.instance_types
    ADD CONSTRAINT instance_types_pkey PRIMARY KEY (id);


--
-- Name: instances instances_pkey; Type: CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.instances
    ADD CONSTRAINT instances_pkey PRIMARY KEY (id);


--
-- Name: instances instances_unique_machine_id; Type: CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.instances
    ADD CONSTRAINT instances_unique_machine_id UNIQUE (machine_id);


--
-- Name: machine_console_metadata machine_console_metadata_machine_id_username_role_key; Type: CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.machine_console_metadata
    ADD CONSTRAINT machine_console_metadata_machine_id_username_role_key UNIQUE (machine_id, username, role);


--
-- Name: machine_interface_addresses machine_interface_addresses_interface_id_address_key; Type: CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.machine_interface_addresses
    ADD CONSTRAINT machine_interface_addresses_interface_id_address_key UNIQUE (interface_id, address);


--
-- Name: machine_interface_addresses machine_interface_addresses_pkey; Type: CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.machine_interface_addresses
    ADD CONSTRAINT machine_interface_addresses_pkey PRIMARY KEY (id);


--
-- Name: machine_interfaces machine_interfaces_pkey; Type: CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.machine_interfaces
    ADD CONSTRAINT machine_interfaces_pkey PRIMARY KEY (id);


--
-- Name: machine_interfaces machine_interfaces_segment_id_mac_address_key; Type: CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.machine_interfaces
    ADD CONSTRAINT machine_interfaces_segment_id_mac_address_key UNIQUE (segment_id, mac_address);


--
-- Name: machine_state_history machine_state_history_pkey; Type: CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.machine_state_history
    ADD CONSTRAINT machine_state_history_pkey PRIMARY KEY (id);


--
-- Name: machine_topologies machine_topologies_pkey; Type: CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.machine_topologies
    ADD CONSTRAINT machine_topologies_pkey PRIMARY KEY (machine_id);


--
-- Name: machines machines_pkey; Type: CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.machines
    ADD CONSTRAINT machines_pkey PRIMARY KEY (id);


--
-- Name: mq_msgs mq_msgs_pkey; Type: CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.mq_msgs
    ADD CONSTRAINT mq_msgs_pkey PRIMARY KEY (id);


--
-- Name: mq_payloads mq_payloads_pkey; Type: CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.mq_payloads
    ADD CONSTRAINT mq_payloads_pkey PRIMARY KEY (id);


--
-- Name: network_prefixes network_prefixes_circuit_id_key; Type: CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.network_prefixes
    ADD CONSTRAINT network_prefixes_circuit_id_key UNIQUE (circuit_id);


--
-- Name: network_prefixes network_prefixes_pkey; Type: CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.network_prefixes
    ADD CONSTRAINT network_prefixes_pkey PRIMARY KEY (id);


--
-- Name: network_prefixes network_prefixes_prefix_excl; Type: CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.network_prefixes
    ADD CONSTRAINT network_prefixes_prefix_excl EXCLUDE USING gist (prefix inet_ops WITH &&);


--
-- Name: network_segment_state_history network_segment_state_history_pkey; Type: CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.network_segment_state_history
    ADD CONSTRAINT network_segment_state_history_pkey PRIMARY KEY (id);


--
-- Name: network_segments network_segments_pkey; Type: CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.network_segments
    ADD CONSTRAINT network_segments_pkey PRIMARY KEY (id);


--
-- Name: network_segments network_segments_vlan_id_key; Type: CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.network_segments
    ADD CONSTRAINT network_segments_vlan_id_key UNIQUE (vlan_id);


--
-- Name: machine_interfaces one_primary_interface_per_machine; Type: CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.machine_interfaces
    ADD CONSTRAINT one_primary_interface_per_machine UNIQUE (machine_id, primary_interface);


--
-- Name: resource_pool resource_pool_name_value_key; Type: CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.resource_pool
    ADD CONSTRAINT resource_pool_name_value_key UNIQUE (name, value);


--
-- Name: resource_pool resource_pool_pkey; Type: CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.resource_pool
    ADD CONSTRAINT resource_pool_pkey PRIMARY KEY (id);


--
-- Name: ssh_public_keys ssh_public_keys_username_key; Type: CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.ssh_public_keys
    ADD CONSTRAINT ssh_public_keys_username_key UNIQUE (username);


--
-- Name: tags_machine tags_machine_tag_id_target_id_key; Type: CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.tags_machine
    ADD CONSTRAINT tags_machine_tag_id_target_id_key UNIQUE (tag_id, target_id);


--
-- Name: tags_networksegment tags_networksegment_tag_id_target_id_key; Type: CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.tags_networksegment
    ADD CONSTRAINT tags_networksegment_tag_id_target_id_key UNIQUE (tag_id, target_id);


--
-- Name: tags tags_pkey; Type: CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.tags
    ADD CONSTRAINT tags_pkey PRIMARY KEY (id);


--
-- Name: tags tags_slug_key; Type: CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.tags
    ADD CONSTRAINT tags_slug_key UNIQUE (slug);


--
-- Name: tenant_keysets tenant_keysets_pkey; Type: CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.tenant_keysets
    ADD CONSTRAINT tenant_keysets_pkey PRIMARY KEY (organization_id, keyset_id);


--
-- Name: tenants tenants_pkey; Type: CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.tenants
    ADD CONSTRAINT tenants_pkey PRIMARY KEY (organization_id);


--
-- Name: vpcs vpcs_pkey; Type: CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.vpcs
    ADD CONSTRAINT vpcs_pkey PRIMARY KEY (id);


--
-- Name: idx_resource_pools_name; Type: INDEX; Schema: public; Owner: carbide_development
--

CREATE INDEX idx_resource_pools_name ON public.resource_pool USING btree (name);


--
-- Name: mq_msgs_channel_name_channel_args_after_message_id_idx; Type: INDEX; Schema: public; Owner: carbide_development
--

CREATE UNIQUE INDEX mq_msgs_channel_name_channel_args_after_message_id_idx ON public.mq_msgs USING btree (channel_name, channel_args, after_message_id);


--
-- Name: mq_msgs_channel_name_channel_args_attempt_at_idx; Type: INDEX; Schema: public; Owner: carbide_development
--

CREATE INDEX mq_msgs_channel_name_channel_args_attempt_at_idx ON public.mq_msgs USING btree (channel_name, channel_args, attempt_at) WHERE ((id <> public.uuid_nil()) AND (NOT public.mq_uuid_exists(after_message_id)));


--
-- Name: mq_msgs_channel_name_channel_args_created_at_id_idx; Type: INDEX; Schema: public; Owner: carbide_development
--

CREATE INDEX mq_msgs_channel_name_channel_args_created_at_id_idx ON public.mq_msgs USING btree (channel_name, channel_args, created_at, id) WHERE ((id <> public.uuid_nil()) AND (after_message_id IS NOT NULL));


--
-- Name: network_prefix_family; Type: INDEX; Schema: public; Owner: carbide_development
--

CREATE UNIQUE INDEX network_prefix_family ON public.network_prefixes USING btree (family((prefix)::inet), segment_id);


--
-- Name: one_address_for_a_family; Type: INDEX; Schema: public; Owner: carbide_development
--

CREATE UNIQUE INDEX one_address_for_a_family ON public.instance_addresses USING btree (instance_id, circuit_id, family(address));


--
-- Name: only_one_admin_network_segment; Type: INDEX; Schema: public; Owner: carbide_development
--

CREATE UNIQUE INDEX only_one_admin_network_segment ON public.network_segments USING btree (network_segment_type) WHERE (network_segment_type = 'admin'::public.network_segment_type_t);


--
-- Name: unique_address_family_on_interface; Type: INDEX; Schema: public; Owner: carbide_development
--

CREATE UNIQUE INDEX unique_address_family_on_interface ON public.machine_interface_addresses USING btree (family(address), interface_id);


--
-- Name: vpcs_unique_active_vni; Type: INDEX; Schema: public; Owner: carbide_development
--

CREATE UNIQUE INDEX vpcs_unique_active_vni ON public.vpcs USING btree (vni) WHERE (deleted IS NULL);


--
-- Name: machines machine_last_updated; Type: TRIGGER; Schema: public; Owner: carbide_development
--

CREATE TRIGGER machine_last_updated BEFORE UPDATE ON public.machines FOR EACH ROW EXECUTE FUNCTION public.update_machine_updated_trigger();


--
-- Name: machine_state_history t_machine_state_history_keep_limit; Type: TRIGGER; Schema: public; Owner: carbide_development
--

CREATE TRIGGER t_machine_state_history_keep_limit AFTER INSERT ON public.machine_state_history FOR EACH ROW EXECUTE FUNCTION public.machine_state_history_keep_limit();


--
-- Name: network_segment_state_history t_network_segment_state_history_keep_limit; Type: TRIGGER; Schema: public; Owner: carbide_development
--

CREATE TRIGGER t_network_segment_state_history_keep_limit AFTER INSERT ON public.network_segment_state_history FOR EACH ROW EXECUTE FUNCTION public.network_segment_state_history_keep_limit();


--
-- Name: bg_status trigger_delete_old_rows_bg_status; Type: TRIGGER; Schema: public; Owner: carbide_development
--

CREATE TRIGGER trigger_delete_old_rows_bg_status AFTER INSERT ON public.bg_status FOR EACH STATEMENT EXECUTE FUNCTION public.delete_old_rows();


--
-- Name: bg_status trigger_update_timestamp_bg_status; Type: TRIGGER; Schema: public; Owner: carbide_development
--

CREATE TRIGGER trigger_update_timestamp_bg_status BEFORE UPDATE ON public.bg_status FOR EACH STATEMENT EXECUTE FUNCTION public.update_timestamp_bg_status();


--
-- Name: dhcp_entries dhcp_entries_machine_interface_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.dhcp_entries
    ADD CONSTRAINT dhcp_entries_machine_interface_id_fkey FOREIGN KEY (machine_interface_id) REFERENCES public.machine_interfaces(id);


--
-- Name: tags_machine fk_tags_machine; Type: FK CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.tags_machine
    ADD CONSTRAINT fk_tags_machine FOREIGN KEY (target_id) REFERENCES public.machines(id);


--
-- Name: tags_machine fk_tags_machine_slug; Type: FK CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.tags_machine
    ADD CONSTRAINT fk_tags_machine_slug FOREIGN KEY (tag_id) REFERENCES public.tags(id) ON DELETE CASCADE;


--
-- Name: tags_networksegment fk_tags_machine_slug; Type: FK CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.tags_networksegment
    ADD CONSTRAINT fk_tags_machine_slug FOREIGN KEY (tag_id) REFERENCES public.tags(id) ON DELETE CASCADE;


--
-- Name: tags_networksegment fk_tags_ns; Type: FK CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.tags_networksegment
    ADD CONSTRAINT fk_tags_ns FOREIGN KEY (target_id) REFERENCES public.network_segments(id) ON DELETE CASCADE;


--
-- Name: ib_subnets ib_subnets_vpc_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.ib_subnets
    ADD CONSTRAINT ib_subnets_vpc_id_fkey FOREIGN KEY (vpc_id) REFERENCES public.vpcs(id);


--
-- Name: instance_addresses instance_addresses_instance_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.instance_addresses
    ADD CONSTRAINT instance_addresses_instance_id_fkey FOREIGN KEY (instance_id) REFERENCES public.instances(id);


--
-- Name: instances instances_machine_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.instances
    ADD CONSTRAINT instances_machine_id_fkey FOREIGN KEY (machine_id) REFERENCES public.machines(id);


--
-- Name: machine_console_metadata machine_console_metadata_machine_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.machine_console_metadata
    ADD CONSTRAINT machine_console_metadata_machine_id_fkey FOREIGN KEY (machine_id) REFERENCES public.machines(id);


--
-- Name: machine_interface_addresses machine_interface_addresses_interface_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.machine_interface_addresses
    ADD CONSTRAINT machine_interface_addresses_interface_id_fkey FOREIGN KEY (interface_id) REFERENCES public.machine_interfaces(id);


--
-- Name: machine_interfaces machine_interfaces_attached_dpu_machine_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.machine_interfaces
    ADD CONSTRAINT machine_interfaces_attached_dpu_machine_id_fkey FOREIGN KEY (attached_dpu_machine_id) REFERENCES public.machines(id);


--
-- Name: machine_interfaces machine_interfaces_domain_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.machine_interfaces
    ADD CONSTRAINT machine_interfaces_domain_id_fkey FOREIGN KEY (domain_id) REFERENCES public.domains(id);


--
-- Name: machine_interfaces machine_interfaces_machine_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.machine_interfaces
    ADD CONSTRAINT machine_interfaces_machine_id_fkey FOREIGN KEY (machine_id) REFERENCES public.machines(id) ON UPDATE CASCADE;


--
-- Name: machine_interfaces machine_interfaces_segment_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.machine_interfaces
    ADD CONSTRAINT machine_interfaces_segment_id_fkey FOREIGN KEY (segment_id) REFERENCES public.network_segments(id);


--
-- Name: machine_topologies machine_topologies_machine_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.machine_topologies
    ADD CONSTRAINT machine_topologies_machine_id_fkey FOREIGN KEY (machine_id) REFERENCES public.machines(id);


--
-- Name: machines machines_supported_instance_type_fkey; Type: FK CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.machines
    ADD CONSTRAINT machines_supported_instance_type_fkey FOREIGN KEY (supported_instance_type) REFERENCES public.instance_types(id);


--
-- Name: mq_msgs mq_msgs_after_message_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.mq_msgs
    ADD CONSTRAINT mq_msgs_after_message_id_fkey FOREIGN KEY (after_message_id) REFERENCES public.mq_msgs(id) ON DELETE SET DEFAULT;


--
-- Name: network_prefixes network_prefixes_segment_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.network_prefixes
    ADD CONSTRAINT network_prefixes_segment_id_fkey FOREIGN KEY (segment_id) REFERENCES public.network_segments(id);


--
-- Name: network_segments network_segments_subdomain_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.network_segments
    ADD CONSTRAINT network_segments_subdomain_id_fkey FOREIGN KEY (subdomain_id) REFERENCES public.domains(id);


--
-- Name: network_segments network_segments_vpc_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.network_segments
    ADD CONSTRAINT network_segments_vpc_id_fkey FOREIGN KEY (vpc_id) REFERENCES public.vpcs(id);

-- Manual updates

-- 20230711095418_bmc_machine.sql

CREATE TABLE public.bmc_machine_controller_lock (
    id uuid DEFAULT gen_random_uuid() NOT NULL
);
ALTER TABLE public.bmc_machine_controller_lock OWNER TO carbide_development;

CREATE TYPE public.bmc_machine_type_t AS ENUM ('dpu', 'host');
ALTER TYPE public.bmc_machine_type_t OWNER TO carbide_development;

CREATE TABLE public.bmc_machine (
  id uuid DEFAULT gen_random_uuid() NOT NULL,

  machine_interface_id uuid NOT NULL,

  -- Bmc type:
  --   * Dpu
  --   * Host
  bmc_type public.bmc_machine_type_t NOT NULL,

  -- The state of BMC Machine:
  --   * Init: 0
  controller_state_version VARCHAR(64) NOT NULL DEFAULT ('V1-T1666644937952268'),
  controller_state         jsonb       NOT NULL DEFAULT ('{"state":"init"}'),

  PRIMARY KEY(id),
  FOREIGN KEY(machine_interface_id) REFERENCES public.machine_interfaces(id)
);
ALTER TABLE public.bmc_machine OWNER TO carbide_development;

-- 20230801424242_add_custom_pxe_table.sql

CREATE TABLE public.machine_boot_override (
  machine_interface_id uuid NOT NULL,
  custom_pxe text,
  custom_user_data text,

  PRIMARY KEY(machine_interface_id),
  FOREIGN KEY(machine_interface_id) REFERENCES public.machine_interfaces(id),
  CONSTRAINT custom_pxe_unique_machine_interface_id UNIQUE(machine_interface_id)
);
ALTER TABLE public.machine_boot_override OWNER TO carbide_development;


--
-- Name: SCHEMA public; Type: ACL; Schema: -; Owner: carbide_development
--

REVOKE USAGE ON SCHEMA public FROM PUBLIC;
GRANT ALL ON SCHEMA public TO PUBLIC;

--
-- PostgreSQL database dump complete
--

