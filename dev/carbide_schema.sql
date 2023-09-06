-- Last updated Sep 06 2023

--
-- Carbide database schema with all migrations applied.
--
-- Created like this and then maintained manually
-- PGPASSWORD=notforprod pg_dump -h 172.20.0.16 --schema-only -U carbide_development > ~/carbide_schema.sql

--
-- PostgreSQL database dump
--

-- Dumped from database version 14.1
-- Dumped by pg_dump version 15.4

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
-- Name: bmc_machine_type_t; Type: TYPE; Schema: public; Owner: carbide_development
--

CREATE TYPE public.bmc_machine_type_t AS ENUM (
    'dpu',
    'host'
);


ALTER TYPE public.bmc_machine_type_t OWNER TO carbide_development;

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
-- Name: bmc_machine; Type: TABLE; Schema: public; Owner: carbide_development
--

CREATE TABLE public.bmc_machine (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    machine_interface_id uuid NOT NULL,
    bmc_type public.bmc_machine_type_t NOT NULL,
    controller_state_version character varying(64) DEFAULT 'V1-T1666644937952268'::character varying NOT NULL,
    controller_state jsonb DEFAULT '{"state": "init"}'::jsonb NOT NULL
);


ALTER TABLE public.bmc_machine OWNER TO carbide_development;

--
-- Name: bmc_machine_controller_lock; Type: TABLE; Schema: public; Owner: carbide_development
--

CREATE TABLE public.bmc_machine_controller_lock (
    id uuid DEFAULT gen_random_uuid() NOT NULL
);


ALTER TABLE public.bmc_machine_controller_lock OWNER TO carbide_development;

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
    network_config jsonb DEFAULT '{}'::jsonb NOT NULL,
    failure_details jsonb DEFAULT '{"cause": "noerror", "source": "noerror", "failed_at": "2023-07-31T11:26:18.261228950+00:00"}'::jsonb NOT NULL,
    maintenance_reference character varying(256),
    maintenance_start_time timestamp with time zone
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
    deleted timestamp with time zone,
    ib_config_version character varying(64) DEFAULT 'V1-T1666644937952267'::character varying NOT NULL,
    ib_config jsonb DEFAULT '{"ib_interfaces": []}'::jsonb NOT NULL,
    ib_status_observation jsonb DEFAULT '{"observed_at": "2023-01-01T00:00:00.000000000Z", "config_version": "V1-T1666644937952267"}'::jsonb NOT NULL,
    keyset_ids text[] DEFAULT '{}'::text[] NOT NULL
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
-- Name: machine_boot_override; Type: TABLE; Schema: public; Owner: carbide_development
--

CREATE TABLE public.machine_boot_override (
    machine_interface_id uuid NOT NULL,
    custom_pxe text,
    custom_user_data text
);


ALTER TABLE public.machine_boot_override OWNER TO carbide_development;

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
-- Name: bmc_machine bmc_machine_pkey; Type: CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.bmc_machine
    ADD CONSTRAINT bmc_machine_pkey PRIMARY KEY (id);


--
-- Name: machine_boot_override custom_pxe_unique_machine_interface_id; Type: CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.machine_boot_override
    ADD CONSTRAINT custom_pxe_unique_machine_interface_id PRIMARY KEY (machine_interface_id);


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
-- Name: bmc_machine bmc_machine_machine_interface_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.bmc_machine
    ADD CONSTRAINT bmc_machine_machine_interface_id_fkey FOREIGN KEY (machine_interface_id) REFERENCES public.machine_interfaces(id);


--
-- Name: dhcp_entries dhcp_entries_machine_interface_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.dhcp_entries
    ADD CONSTRAINT dhcp_entries_machine_interface_id_fkey FOREIGN KEY (machine_interface_id) REFERENCES public.machine_interfaces(id);


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
-- Name: machine_boot_override machine_boot_override_machine_interface_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.machine_boot_override
    ADD CONSTRAINT machine_boot_override_machine_interface_id_fkey FOREIGN KEY (machine_interface_id) REFERENCES public.machine_interfaces(id);


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


--
-- Name: SCHEMA public; Type: ACL; Schema: -; Owner: carbide_development
--

REVOKE USAGE ON SCHEMA public FROM PUBLIC;
GRANT ALL ON SCHEMA public TO PUBLIC;


--
-- PostgreSQL database dump complete
--

