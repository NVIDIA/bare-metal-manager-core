-- HEADER
-- Last updated Jul 19 2024
--
-- Carbide database schema with all migrations applied.
--
-- Created like this:
-- PGPASSWORD=notforprod pg_dump -h 172.20.0.16 --schema-only -U carbide_development > ~/carbide_schema.sql
--
-- Copy this header into new version before committing
-- END HEADER

--
-- PostgreSQL database dump
--

-- Dumped from database version 14.1
-- Dumped by pg_dump version 16.1

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
-- Name: metric_helpers; Type: SCHEMA; Schema: -; Owner: carbide_development
--

CREATE SCHEMA metric_helpers;


ALTER SCHEMA metric_helpers OWNER TO carbide_development;

--
-- Name: public; Type: SCHEMA; Schema: -; Owner: carbide_development
--

-- *not* creating schema, since initdb creates it


ALTER SCHEMA public OWNER TO carbide_development;

--
-- Name: user_management; Type: SCHEMA; Schema: -; Owner: carbide_development
--

CREATE SCHEMA user_management;


ALTER SCHEMA user_management OWNER TO carbide_development;

--
-- Name: pg_stat_statements; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pg_stat_statements WITH SCHEMA public;


--
-- Name: EXTENSION pg_stat_statements; Type: COMMENT; Schema: -; Owner:
--

COMMENT ON EXTENSION pg_stat_statements IS 'track planning and execution statistics of all SQL statements executed';


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
-- Name: dpu_local_ports; Type: TYPE; Schema: public; Owner: carbide_development
--

CREATE TYPE public.dpu_local_ports AS ENUM (
    'oob_net0',
    'p0',
    'p1'
);


ALTER TYPE public.dpu_local_ports OWNER TO carbide_development;

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
-- Name: measurement_approved_type; Type: TYPE; Schema: public; Owner: carbide_development
--

CREATE TYPE public.measurement_approved_type AS ENUM (
    'oneshot',
    'persist'
);


ALTER TYPE public.measurement_approved_type OWNER TO carbide_development;

--
-- Name: measurement_bundle_state; Type: TYPE; Schema: public; Owner: carbide_development
--

CREATE TYPE public.measurement_bundle_state AS ENUM (
    'pending',
    'active',
    'obsolete',
    'retired',
    'revoked'
);


ALTER TYPE public.measurement_bundle_state OWNER TO carbide_development;

--
-- Name: measurement_machine_state; Type: TYPE; Schema: public; Owner: carbide_development
--

CREATE TYPE public.measurement_machine_state AS ENUM (
    'discovered',
    'pendingbundle',
    'measured',
    'measuringfailed'
);


ALTER TYPE public.measurement_machine_state OWNER TO carbide_development;

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
-- Name: network_device_discovered_via; Type: TYPE; Schema: public; Owner: carbide_development
--

CREATE TYPE public.network_device_discovered_via AS ENUM (
    'lldp'
);


ALTER TYPE public.network_device_discovered_via OWNER TO carbide_development;

--
-- Name: network_device_type; Type: TYPE; Schema: public; Owner: carbide_development
--

CREATE TYPE public.network_device_type AS ENUM (
    'ethernet'
);


ALTER TYPE public.network_device_type OWNER TO carbide_development;

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
    'fnn',
    'etv_nvue'
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
-- Name: get_btree_bloat_approx(); Type: FUNCTION; Schema: metric_helpers; Owner: carbide_development
--

CREATE FUNCTION metric_helpers.get_btree_bloat_approx(OUT i_database name, OUT i_schema_name name, OUT i_table_name name, OUT i_index_name name, OUT i_real_size numeric, OUT i_extra_size numeric, OUT i_extra_ratio double precision, OUT i_fill_factor integer, OUT i_bloat_size double precision, OUT i_bloat_ratio double precision, OUT i_is_na boolean) RETURNS SETOF record
    LANGUAGE sql IMMUTABLE STRICT SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $$
SELECT current_database(), nspname AS schemaname, tblname, idxname, bs*(relpages)::bigint AS real_size,
  bs*(relpages-est_pages)::bigint AS extra_size,
  100 * (relpages-est_pages)::float / relpages AS extra_ratio,
  fillfactor,
  CASE WHEN relpages > est_pages_ff
    THEN bs*(relpages-est_pages_ff)
    ELSE 0
  END AS bloat_size,
  100 * (relpages-est_pages_ff)::float / relpages AS bloat_ratio,
  is_na
  -- , 100-(pst).avg_leaf_density AS pst_avg_bloat, est_pages, index_tuple_hdr_bm, maxalign, pagehdr, nulldatawidth, nulldatahdrwidth, reltuples, relpages -- (DEBUG INFO)
FROM (
  SELECT coalesce(1 +
         ceil(reltuples/floor((bs-pageopqdata-pagehdr)/(4+nulldatahdrwidth)::float)), 0 -- ItemIdData size + computed avg size of a tuple (nulldatahdrwidth)
      ) AS est_pages,
      coalesce(1 +
         ceil(reltuples/floor((bs-pageopqdata-pagehdr)*fillfactor/(100*(4+nulldatahdrwidth)::float))), 0
      ) AS est_pages_ff,
      bs, nspname, tblname, idxname, relpages, fillfactor, is_na
      -- , pgstatindex(idxoid) AS pst, index_tuple_hdr_bm, maxalign, pagehdr, nulldatawidth, nulldatahdrwidth, reltuples -- (DEBUG INFO)
  FROM (
      SELECT maxalign, bs, nspname, tblname, idxname, reltuples, relpages, idxoid, fillfactor,
            ( index_tuple_hdr_bm +
                maxalign - CASE -- Add padding to the index tuple header to align on MAXALIGN
                  WHEN index_tuple_hdr_bm%maxalign = 0 THEN maxalign
                  ELSE index_tuple_hdr_bm%maxalign
                END
              + nulldatawidth + maxalign - CASE -- Add padding to the data to align on MAXALIGN
                  WHEN nulldatawidth = 0 THEN 0
                  WHEN nulldatawidth::integer%maxalign = 0 THEN maxalign
                  ELSE nulldatawidth::integer%maxalign
                END
            )::numeric AS nulldatahdrwidth, pagehdr, pageopqdata, is_na
            -- , index_tuple_hdr_bm, nulldatawidth -- (DEBUG INFO)
      FROM (
          SELECT n.nspname, ct.relname AS tblname, i.idxname, i.reltuples, i.relpages,
              i.idxoid, i.fillfactor, current_setting('block_size')::numeric AS bs,
              CASE -- MAXALIGN: 4 on 32bits, 8 on 64bits (and mingw32 ?)
                WHEN version() ~ 'mingw32' OR version() ~ '64-bit|x86_64|ppc64|ia64|amd64' THEN 8
                ELSE 4
              END AS maxalign,
              /* per page header, fixed size: 20 for 7.X, 24 for others */
              24 AS pagehdr,
              /* per page btree opaque data */
              16 AS pageopqdata,
              /* per tuple header: add IndexAttributeBitMapData if some cols are null-able */
              CASE WHEN max(coalesce(s.stanullfrac,0)) = 0
                  THEN 2 -- IndexTupleData size
                  ELSE 2 + (( 32 + 8 - 1 ) / 8) -- IndexTupleData size + IndexAttributeBitMapData size ( max num filed per index + 8 - 1 /8)
              END AS index_tuple_hdr_bm,
              /* data len: we remove null values save space using it fractionnal part from stats */
              sum( (1-coalesce(s.stanullfrac, 0)) * coalesce(s.stawidth, 1024)) AS nulldatawidth,
              max( CASE WHEN a.atttypid = 'pg_catalog.name'::regtype THEN 1 ELSE 0 END ) > 0 AS is_na
          FROM (
              SELECT idxname, reltuples, relpages, tbloid, idxoid, fillfactor,
                  CASE WHEN indkey[i]=0 THEN idxoid ELSE tbloid END AS att_rel,
                  CASE WHEN indkey[i]=0 THEN i ELSE indkey[i] END AS att_pos
              FROM (
                  SELECT idxname, reltuples, relpages, tbloid, idxoid, fillfactor, indkey, generate_series(1,indnatts) AS i
                  FROM (
                      SELECT ci.relname AS idxname, ci.reltuples, ci.relpages, i.indrelid AS tbloid,
                          i.indexrelid AS idxoid,
                          coalesce(substring(
                              array_to_string(ci.reloptions, ' ')
                              from 'fillfactor=([0-9]+)')::smallint, 90) AS fillfactor,
                          i.indnatts,
                          string_to_array(textin(int2vectorout(i.indkey)),' ')::int[] AS indkey
                      FROM pg_index i
                      JOIN pg_class ci ON ci.oid=i.indexrelid
                      WHERE ci.relam=(SELECT oid FROM pg_am WHERE amname = 'btree')
                        AND ci.relpages > 0
                  ) AS idx_data
              ) AS idx_data_cross
          ) i
          JOIN pg_attribute a ON a.attrelid = i.att_rel
                             AND a.attnum = i.att_pos
          JOIN pg_statistic s ON s.starelid = i.att_rel
                             AND s.staattnum = i.att_pos
          JOIN pg_class ct ON ct.oid = i.tbloid
          JOIN pg_namespace n ON ct.relnamespace = n.oid
          GROUP BY 1,2,3,4,5,6,7,8,9,10
      ) AS rows_data_stats
  ) AS rows_hdr_pdg_stats
) AS relation_stats;
$$;


ALTER FUNCTION metric_helpers.get_btree_bloat_approx(OUT i_database name, OUT i_schema_name name, OUT i_table_name name, OUT i_index_name name, OUT i_real_size numeric, OUT i_extra_size numeric, OUT i_extra_ratio double precision, OUT i_fill_factor integer, OUT i_bloat_size double precision, OUT i_bloat_ratio double precision, OUT i_is_na boolean) OWNER TO carbide_development;

--
-- Name: get_table_bloat_approx(); Type: FUNCTION; Schema: metric_helpers; Owner: carbide_development
--

CREATE FUNCTION metric_helpers.get_table_bloat_approx(OUT t_database name, OUT t_schema_name name, OUT t_table_name name, OUT t_real_size numeric, OUT t_extra_size double precision, OUT t_extra_ratio double precision, OUT t_fill_factor integer, OUT t_bloat_size double precision, OUT t_bloat_ratio double precision, OUT t_is_na boolean) RETURNS SETOF record
    LANGUAGE sql IMMUTABLE STRICT SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $$
SELECT
  current_database(),
  schemaname,
  tblname,
  (bs*tblpages) AS real_size,
  ((tblpages-est_tblpages)*bs) AS extra_size,
  CASE WHEN tblpages - est_tblpages > 0
    THEN 100 * (tblpages - est_tblpages)/tblpages::float
    ELSE 0
  END AS extra_ratio,
  fillfactor,
  CASE WHEN tblpages - est_tblpages_ff > 0
    THEN (tblpages-est_tblpages_ff)*bs
    ELSE 0
  END AS bloat_size,
  CASE WHEN tblpages - est_tblpages_ff > 0
    THEN 100 * (tblpages - est_tblpages_ff)/tblpages::float
    ELSE 0
  END AS bloat_ratio,
  is_na
FROM (
  SELECT ceil( reltuples / ( (bs-page_hdr)/tpl_size ) ) + ceil( toasttuples / 4 ) AS est_tblpages,
    ceil( reltuples / ( (bs-page_hdr)*fillfactor/(tpl_size*100) ) ) + ceil( toasttuples / 4 ) AS est_tblpages_ff,
    tblpages, fillfactor, bs, tblid, schemaname, tblname, heappages, toastpages, is_na
    -- , tpl_hdr_size, tpl_data_size, pgstattuple(tblid) AS pst -- (DEBUG INFO)
  FROM (
    SELECT
      ( 4 + tpl_hdr_size + tpl_data_size + (2*ma)
        - CASE WHEN tpl_hdr_size%ma = 0 THEN ma ELSE tpl_hdr_size%ma END
        - CASE WHEN ceil(tpl_data_size)::int%ma = 0 THEN ma ELSE ceil(tpl_data_size)::int%ma END
      ) AS tpl_size, bs - page_hdr AS size_per_block, (heappages + toastpages) AS tblpages, heappages,
      toastpages, reltuples, toasttuples, bs, page_hdr, tblid, schemaname, tblname, fillfactor, is_na
      -- , tpl_hdr_size, tpl_data_size
    FROM (
      SELECT
        tbl.oid AS tblid, ns.nspname AS schemaname, tbl.relname AS tblname, tbl.reltuples,
        tbl.relpages AS heappages, coalesce(toast.relpages, 0) AS toastpages,
        coalesce(toast.reltuples, 0) AS toasttuples,
        coalesce(substring(
          array_to_string(tbl.reloptions, ' ')
          FROM 'fillfactor=([0-9]+)')::smallint, 100) AS fillfactor,
        current_setting('block_size')::numeric AS bs,
        CASE WHEN version()~'mingw32' OR version()~'64-bit|x86_64|ppc64|ia64|amd64' THEN 8 ELSE 4 END AS ma,
        24 AS page_hdr,
        23 + CASE WHEN MAX(coalesce(s.null_frac,0)) > 0 THEN ( 7 + count(s.attname) ) / 8 ELSE 0::int END
           + CASE WHEN bool_or(att.attname = 'oid' and att.attnum < 0) THEN 4 ELSE 0 END AS tpl_hdr_size,
        sum( (1-coalesce(s.null_frac, 0)) * coalesce(s.avg_width, 0) ) AS tpl_data_size,
        bool_or(att.atttypid = 'pg_catalog.name'::regtype)
          OR sum(CASE WHEN att.attnum > 0 THEN 1 ELSE 0 END) <> count(s.attname) AS is_na
      FROM pg_attribute AS att
        JOIN pg_class AS tbl ON att.attrelid = tbl.oid
        JOIN pg_namespace AS ns ON ns.oid = tbl.relnamespace
        LEFT JOIN pg_stats AS s ON s.schemaname=ns.nspname
          AND s.tablename = tbl.relname AND s.inherited=false AND s.attname=att.attname
        LEFT JOIN pg_class AS toast ON tbl.reltoastrelid = toast.oid
      WHERE NOT att.attisdropped
        AND tbl.relkind = 'r'
      GROUP BY 1,2,3,4,5,6,7,8,9,10
      ORDER BY 2,3
    ) AS s
  ) AS s2
) AS s3 WHERE schemaname NOT LIKE 'information_schema';
$$;


ALTER FUNCTION metric_helpers.get_table_bloat_approx(OUT t_database name, OUT t_schema_name name, OUT t_table_name name, OUT t_real_size numeric, OUT t_extra_size double precision, OUT t_extra_ratio double precision, OUT t_fill_factor integer, OUT t_bloat_size double precision, OUT t_bloat_ratio double precision, OUT t_is_na boolean) OWNER TO carbide_development;

--
-- Name: pg_stat_statements(boolean); Type: FUNCTION; Schema: metric_helpers; Owner: carbide_development
--

CREATE FUNCTION metric_helpers.pg_stat_statements(showtext boolean) RETURNS SETOF public.pg_stat_statements
    LANGUAGE sql IMMUTABLE STRICT SECURITY DEFINER
    AS $$
  SELECT * FROM public.pg_stat_statements(showtext);
$$;


ALTER FUNCTION metric_helpers.pg_stat_statements(showtext boolean) OWNER TO carbide_development;

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
  delete from measurement_journal where report_id in (select report_id from measurement_reports where machine_id = deletion_machine_id);
  delete from measurement_reports_values where report_id in (select report_id from measurement_reports where machine_id = deletion_machine_id);
  delete from measurement_reports where machine_id = deletion_machine_id;
  delete from measurement_approved_machines where machine_id = deletion_machine_id;
  delete from machine_topologies where machine_id = deletion_machine_id;
  delete from machines where id = deletion_machine_id;
  delete from machine_validation where machine_id = deletion_machine_id;
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
-- Name: delete_old_secret_ak_pub(); Type: FUNCTION; Schema: public; Owner: carbide_development
--

CREATE FUNCTION public.delete_old_secret_ak_pub() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  DELETE FROM attestation_secret_ak_pub WHERE created_at < CURRENT_TIMESTAMP - INTERVAL '1 hour';
  RETURN NULL;
END;
$$;


ALTER FUNCTION public.delete_old_secret_ak_pub() OWNER TO carbide_development;

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

--
-- Name: create_application_user(text); Type: FUNCTION; Schema: user_management; Owner: carbide_development
--

CREATE FUNCTION user_management.create_application_user(username text) RETURNS text
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $_$
DECLARE
    pw text;
BEGIN
    SELECT user_management.random_password(20) INTO pw;
    EXECUTE format($$ CREATE USER %I WITH PASSWORD %L $$, username, pw);
    RETURN pw;
END
$_$;


ALTER FUNCTION user_management.create_application_user(username text) OWNER TO carbide_development;

--
-- Name: FUNCTION create_application_user(username text); Type: COMMENT; Schema: user_management; Owner: carbide_development
--

COMMENT ON FUNCTION user_management.create_application_user(username text) IS 'Creates a user that can login, sets the password to a strong random one,
which is then returned';


--
-- Name: create_application_user_or_change_password(text, text); Type: FUNCTION; Schema: user_management; Owner: carbide_development
--

CREATE FUNCTION user_management.create_application_user_or_change_password(username text, password text) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $_$
BEGIN
    PERFORM 1 FROM pg_roles WHERE rolname = username;

    IF FOUND
    THEN
        EXECUTE format($$ ALTER ROLE %I WITH PASSWORD %L $$, username, password);
    ELSE
        EXECUTE format($$ CREATE USER %I WITH PASSWORD %L $$, username, password);
    END IF;
END
$_$;


ALTER FUNCTION user_management.create_application_user_or_change_password(username text, password text) OWNER TO carbide_development;

--
-- Name: FUNCTION create_application_user_or_change_password(username text, password text); Type: COMMENT; Schema: user_management; Owner: carbide_development
--

COMMENT ON FUNCTION user_management.create_application_user_or_change_password(username text, password text) IS 'USE THIS ONLY IN EMERGENCY!  The password will appear in the DB logs.
Creates a user that can login, sets the password to the one provided.
If the user already exists, sets its password.';


--
-- Name: create_role(text); Type: FUNCTION; Schema: user_management; Owner: carbide_development
--

CREATE FUNCTION user_management.create_role(rolename text) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $_$
BEGIN
    -- set ADMIN to the admin user, so every member of admin can GRANT these roles to each other
    EXECUTE format($$ CREATE ROLE %I WITH ADMIN admin $$, rolename);
END;
$_$;


ALTER FUNCTION user_management.create_role(rolename text) OWNER TO carbide_development;

--
-- Name: FUNCTION create_role(rolename text); Type: COMMENT; Schema: user_management; Owner: carbide_development
--

COMMENT ON FUNCTION user_management.create_role(rolename text) IS 'Creates a role that cannot log in, but can be used to set up fine-grained privileges';


--
-- Name: create_user(text); Type: FUNCTION; Schema: user_management; Owner: carbide_development
--

CREATE FUNCTION user_management.create_user(username text) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $_$
BEGIN
    EXECUTE format($$ CREATE USER %I IN ROLE zalandos, admin $$, username);
    EXECUTE format($$ ALTER ROLE %I SET log_statement TO 'all' $$, username);
END;
$_$;


ALTER FUNCTION user_management.create_user(username text) OWNER TO carbide_development;

--
-- Name: FUNCTION create_user(username text); Type: COMMENT; Schema: user_management; Owner: carbide_development
--

COMMENT ON FUNCTION user_management.create_user(username text) IS 'Creates a user that is supposed to be a human, to be authenticated without a password';


--
-- Name: drop_role(text); Type: FUNCTION; Schema: user_management; Owner: carbide_development
--

CREATE FUNCTION user_management.drop_role(username text) RETURNS void
    LANGUAGE sql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $$
SELECT user_management.drop_user(username);
$$;


ALTER FUNCTION user_management.drop_role(username text) OWNER TO carbide_development;

--
-- Name: FUNCTION drop_role(username text); Type: COMMENT; Schema: user_management; Owner: carbide_development
--

COMMENT ON FUNCTION user_management.drop_role(username text) IS 'Drop a human or application user.  Intended for cleanup (either after team changes or mistakes in role setup).
Roles (= users) that own database objects cannot be dropped.';


--
-- Name: drop_user(text); Type: FUNCTION; Schema: user_management; Owner: carbide_development
--

CREATE FUNCTION user_management.drop_user(username text) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $_$
BEGIN
    EXECUTE format($$ DROP ROLE %I $$, username);
END
$_$;


ALTER FUNCTION user_management.drop_user(username text) OWNER TO carbide_development;

--
-- Name: FUNCTION drop_user(username text); Type: COMMENT; Schema: user_management; Owner: carbide_development
--

COMMENT ON FUNCTION user_management.drop_user(username text) IS 'Drop a human or application user.  Intended for cleanup (either after team changes or mistakes in role setup).
Roles (= users) that own database objects cannot be dropped.';


--
-- Name: random_password(integer); Type: FUNCTION; Schema: user_management; Owner: carbide_development
--

CREATE FUNCTION user_management.random_password(length integer) RETURNS text
    LANGUAGE sql
    SET search_path TO 'pg_catalog'
    AS $$
WITH chars (c) AS (
    SELECT chr(33)
    UNION ALL
    SELECT chr(i) FROM generate_series (35, 38) AS t (i)
    UNION ALL
    SELECT chr(i) FROM generate_series (42, 90) AS t (i)
    UNION ALL
    SELECT chr(i) FROM generate_series (97, 122) AS t (i)
),
bricks (b) AS (
    -- build a pool of chars (the size will be the number of chars above times length)
    -- and shuffle it
    SELECT c FROM chars, generate_series(1, length) ORDER BY random()
)
SELECT substr(string_agg(b, ''), 1, length) FROM bricks;
$$;


ALTER FUNCTION user_management.random_password(length integer) OWNER TO carbide_development;

--
-- Name: revoke_admin(text); Type: FUNCTION; Schema: user_management; Owner: carbide_development
--

CREATE FUNCTION user_management.revoke_admin(username text) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $_$
BEGIN
    EXECUTE format($$ REVOKE admin FROM %I $$, username);
END
$_$;


ALTER FUNCTION user_management.revoke_admin(username text) OWNER TO carbide_development;

--
-- Name: FUNCTION revoke_admin(username text); Type: COMMENT; Schema: user_management; Owner: carbide_development
--

COMMENT ON FUNCTION user_management.revoke_admin(username text) IS 'Use this function to make a human user less privileged,
ie. when you want to grant someone read privileges only';


--
-- Name: terminate_backend(integer); Type: FUNCTION; Schema: user_management; Owner: carbide_development
--

CREATE FUNCTION user_management.terminate_backend(pid integer) RETURNS boolean
    LANGUAGE sql SECURITY DEFINER
    SET search_path TO 'pg_catalog'
    AS $$
SELECT pg_terminate_backend(pid);
$$;


ALTER FUNCTION user_management.terminate_backend(pid integer) OWNER TO carbide_development;

--
-- Name: FUNCTION terminate_backend(pid integer); Type: COMMENT; Schema: user_management; Owner: carbide_development
--

COMMENT ON FUNCTION user_management.terminate_backend(pid integer) IS 'When there is a process causing harm, you can kill it using this function.  Get the pid from pg_stat_activity
(be careful to match the user name (usename) and the query, in order not to kill innocent kittens) and pass it to terminate_backend()';


--
-- Name: index_bloat; Type: VIEW; Schema: metric_helpers; Owner: carbide_development
--

CREATE VIEW metric_helpers.index_bloat AS
 SELECT get_btree_bloat_approx.i_database,
    get_btree_bloat_approx.i_schema_name,
    get_btree_bloat_approx.i_table_name,
    get_btree_bloat_approx.i_index_name,
    get_btree_bloat_approx.i_real_size,
    get_btree_bloat_approx.i_extra_size,
    get_btree_bloat_approx.i_extra_ratio,
    get_btree_bloat_approx.i_fill_factor,
    get_btree_bloat_approx.i_bloat_size,
    get_btree_bloat_approx.i_bloat_ratio,
    get_btree_bloat_approx.i_is_na
   FROM metric_helpers.get_btree_bloat_approx() get_btree_bloat_approx(i_database, i_schema_name, i_table_name, i_index_name, i_real_size, i_extra_size, i_extra_ratio, i_fill_factor, i_bloat_size, i_bloat_ratio, i_is_na);


ALTER VIEW metric_helpers.index_bloat OWNER TO carbide_development;

--
-- Name: table_bloat; Type: VIEW; Schema: metric_helpers; Owner: carbide_development
--

CREATE VIEW metric_helpers.table_bloat AS
 SELECT get_table_bloat_approx.t_database,
    get_table_bloat_approx.t_schema_name,
    get_table_bloat_approx.t_table_name,
    get_table_bloat_approx.t_real_size,
    get_table_bloat_approx.t_extra_size,
    get_table_bloat_approx.t_extra_ratio,
    get_table_bloat_approx.t_fill_factor,
    get_table_bloat_approx.t_bloat_size,
    get_table_bloat_approx.t_bloat_ratio,
    get_table_bloat_approx.t_is_na
   FROM metric_helpers.get_table_bloat_approx() get_table_bloat_approx(t_database, t_schema_name, t_table_name, t_real_size, t_extra_size, t_extra_ratio, t_fill_factor, t_bloat_size, t_bloat_ratio, t_is_na);


ALTER VIEW metric_helpers.table_bloat OWNER TO carbide_development;

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
-- Name: attestation_secret_ak_pub; Type: TABLE; Schema: public; Owner: carbide_development
--

CREATE TABLE public.attestation_secret_ak_pub (
    secret bytea NOT NULL,
    ak_pub bytea NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.attestation_secret_ak_pub OWNER TO carbide_development;

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
    hostname character varying(63) NOT NULL,
    created timestamp with time zone DEFAULT now() NOT NULL,
    last_dhcp timestamp with time zone
);


ALTER TABLE public.machine_interfaces OWNER TO carbide_development;

--
-- Name: dns_records_adm_combined; Type: VIEW; Schema: public; Owner: carbide_development
--

CREATE VIEW public.dns_records_adm_combined AS
 SELECT concat(machine_interfaces.machine_id, '.adm.', domains.name, '.') AS q_name,
    machine_interface_addresses.address AS resource_record
   FROM ((public.machine_interfaces
     JOIN public.machine_interface_addresses ON ((machine_interface_addresses.interface_id = machine_interfaces.id)))
     JOIN public.domains ON (((domains.id = machine_interfaces.domain_id) AND (machine_interfaces.primary_interface = true))))
  WHERE (machine_interfaces.machine_id IS NOT NULL);


ALTER VIEW public.dns_records_adm_combined OWNER TO carbide_development;

--
-- Name: machine_topologies; Type: TABLE; Schema: public; Owner: carbide_development
--

CREATE TABLE public.machine_topologies (
    machine_id character varying(64) NOT NULL,
    topology jsonb NOT NULL,
    created timestamp with time zone DEFAULT now() NOT NULL,
    updated timestamp with time zone DEFAULT now() NOT NULL,
    topology_update_needed boolean DEFAULT false
);


ALTER TABLE public.machine_topologies OWNER TO carbide_development;

--
-- Name: dns_records_bmc_dpu_id; Type: VIEW; Schema: public; Owner: carbide_development
--

CREATE VIEW public.dns_records_bmc_dpu_id AS
 SELECT concat(machine_interfaces.machine_id, '.bmc.', domains.name, '.') AS q_name,
    (((machine_topologies.topology -> 'bmc_info'::text) ->> 'ip'::text))::inet AS resource_record
   FROM ((public.machine_interfaces
     JOIN public.machine_topologies ON ((((machine_interfaces.machine_id)::text = (machine_topologies.machine_id)::text) AND ((machine_interfaces.machine_id)::text = (machine_interfaces.attached_dpu_machine_id)::text))))
     JOIN public.domains ON ((domains.id = machine_interfaces.domain_id)))
  WHERE (machine_interfaces.machine_id IS NOT NULL);


ALTER VIEW public.dns_records_bmc_dpu_id OWNER TO carbide_development;

--
-- Name: dns_records_bmc_host_id; Type: VIEW; Schema: public; Owner: carbide_development
--

CREATE VIEW public.dns_records_bmc_host_id AS
 SELECT concat(machine_interfaces.machine_id, '.bmc.', domains.name, '.') AS q_name,
    (((machine_topologies.topology -> 'bmc_info'::text) ->> 'ip'::text))::inet AS resource_record
   FROM ((public.machine_interfaces
     JOIN public.machine_topologies ON ((((machine_interfaces.machine_id)::text = (machine_topologies.machine_id)::text) AND ((machine_interfaces.machine_id)::text <> (machine_interfaces.attached_dpu_machine_id)::text))))
     JOIN public.domains ON ((domains.id = machine_interfaces.domain_id)))
  WHERE (machine_interfaces.machine_id IS NOT NULL);


ALTER VIEW public.dns_records_bmc_host_id OWNER TO carbide_development;

--
-- Name: instances; Type: TABLE; Schema: public; Owner: carbide_development
--

CREATE TABLE public.instances (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    machine_id character varying(64) NOT NULL,
    requested timestamp with time zone DEFAULT now() NOT NULL,
    started timestamp with time zone DEFAULT now() NOT NULL,
    finished timestamp with time zone,
    os_user_data text,
    os_ipxe_script text DEFAULT 'need a proper string'::text NOT NULL,
    use_custom_pxe_on_boot boolean DEFAULT false NOT NULL,
    network_config_version character varying(64) DEFAULT 'V1-T1666644937952267'::character varying NOT NULL,
    network_config jsonb DEFAULT '{}'::jsonb NOT NULL,
    network_status_observation jsonb DEFAULT 'null'::jsonb NOT NULL,
    tenant_org text DEFAULT 'UNKNOWN'::text,
    deleted timestamp with time zone,
    ib_config_version character varying(64) DEFAULT 'V1-T1666644937952267'::character varying NOT NULL,
    ib_config jsonb DEFAULT '{"ib_interfaces": []}'::jsonb NOT NULL,
    keyset_ids text[] DEFAULT '{}'::text[] NOT NULL,
    os_always_boot_with_ipxe boolean DEFAULT false,
    os_phone_home_enabled boolean DEFAULT false NOT NULL,
    phone_home_last_contact timestamp with time zone,
    labels jsonb DEFAULT '{}'::jsonb NOT NULL,
    name character varying(256) DEFAULT ''::character varying NOT NULL,
    description character varying(1024) DEFAULT ''::character varying NOT NULL,
    config_version character varying(64) DEFAULT 'V1-T1666644937952268'::character varying NOT NULL,
    hostname character varying(64)
);


ALTER TABLE public.instances OWNER TO carbide_development;

--
-- Name: dns_records_instance; Type: VIEW; Schema: public; Owner: carbide_development
--

CREATE VIEW public.dns_records_instance AS
 SELECT concat(regexp_replace(ip_addrs.value, '\.'::text, '-'::text, 'g'::text), '.', d.name, '.') AS q_name,
    (ip_addrs.value)::inet AS resource_record
   FROM ((((public.instances i
     JOIN public.machine_interfaces mi ON (((i.machine_id)::text = (mi.machine_id)::text)))
     JOIN public.domains d ON ((mi.domain_id = d.id)))
     CROSS JOIN LATERAL jsonb_array_elements((i.network_config -> 'interfaces'::text)) iface(value))
     CROSS JOIN LATERAL jsonb_each_text((iface.value -> 'ip_addrs'::text)) ip_addrs(key, value))
  WHERE (((iface.value -> 'function_id'::text) ->> 'type'::text) = 'physical'::text);


ALTER VIEW public.dns_records_instance OWNER TO carbide_development;

--
-- Name: dns_records_shortname_combined; Type: VIEW; Schema: public; Owner: carbide_development
--

CREATE VIEW public.dns_records_shortname_combined AS
 SELECT concat(concat(machine_interfaces.hostname, '.', domains.name), '.') AS q_name,
    machine_interface_addresses.address AS resource_record
   FROM ((public.machine_interfaces
     JOIN public.machine_interface_addresses ON ((machine_interface_addresses.interface_id = machine_interfaces.id)))
     JOIN public.domains ON (((domains.id = machine_interfaces.domain_id) AND (machine_interfaces.primary_interface = true))));


ALTER VIEW public.dns_records_shortname_combined OWNER TO carbide_development;

--
-- Name: dns_records_machines; Type: VIEW; Schema: public; Owner: carbide_development
--

CREATE VIEW public.dns_records_machines AS
 SELECT q_name,
    resource_record
   FROM (((public.dns_records_shortname_combined
     FULL JOIN public.dns_records_adm_combined USING (q_name, resource_record))
     FULL JOIN public.dns_records_bmc_host_id USING (q_name, resource_record))
     FULL JOIN public.dns_records_bmc_dpu_id USING (q_name, resource_record));


ALTER VIEW public.dns_records_machines OWNER TO carbide_development;

--
-- Name: dns_records; Type: VIEW; Schema: public; Owner: carbide_development
--

CREATE VIEW public.dns_records AS
 SELECT q_name,
    resource_record
   FROM (public.dns_records_machines
     FULL JOIN public.dns_records_instance USING (q_name, resource_record));


ALTER VIEW public.dns_records OWNER TO carbide_development;

--
-- Name: dpu_agent_upgrade_policy; Type: TABLE; Schema: public; Owner: carbide_development
--

CREATE TABLE public.dpu_agent_upgrade_policy (
    policy character varying(32) DEFAULT 'Off'::character varying NOT NULL,
    created timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE public.dpu_agent_upgrade_policy OWNER TO carbide_development;

--
-- Name: expected_machines; Type: TABLE; Schema: public; Owner: carbide_development
--

CREATE TABLE public.expected_machines (
    serial_number character varying(32) NOT NULL,
    bmc_mac_address macaddr NOT NULL,
    bmc_username character varying(16) NOT NULL,
    bmc_password character varying(20) NOT NULL
);


ALTER TABLE public.expected_machines OWNER TO carbide_development;

--
-- Name: explored_endpoints; Type: TABLE; Schema: public; Owner: carbide_development
--

CREATE TABLE public.explored_endpoints (
    address inet NOT NULL,
    exploration_report jsonb NOT NULL,
    version character varying(64) NOT NULL,
    preingestion_state jsonb DEFAULT '{"state": "initial"}'::jsonb NOT NULL,
    waiting_for_explorer_refresh boolean DEFAULT false NOT NULL,
    exploration_requested boolean DEFAULT false NOT NULL
);


ALTER TABLE public.explored_endpoints OWNER TO carbide_development;

--
-- Name: explored_managed_hosts; Type: TABLE; Schema: public; Owner: carbide_development
--

CREATE TABLE public.explored_managed_hosts (
    host_bmc_ip inet NOT NULL,
    explored_dpus jsonb
);


ALTER TABLE public.explored_managed_hosts OWNER TO carbide_development;

--
-- Name: ib_partition_controller_lock; Type: TABLE; Schema: public; Owner: carbide_development
--

CREATE TABLE public.ib_partition_controller_lock (
    id uuid DEFAULT gen_random_uuid() NOT NULL
);


ALTER TABLE public.ib_partition_controller_lock OWNER TO carbide_development;

--
-- Name: ib_partitions; Type: TABLE; Schema: public; Owner: carbide_development
--

CREATE TABLE public.ib_partitions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name character varying NOT NULL,
    config_version character varying(64) NOT NULL,
    status jsonb,
    created timestamp with time zone DEFAULT now() NOT NULL,
    updated timestamp with time zone DEFAULT now() NOT NULL,
    deleted timestamp with time zone,
    controller_state_version character varying(64) DEFAULT 'V1-T1666644937952268'::character varying NOT NULL,
    controller_state jsonb DEFAULT '{"state": "provisioning"}'::jsonb NOT NULL,
    pkey integer NOT NULL,
    mtu integer NOT NULL,
    rate_limit integer NOT NULL,
    service_level integer NOT NULL,
    organization_id text DEFAULT ''::text NOT NULL,
    controller_state_outcome jsonb
);


ALTER TABLE public.ib_partitions OWNER TO carbide_development;

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
-- Name: machines; Type: TABLE; Schema: public; Owner: carbide_development
--

CREATE TABLE public.machines (
    id character varying(64) DEFAULT 'INVALID_MACHINE'::character varying NOT NULL,
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
    maintenance_start_time timestamp with time zone,
    reprovisioning_requested jsonb,
    dpu_agent_upgrade_requested jsonb,
    last_reboot_requested jsonb,
    agent_reported_inventory jsonb,
    controller_state_outcome jsonb,
    bios_password_set_time timestamp with time zone,
    last_machine_validation_time timestamp with time zone,
    current_machine_validation_id uuid,
    dpu_agent_health_report jsonb,
    discovery_machine_validation_id uuid,
    cleanup_machine_validation_id uuid
    on_demand_machine_validation_id uuid
    on_demand_machine_validation_request: BOOLEAN,
    infiniband_status_observation jsonb,
);


ALTER TABLE public.machines OWNER TO carbide_development;

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
    controller_state_outcome jsonb,
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


ALTER VIEW public.instance_dhcp_records OWNER TO carbide_development;

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


ALTER VIEW public.machine_dhcp_records OWNER TO carbide_development;

--
-- Name: machine_interfaces_lock; Type: TABLE; Schema: public; Owner: carbide_development
--

CREATE TABLE public.machine_interfaces_lock (
);


ALTER TABLE public.machine_interfaces_lock OWNER TO carbide_development;

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
-- Name: machine_update_lock; Type: TABLE; Schema: public; Owner: carbide_development
--

CREATE TABLE public.machine_update_lock (
    id uuid DEFAULT gen_random_uuid() NOT NULL
);


ALTER TABLE public.machine_update_lock OWNER TO carbide_development;

--
-- Name: machine_validation; Type: TABLE; Schema: public; Owner: carbide_development
--

CREATE TABLE public.machine_validation (
    id uuid NOT NULL,
    machine_id character varying(64) NOT NULL,
    start_time timestamp with time zone DEFAULT now() NOT NULL,
    name character varying(64),
    end_time timestamp with time zone,
    filter JSONB,
    context character varying(64)

);


ALTER TABLE public.machine_validation OWNER TO carbide_development;

--
-- Name: machine_validation_results; Type: TABLE; Schema: public; Owner: carbide_development
--

CREATE TABLE public.machine_validation_results (
    machine_validation_id uuid NOT NULL,
    name character varying(64) NOT NULL,
    description character varying(64),
    command text NOT NULL,
    args text,
    stdout text,
    stderr text,
    context character varying(64),
    exit_code integer DEFAULT 0,
    start_time timestamp with time zone NOT NULL,
    end_time timestamp with time zone NOT NULL
);


ALTER TABLE public.machine_validation_results OWNER TO carbide_development;

--
-- Name: measurement_approved_machines; Type: TABLE; Schema: public; Owner: carbide_development
--

CREATE TABLE public.measurement_approved_machines (
    approval_id uuid DEFAULT gen_random_uuid() NOT NULL,
    machine_id text NOT NULL,
    approval_type public.measurement_approved_type DEFAULT 'oneshot'::public.measurement_approved_type NOT NULL,
    ts timestamp with time zone DEFAULT clock_timestamp(),
    pcr_registers text,
    comments text
);


ALTER TABLE public.measurement_approved_machines OWNER TO carbide_development;

--
-- Name: measurement_approved_profiles; Type: TABLE; Schema: public; Owner: carbide_development
--

CREATE TABLE public.measurement_approved_profiles (
    approval_id uuid DEFAULT gen_random_uuid() NOT NULL,
    profile_id uuid NOT NULL,
    approval_type public.measurement_approved_type DEFAULT 'oneshot'::public.measurement_approved_type NOT NULL,
    ts timestamp with time zone DEFAULT clock_timestamp(),
    pcr_registers text,
    comments text
);


ALTER TABLE public.measurement_approved_profiles OWNER TO carbide_development;

--
-- Name: measurement_bundles; Type: TABLE; Schema: public; Owner: carbide_development
--

CREATE TABLE public.measurement_bundles (
    bundle_id uuid DEFAULT gen_random_uuid() NOT NULL,
    name text NOT NULL,
    profile_id uuid NOT NULL,
    ts timestamp with time zone DEFAULT clock_timestamp(),
    state public.measurement_bundle_state DEFAULT 'pending'::public.measurement_bundle_state NOT NULL
);


ALTER TABLE public.measurement_bundles OWNER TO carbide_development;

--
-- Name: measurement_bundles_values; Type: TABLE; Schema: public; Owner: carbide_development
--

CREATE TABLE public.measurement_bundles_values (
    value_id uuid DEFAULT gen_random_uuid() NOT NULL,
    bundle_id uuid,
    pcr_register smallint NOT NULL,
    sha256 character varying(64) NOT NULL,
    ts timestamp with time zone DEFAULT clock_timestamp()
);


ALTER TABLE public.measurement_bundles_values OWNER TO carbide_development;

--
-- Name: measurement_journal; Type: TABLE; Schema: public; Owner: carbide_development
--

CREATE TABLE public.measurement_journal (
    journal_id uuid DEFAULT gen_random_uuid() NOT NULL,
    machine_id text NOT NULL,
    report_id uuid,
    profile_id uuid,
    bundle_id uuid,
    state public.measurement_machine_state DEFAULT 'discovered'::public.measurement_machine_state NOT NULL,
    ts timestamp with time zone DEFAULT clock_timestamp()
);


ALTER TABLE public.measurement_journal OWNER TO carbide_development;

--
-- Name: measurement_reports; Type: TABLE; Schema: public; Owner: carbide_development
--

CREATE TABLE public.measurement_reports (
    report_id uuid DEFAULT gen_random_uuid() NOT NULL,
    machine_id text NOT NULL,
    ts timestamp with time zone DEFAULT clock_timestamp()
);


ALTER TABLE public.measurement_reports OWNER TO carbide_development;

--
-- Name: measurement_reports_values; Type: TABLE; Schema: public; Owner: carbide_development
--

CREATE TABLE public.measurement_reports_values (
    value_id uuid DEFAULT gen_random_uuid() NOT NULL,
    report_id uuid NOT NULL,
    pcr_register smallint NOT NULL,
    sha256 character varying(64) NOT NULL,
    ts timestamp with time zone DEFAULT clock_timestamp()
);


ALTER TABLE public.measurement_reports_values OWNER TO carbide_development;

--
-- Name: measurement_system_profiles; Type: TABLE; Schema: public; Owner: carbide_development
--

CREATE TABLE public.measurement_system_profiles (
    profile_id uuid DEFAULT gen_random_uuid() NOT NULL,
    name text NOT NULL,
    ts timestamp with time zone DEFAULT clock_timestamp()
);


ALTER TABLE public.measurement_system_profiles OWNER TO carbide_development;

--
-- Name: measurement_system_profiles_attrs; Type: TABLE; Schema: public; Owner: carbide_development
--

CREATE TABLE public.measurement_system_profiles_attrs (
    attribute_id uuid DEFAULT gen_random_uuid() NOT NULL,
    profile_id uuid NOT NULL,
    key text NOT NULL,
    value text NOT NULL,
    ts timestamp with time zone DEFAULT clock_timestamp()
);


ALTER TABLE public.measurement_system_profiles_attrs OWNER TO carbide_development;

--
-- Name: network_device_lock; Type: TABLE; Schema: public; Owner: carbide_development
--

CREATE TABLE public.network_device_lock (
    id uuid DEFAULT gen_random_uuid() NOT NULL
);


ALTER TABLE public.network_device_lock OWNER TO carbide_development;

--
-- Name: network_devices; Type: TABLE; Schema: public; Owner: carbide_development
--

CREATE TABLE public.network_devices (
    id character varying(30) NOT NULL,
    name text NOT NULL,
    description text,
    ip_addresses inet[],
    device_type public.network_device_type DEFAULT 'ethernet'::public.network_device_type NOT NULL,
    discovered_via public.network_device_discovered_via DEFAULT 'lldp'::public.network_device_discovered_via NOT NULL
);


ALTER TABLE public.network_devices OWNER TO carbide_development;

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
-- Name: port_to_network_device_map; Type: TABLE; Schema: public; Owner: carbide_development
--

CREATE TABLE public.port_to_network_device_map (
    dpu_id character varying(64) NOT NULL,
    local_port public.dpu_local_ports NOT NULL,
    network_device_id character varying(30),
    remote_port text DEFAULT ''::text NOT NULL
);


ALTER TABLE public.port_to_network_device_map OWNER TO carbide_development;

--
-- Name: preingestion_manager_lock; Type: TABLE; Schema: public; Owner: carbide_development
--

CREATE TABLE public.preingestion_manager_lock (
    id uuid DEFAULT gen_random_uuid() NOT NULL
);


ALTER TABLE public.preingestion_manager_lock OWNER TO carbide_development;

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
-- Name: route_servers; Type: TABLE; Schema: public; Owner: carbide_development
--

CREATE TABLE public.route_servers (
    address inet NOT NULL
);


ALTER TABLE public.route_servers OWNER TO carbide_development;

--
-- Name: site_explorer_lock; Type: TABLE; Schema: public; Owner: carbide_development
--

CREATE TABLE public.site_explorer_lock (
    id uuid DEFAULT gen_random_uuid() NOT NULL
);


ALTER TABLE public.site_explorer_lock OWNER TO carbide_development;

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
    version character varying(64) NOT NULL,
    organization_name text
);


ALTER TABLE public.tenants OWNER TO carbide_development;

--
-- Name: vpcs; Type: TABLE; Schema: public; Owner: carbide_development
--

CREATE TABLE public.vpcs (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name character varying(256) NOT NULL,
    organization_id character varying,
    version character varying(64) NOT NULL,
    created timestamp with time zone DEFAULT now() NOT NULL,
    updated timestamp with time zone DEFAULT now() NOT NULL,
    deleted timestamp with time zone,
    network_virtualization_type public.network_virtualization_type_t DEFAULT 'etv'::public.network_virtualization_type_t NOT NULL,
    vni integer,
    labels JSONB NOT NULL DEFAULT ('{}'),
    description VARCHAR(1024) NOT NULL DEFAULT (''),
);

ALTER TABLE public.vpcs OWNER TO carbide_development;

--
-- Name: _sqlx_migrations _sqlx_migrations_pkey; Type: CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public._sqlx_migrations
    ADD CONSTRAINT _sqlx_migrations_pkey PRIMARY KEY (version);


--
-- Name: attestation_secret_ak_pub attestation_secret_ak_pub_unique_secret; Type: CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.attestation_secret_ak_pub
    ADD CONSTRAINT attestation_secret_ak_pub_unique_secret PRIMARY KEY (secret);


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
-- Name: expected_machines expected_machines_bmc_mac_address_key; Type: CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.expected_machines
    ADD CONSTRAINT expected_machines_bmc_mac_address_key UNIQUE (bmc_mac_address);


--
-- Name: explored_endpoints explored_endpoints_pkey; Type: CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.explored_endpoints
    ADD CONSTRAINT explored_endpoints_pkey PRIMARY KEY (address);


--
-- Name: machine_interfaces fqdn_must_be_unique; Type: CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.machine_interfaces
    ADD CONSTRAINT fqdn_must_be_unique UNIQUE (domain_id, hostname);


--
-- Name: ib_partitions ib_subnets_pkey; Type: CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.ib_partitions
    ADD CONSTRAINT ib_subnets_pkey PRIMARY KEY (id);


--
-- Name: ib_partitions ib_subnets_pkey_key; Type: CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.ib_partitions
    ADD CONSTRAINT ib_subnets_pkey_key UNIQUE (pkey);


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
-- Name: machine_validation machine_validation_pkey; Type: CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.machine_validation
    ADD CONSTRAINT machine_validation_pkey PRIMARY KEY (id);


--
-- Name: machines machines_pkey; Type: CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.machines
    ADD CONSTRAINT machines_pkey PRIMARY KEY (id);


--
-- Name: measurement_approved_machines measurement_approved_machines_pkey; Type: CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.measurement_approved_machines
    ADD CONSTRAINT measurement_approved_machines_pkey PRIMARY KEY (approval_id);


--
-- Name: measurement_approved_profiles measurement_approved_profiles_pkey; Type: CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.measurement_approved_profiles
    ADD CONSTRAINT measurement_approved_profiles_pkey PRIMARY KEY (approval_id);


--
-- Name: measurement_bundles measurement_bundles_pkey; Type: CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.measurement_bundles
    ADD CONSTRAINT measurement_bundles_pkey PRIMARY KEY (bundle_id);


--
-- Name: measurement_bundles_values measurement_bundles_values_pkey; Type: CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.measurement_bundles_values
    ADD CONSTRAINT measurement_bundles_values_pkey PRIMARY KEY (value_id);


--
-- Name: measurement_journal measurement_journal_pkey; Type: CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.measurement_journal
    ADD CONSTRAINT measurement_journal_pkey PRIMARY KEY (journal_id);


--
-- Name: measurement_reports measurement_reports_pkey; Type: CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.measurement_reports
    ADD CONSTRAINT measurement_reports_pkey PRIMARY KEY (report_id);


--
-- Name: measurement_reports_values measurement_reports_values_pkey; Type: CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.measurement_reports_values
    ADD CONSTRAINT measurement_reports_values_pkey PRIMARY KEY (value_id);


--
-- Name: measurement_system_profiles_attrs measurement_system_profiles_attrs_pkey; Type: CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.measurement_system_profiles_attrs
    ADD CONSTRAINT measurement_system_profiles_attrs_pkey PRIMARY KEY (attribute_id);


--
-- Name: measurement_system_profiles measurement_system_profiles_pkey; Type: CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.measurement_system_profiles
    ADD CONSTRAINT measurement_system_profiles_pkey PRIMARY KEY (profile_id);


--
-- Name: port_to_network_device_map network_device_dpu_associations_primary; Type: CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.port_to_network_device_map
    ADD CONSTRAINT network_device_dpu_associations_primary PRIMARY KEY (dpu_id, local_port);


--
-- Name: network_devices network_devices_name_key; Type: CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.network_devices
    ADD CONSTRAINT network_devices_name_key UNIQUE (name);


--
-- Name: network_devices network_devices_pkey; Type: CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.network_devices
    ADD CONSTRAINT network_devices_pkey PRIMARY KEY (id);


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
-- Name: route_servers route_servers_address_key; Type: CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.route_servers
    ADD CONSTRAINT route_servers_address_key UNIQUE (address);


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
-- Name: measurement_bundles unique_bundle_name; Type: CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.measurement_bundles
    ADD CONSTRAINT unique_bundle_name UNIQUE (name);


--
-- Name: measurement_bundles_values unique_bundle_value; Type: CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.measurement_bundles_values
    ADD CONSTRAINT unique_bundle_value UNIQUE (bundle_id, pcr_register);


--
-- Name: measurement_approved_machines unique_machine_id; Type: CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.measurement_approved_machines
    ADD CONSTRAINT unique_machine_id UNIQUE (machine_id);


--
-- Name: measurement_system_profiles_attrs unique_profile_attr; Type: CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.measurement_system_profiles_attrs
    ADD CONSTRAINT unique_profile_attr UNIQUE (profile_id, key);


--
-- Name: measurement_approved_profiles unique_profile_id; Type: CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.measurement_approved_profiles
    ADD CONSTRAINT unique_profile_id UNIQUE (profile_id);


--
-- Name: measurement_system_profiles unique_profile_name; Type: CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.measurement_system_profiles
    ADD CONSTRAINT unique_profile_name UNIQUE (name);


--
-- Name: measurement_reports_values unique_report_value; Type: CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.measurement_reports_values
    ADD CONSTRAINT unique_report_value UNIQUE (report_id, pcr_register);


--
-- Name: vpcs vpcs_pkey; Type: CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.vpcs
    ADD CONSTRAINT vpcs_pkey PRIMARY KEY (id);


--
-- Name: ib_partitions_organization_id_idx; Type: INDEX; Schema: public; Owner: carbide_development
--

CREATE INDEX ib_partitions_organization_id_idx ON public.ib_partitions USING btree (organization_id);


--
-- Name: idx_resource_pools_name; Type: INDEX; Schema: public; Owner: carbide_development
--

CREATE INDEX idx_resource_pools_name ON public.resource_pool USING btree (name);


--
-- Name: instances_tenant_org_idx; Type: INDEX; Schema: public; Owner: carbide_development
--

CREATE INDEX instances_tenant_org_idx ON public.instances USING btree (tenant_org);


--
-- Name: machine_interfaces_attached_dpu_machine_id_idx; Type: INDEX; Schema: public; Owner: carbide_development
--

CREATE INDEX machine_interfaces_attached_dpu_machine_id_idx ON public.machine_interfaces USING btree (attached_dpu_machine_id);


--
-- Name: network_prefix_family; Type: INDEX; Schema: public; Owner: carbide_development
--

CREATE UNIQUE INDEX network_prefix_family ON public.network_prefixes USING btree (family((prefix)::inet), segment_id);


--
-- Name: network_prefixes_segment_id_idx; Type: INDEX; Schema: public; Owner: carbide_development
--

CREATE INDEX network_prefixes_segment_id_idx ON public.network_prefixes USING btree (segment_id);


--
-- Name: network_segments_subdomain_id_idx; Type: INDEX; Schema: public; Owner: carbide_development
--

CREATE INDEX network_segments_subdomain_id_idx ON public.network_segments USING btree (subdomain_id);


--
-- Name: network_segments_vpc_id_idx; Type: INDEX; Schema: public; Owner: carbide_development
--

CREATE INDEX network_segments_vpc_id_idx ON public.network_segments USING btree (vpc_id);


--
-- Name: one_address_for_a_family; Type: INDEX; Schema: public; Owner: carbide_development
--

CREATE UNIQUE INDEX one_address_for_a_family ON public.instance_addresses USING btree (instance_id, circuit_id, family(address));


--
-- Name: one_primary_interface_per_machine; Type: INDEX; Schema: public; Owner: carbide_development
--

CREATE UNIQUE INDEX one_primary_interface_per_machine ON public.machine_interfaces USING btree (machine_id) WHERE (primary_interface = true);


--
-- Name: only_one_admin_network_segment; Type: INDEX; Schema: public; Owner: carbide_development
--

CREATE UNIQUE INDEX only_one_admin_network_segment ON public.network_segments USING btree (network_segment_type) WHERE (network_segment_type = 'admin'::public.network_segment_type_t);


--
-- Name: port_to_network_device_map_network_device_id_idx; Type: INDEX; Schema: public; Owner: carbide_development
--

CREATE INDEX port_to_network_device_map_network_device_id_idx ON public.port_to_network_device_map USING btree (network_device_id);


--
-- Name: unique_address_family_on_interface; Type: INDEX; Schema: public; Owner: carbide_development
--

CREATE UNIQUE INDEX unique_address_family_on_interface ON public.machine_interface_addresses USING btree (family(address), interface_id);


--
-- Name: unique_org_hostname; Type: INDEX; Schema: public; Owner: carbide_development
--

CREATE UNIQUE INDEX unique_org_hostname ON public.instances USING btree (tenant_org, hostname) WHERE (hostname IS NOT NULL);


--
-- Name: vpcs_organization_id_idx; Type: INDEX; Schema: public; Owner: carbide_development
--

CREATE INDEX vpcs_organization_id_idx ON public.vpcs USING btree (organization_id);


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
-- Name: attestation_secret_ak_pub trigger_delete_old_secret_ak_pub; Type: TRIGGER; Schema: public; Owner: carbide_development
--

CREATE TRIGGER trigger_delete_old_secret_ak_pub AFTER INSERT ON public.attestation_secret_ak_pub FOR EACH STATEMENT EXECUTE FUNCTION public.delete_old_secret_ak_pub();


--
-- Name: dhcp_entries dhcp_entries_machine_interface_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.dhcp_entries
    ADD CONSTRAINT dhcp_entries_machine_interface_id_fkey FOREIGN KEY (machine_interface_id) REFERENCES public.machine_interfaces(id);


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
    ADD CONSTRAINT machine_topologies_machine_id_fkey FOREIGN KEY (machine_id) REFERENCES public.machines(id) ON UPDATE CASCADE;


--
-- Name: machine_validation_results machine_validation_id_fk; Type: FK CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.machine_validation_results
    ADD CONSTRAINT machine_validation_id_fk FOREIGN KEY (machine_validation_id) REFERENCES public.machine_validation(id) ON DELETE CASCADE;


--
-- Name: measurement_approved_profiles measurement_approved_profiles_profile_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.measurement_approved_profiles
    ADD CONSTRAINT measurement_approved_profiles_profile_id_fkey FOREIGN KEY (profile_id) REFERENCES public.measurement_system_profiles(profile_id);


--
-- Name: measurement_bundles measurement_bundles_profile_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.measurement_bundles
    ADD CONSTRAINT measurement_bundles_profile_id_fkey FOREIGN KEY (profile_id) REFERENCES public.measurement_system_profiles(profile_id);


--
-- Name: measurement_bundles_values measurement_bundles_values_bundle_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.measurement_bundles_values
    ADD CONSTRAINT measurement_bundles_values_bundle_id_fkey FOREIGN KEY (bundle_id) REFERENCES public.measurement_bundles(bundle_id);


--
-- Name: measurement_journal measurement_journal_bundle_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.measurement_journal
    ADD CONSTRAINT measurement_journal_bundle_id_fkey FOREIGN KEY (bundle_id) REFERENCES public.measurement_bundles(bundle_id);


--
-- Name: measurement_journal measurement_journal_profile_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.measurement_journal
    ADD CONSTRAINT measurement_journal_profile_id_fkey FOREIGN KEY (profile_id) REFERENCES public.measurement_system_profiles(profile_id);


--
-- Name: measurement_journal measurement_journal_report_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.measurement_journal
    ADD CONSTRAINT measurement_journal_report_id_fkey FOREIGN KEY (report_id) REFERENCES public.measurement_reports(report_id);


--
-- Name: measurement_reports measurement_reports_machine_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.measurement_reports
    ADD CONSTRAINT measurement_reports_machine_id_fkey FOREIGN KEY (machine_id) REFERENCES public.machines(id);


--
-- Name: measurement_reports_values measurement_reports_values_report_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.measurement_reports_values
    ADD CONSTRAINT measurement_reports_values_report_id_fkey FOREIGN KEY (report_id) REFERENCES public.measurement_reports(report_id);


--
-- Name: measurement_system_profiles_attrs measurement_system_profiles_attrs_profile_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.measurement_system_profiles_attrs
    ADD CONSTRAINT measurement_system_profiles_attrs_profile_id_fkey FOREIGN KEY (profile_id) REFERENCES public.measurement_system_profiles(profile_id);


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
-- Name: port_to_network_device_map port_to_network_device_map_dpu_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.port_to_network_device_map
    ADD CONSTRAINT port_to_network_device_map_dpu_id_fkey FOREIGN KEY (dpu_id) REFERENCES public.machines(id);


--
-- Name: port_to_network_device_map port_to_network_device_map_network_device_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: carbide_development
--

ALTER TABLE ONLY public.port_to_network_device_map
    ADD CONSTRAINT port_to_network_device_map_network_device_id_fkey FOREIGN KEY (network_device_id) REFERENCES public.network_devices(id);


--
-- Name: SCHEMA public; Type: ACL; Schema: -; Owner: carbide_development
--

REVOKE USAGE ON SCHEMA public FROM PUBLIC;
GRANT ALL ON SCHEMA public TO PUBLIC;


--
-- Name: FUNCTION get_btree_bloat_approx(OUT i_database name, OUT i_schema_name name, OUT i_table_name name, OUT i_index_name name, OUT i_real_size numeric, OUT i_extra_size numeric, OUT i_extra_ratio double precision, OUT i_fill_factor integer, OUT i_bloat_size double precision, OUT i_bloat_ratio double precision, OUT i_is_na boolean); Type: ACL; Schema: metric_helpers; Owner: carbide_development
--

REVOKE ALL ON FUNCTION metric_helpers.get_btree_bloat_approx(OUT i_database name, OUT i_schema_name name, OUT i_table_name name, OUT i_index_name name, OUT i_real_size numeric, OUT i_extra_size numeric, OUT i_extra_ratio double precision, OUT i_fill_factor integer, OUT i_bloat_size double precision, OUT i_bloat_ratio double precision, OUT i_is_na boolean) FROM PUBLIC;


--
-- Name: FUNCTION get_table_bloat_approx(OUT t_database name, OUT t_schema_name name, OUT t_table_name name, OUT t_real_size numeric, OUT t_extra_size double precision, OUT t_extra_ratio double precision, OUT t_fill_factor integer, OUT t_bloat_size double precision, OUT t_bloat_ratio double precision, OUT t_is_na boolean); Type: ACL; Schema: metric_helpers; Owner: carbide_development
--

REVOKE ALL ON FUNCTION metric_helpers.get_table_bloat_approx(OUT t_database name, OUT t_schema_name name, OUT t_table_name name, OUT t_real_size numeric, OUT t_extra_size double precision, OUT t_extra_ratio double precision, OUT t_fill_factor integer, OUT t_bloat_size double precision, OUT t_bloat_ratio double precision, OUT t_is_na boolean) FROM PUBLIC;


--
-- Name: FUNCTION pg_stat_statements(showtext boolean); Type: ACL; Schema: metric_helpers; Owner: carbide_development
--

REVOKE ALL ON FUNCTION metric_helpers.pg_stat_statements(showtext boolean) FROM PUBLIC;


--
-- Name: FUNCTION create_application_user(username text); Type: ACL; Schema: user_management; Owner: carbide_development
--

REVOKE ALL ON FUNCTION user_management.create_application_user(username text) FROM PUBLIC;


--
-- Name: FUNCTION create_application_user_or_change_password(username text, password text); Type: ACL; Schema: user_management; Owner: carbide_development
--

REVOKE ALL ON FUNCTION user_management.create_application_user_or_change_password(username text, password text) FROM PUBLIC;


--
-- Name: FUNCTION create_role(rolename text); Type: ACL; Schema: user_management; Owner: carbide_development
--

REVOKE ALL ON FUNCTION user_management.create_role(rolename text) FROM PUBLIC;


--
-- Name: FUNCTION create_user(username text); Type: ACL; Schema: user_management; Owner: carbide_development
--

REVOKE ALL ON FUNCTION user_management.create_user(username text) FROM PUBLIC;


--
-- Name: FUNCTION drop_role(username text); Type: ACL; Schema: user_management; Owner: carbide_development
--

REVOKE ALL ON FUNCTION user_management.drop_role(username text) FROM PUBLIC;


--
-- Name: FUNCTION drop_user(username text); Type: ACL; Schema: user_management; Owner: carbide_development
--

REVOKE ALL ON FUNCTION user_management.drop_user(username text) FROM PUBLIC;


--
-- Name: FUNCTION revoke_admin(username text); Type: ACL; Schema: user_management; Owner: carbide_development
--

REVOKE ALL ON FUNCTION user_management.revoke_admin(username text) FROM PUBLIC;


--
-- Name: FUNCTION terminate_backend(pid integer); Type: ACL; Schema: user_management; Owner: carbide_development
--

REVOKE ALL ON FUNCTION user_management.terminate_backend(pid integer) FROM PUBLIC;


--
-- PostgreSQL database dump complete
--

