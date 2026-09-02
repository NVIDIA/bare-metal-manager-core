-- Persist the two leased VNI endpoints while an operator verifies or reverses
-- an in-place VPC routing-profile transition.
CREATE TABLE vpc_routing_profile_transitions (
    id uuid PRIMARY KEY,
    vpc_id uuid NOT NULL REFERENCES vpcs(id) ON DELETE CASCADE,
    version character varying(64) NOT NULL,
    state text NOT NULL,
    source_routing_profile_type character varying(64) NOT NULL,
    target_routing_profile_type character varying(64) NOT NULL,
    source_pool_name character varying(32) NOT NULL,
    target_pool_name character varying(32) NOT NULL,
    source_vni integer NOT NULL,
    target_vni integer NOT NULL,
    source_requested_vni integer,
    target_requested_vni integer,
    source_routing_profile_overrides jsonb,
    target_routing_profile_overrides jsonb,
    source_vpc_version character varying(64) NOT NULL,
    cutover_vpc_version character varying(64) NOT NULL,
    rollback_vpc_version character varying(64),
    reason text NOT NULL,
    created timestamp with time zone DEFAULT now() NOT NULL,
    updated timestamp with time zone DEFAULT now() NOT NULL,
    completed timestamp with time zone,
    CONSTRAINT vpc_routing_profile_transitions_state_check CHECK (
        state IN (
            'cutover_pending_finalize',
            'rollback_pending_finalize',
            'finalized',
            'rolled_back'
        )
    ),
    CONSTRAINT vpc_routing_profile_transitions_distinct_pools_check CHECK (
        source_pool_name <> target_pool_name
    ),
    CONSTRAINT vpc_routing_profile_transitions_distinct_vnis_check CHECK (
        source_vni <> target_vni
    ),
    CONSTRAINT vpc_routing_profile_transitions_source_requested_vni_check CHECK (
        source_requested_vni IS NULL OR source_requested_vni = source_vni
    ),
    CONSTRAINT vpc_routing_profile_transitions_target_requested_vni_check CHECK (
        target_requested_vni IS NULL OR target_requested_vni = target_vni
    ),
    CONSTRAINT vpc_routing_profile_transitions_reason_check CHECK (
        btrim(reason) <> ''
    ),
    CONSTRAINT vpc_routing_profile_transitions_completed_check CHECK (
        (state IN ('finalized', 'rolled_back')) = (completed IS NOT NULL)
    ),
    CONSTRAINT vpc_routing_profile_transitions_rollback_version_check CHECK (
        state NOT IN ('rollback_pending_finalize', 'rolled_back')
        OR rollback_vpc_version IS NOT NULL
    )
);

CREATE UNIQUE INDEX vpc_routing_profile_transitions_one_active_per_vpc
    ON vpc_routing_profile_transitions (vpc_id)
    WHERE state IN ('cutover_pending_finalize', 'rollback_pending_finalize');

CREATE INDEX vpc_routing_profile_transitions_vpc_history
    ON vpc_routing_profile_transitions (vpc_id, created, id);
