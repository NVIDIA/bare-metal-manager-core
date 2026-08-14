-- Records who completed a pending action.
--
-- Carbide releases a DPF maintenance hold on its own for hosts it has confirmed
-- are up to date, but a site can turn that off and drive the rollout by hand
-- instead, and a host that never reaches an eligible state has to be released by
-- an operator either way. Both paths write the same completion, so without this
-- the retained history cannot answer whether a machine was synced automatically
-- or released deliberately -- which is the first question asked when working out
-- what happened to a host.
--
-- Mirrors the `UpdateInitiator` RPC enum, which already draws this distinction
-- for reprovisioning, so the two features describe the same thing the same way.
CREATE TYPE machine_pending_action_actor AS ENUM (
    'automatic',
    'admin_cli'
);

-- Null while the action is still outstanding: nobody has completed it yet. Set
-- together with `completed_at`, so the pair is either both present or both
-- absent.
ALTER TABLE machine_pending_actions
    ADD COLUMN completed_by machine_pending_action_actor;
