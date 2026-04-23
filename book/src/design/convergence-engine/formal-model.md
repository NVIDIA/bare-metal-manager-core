# Convergence Engine — Formal Model

This document contains the mathematical specification of the convergence engine.

---

## F.1 State Space

**Definition.** Let `K` be a finite set of *state keys* — strongly-typed identifiers such as `PowerState`, `FirmwareBmcVersion`, or `BiosBootOrder`. Let `V` be a set of *state values* — a typed union of booleans, integers, semantic versions, and text.

A **host state** is a partial function:

```
S : K ⇀ V
```

The notation `⇀` (as opposed to `→`) indicates that `S` need not be defined on all of `K`. The **domain** of `S` is:

```
dom(S) = { k ∈ K | S(k) is defined }
```

At any moment in time, the system maintains two states:

- `S_o` — the **observed state**, populated by reading hardware, databases, and agent reports.
- `S_d` — the **desired state**, assembled at runtime by the desired-state composition layer.

**Unified key space.** Both `S_o` and `S_d` draw from the same key space `K`. Any key can appear in either or both maps:

```
dom(S_d) ⊆ K,  dom(S_o) ⊆ K
```

`dom(S_d) \ dom(S_o)` may be non-empty when the observed state has not yet discovered a key that the desired state declares. Such keys are treated as mismatched (see F.2).

---

## F.2 Delta

**Definition.** The **delta** (or *drift*) between observed and desired state is the set of keys where the two states disagree:

```
Δ(S_o, S_d) = { k ∈ dom(S_d) | S_o(k) ≠ S_d(k) }
```

with the convention that if `k ∈ dom(S_d) \ dom(S_o)` — i.e., the desired state declares a key that the observed state has not yet discovered — then `S_o(k) ≠ S_d(k)` holds. Formally:

```
k ∈ Δ  ⟺  k ∈ dom(S_d) ∧ ( k ∉ dom(S_o) ∨ S_o(k) ≠ S_d(k) )
```

**Convergence criterion.** The system has **converged** when:

```
Δ(S_o, S_d) = ∅
```

**What the delta does NOT include.** Keys in `dom(S_o) \ dom(S_d)` — observed keys with no corresponding desired value — are not part of the delta. `S_d` is a *patch*, not a complete specification.

---

## F.3 Operations

**Definition.** An **operation** is a tuple:

```
ω = (id, P, G, L, E, π)
```

where:

| Component | Constraint       | Description |
| --------- | ---------------- | ----------- |
| `id`      | unique in `Ω`    | Unique identifier for this operation. |
| `P`       | `P ⊆ K`          | **Provides** — the set of state keys this operation can change. An operation is only considered for a delta key `k` if `k ∈ P`. |
| `G`       | `G : S → {0, 1}` | **Guard** — a boolean predicate over the observed state (see F.4). The operation may only fire when `G(S_o) = 1`. |
| `L`       | `L ⊆ R`          | **Locks** — a set of resource identifiers requiring mutual exclusion. `R` is the universe of lockable resources. Two operations with `L₁ ∩ L₂ ≠ ∅` cannot execute in the same tick. |
| `E`       | `E : K ⇀ V`      | **Effects** — a partial function mapping state keys to their post-execution values. After execution, `S_o(k) ← E(k)` for each `k ∈ dom(E)`. |
| `π`       | `π ∈ ℕ`          | **Priority** — a non-negative integer. Higher values are scheduled first when multiple operations compete. |

**Note on effects and provides.** Typically `dom(E) ⊆ P`, but this is not strictly required. An operation may have effects on keys it does not "provide" (side effects), though this is discouraged as it complicates reasoning.

---

## F.4 Guard Algebra

Guards are the precondition language of the engine. They form a small algebra closed under boolean combinators.

**Grammar.** The set of guard expressions `G` is defined inductively:

```
G ::= Eq(k, v)
    | Neq(k, v)
    | In(k, {v₁, …, vₙ})
    | Contains(k, s)
    | And(G₁, …, Gₙ)
    | Or(G₁, …, Gₙ)
    | Not(G)
    | True
```

**Evaluation semantics.** Given a state `S`, each guard variant evaluates as follows:

| Guard            | `G(S) = 1` iff |
| ---------------- | --------------- |
| `Eq(k, v)`       | `k ∈ dom(S) ∧ S(k) = resolve(v, S)` |
| `Neq(k, v)`      | `k ∉ dom(S) ∨ S(k) ≠ resolve(v, S)` |
| `In(k, V)`       | `k ∈ dom(S) ∧ S(k) ∈ V` |
| `Contains(k, s)` | `k ∈ dom(S) ∧ s` is a substring of `S(k)` |
| `And(G₁, …)`     | `∀ i : Gᵢ(S) = 1` |
| `Or(G₁, …)`      | `∃ i : Gᵢ(S) = 1` |
| `Not(G')`        | `G'(S) = 0` |
| `True`           | always 1 |

**Desired-state references.** Values `v` in guard and effect expressions may reference the desired state via `desired(k)`. The resolution function is:

```
resolve(v, S_o, S_d) =
    if v = desired(k'):
        return S_d(k')
    else:
        return v
```

**Conflict detection.** The function `conflicts_with_effect(G, k, v, S)` determines whether setting key `k` to value `v` in state `S` would cause guard `G` to transition from true to false. Used by the anti-oscillation logic (F.8):

```
conflicts_with_effect(G, k, v, S) = G(S) = 1  ∧  G(S[k ↦ v]) = 0
```

where `S[k ↦ v]` denotes the state `S` with key `k` overwritten to `v`.

---

## F.5 Hardware Profiles and Inheritance

**Definition.** A **hardware profile** is a tuple:

```
P = (id, M, I, Ω, α)
```

where:

| Component | Constraint        | Description |
| --------- | ----------------- | ----------- |
| `id`      | unique in `Π`     | Profile identifier (e.g., `nvidia_gb300`, `generic_x86`). `Π` is the set of all profiles. |
| `M`       | `M : S → {0, 1}`  | **Match rule** — a guard expression evaluated against observed state. The first non-abstract profile whose match rule holds is selected. |
| `I`       | `I ⊆ Π`           | **Inherits** — an ordered list of parent profile identifiers. |
| `Ω`       | `Ω = {ω₁, …, ωₘ}` | **Operations** — the set of operations defined in this profile. |
| `α`       | `α ∈ {0, 1}`      | **Is abstract** — if 1, the profile cannot be directly selected but can be inherited from. |

**Inheritance resolution.** The effective operation set for a profile `P` is computed by traversing the inheritance DAG in order and merging operations:

```
ops(P) = ops(P_I₁) ∪ ops(P_I₂) ∪ … ∪ Ω_P
```

When two profiles define an operation with the same `id`, the later definition wins (**last-writer-wins**).

**Profile detection algorithm:**

```
function detect_profile(S_o, profiles):
    for P in profiles sorted by specificity:
        if P.is_abstract: continue
        if P.match_rule(S_o) = 1:
            return P
    return error("no matching profile")
```

---

## F.6 Three-Predicate Scheduler

The scheduler is the decision-making core of the engine. On each tick, it evaluates every available operation against three predicates and selects a safe, non-conflicting action set.

**Predicate 1 — Relevant.** An operation is relevant if it provides at least one key in the current delta:

```
relevant(ω)  ⟺  P_ω ∩ Δ(S_o, S_d) ≠ ∅
```

**Predicate 2 — Constructive.** A relevant operation is constructive if at least one of its effects moves the observed state *toward* the desired state:

```
constructive(ω)  ⟺  ∃ k ∈ P_ω ∩ Δ : resolve(E_ω(k), S_o) = S_d(k)
```

**Predicate 3 — Ready.** A constructive, relevant operation is ready if its guard holds on the current observed state:

```
ready(ω)  ⟺  G_ω(S_o) = 1
```

**Candidate set.** The set of fully qualified candidates is:

```
R = { ω | relevant(ω) ∧ constructive(ω) ∧ ready(ω) }
```

**Greedy resource-conflict-free selection.** From `R`, the scheduler selects a maximal subset that respects resource locks:

**Algorithm:**

```
function schedule(R):
    sort R by priority π descending (stable sort preserves insertion order for ties)
    claimed_resources ← ∅
    scheduled ← []

    for ω in R:
        if L_ω ∩ claimed_resources = ∅:
            if not anti_oscillation_deferred(ω):
                scheduled.append(ω)
                claimed_resources ← claimed_resources ∪ L_ω

    return scheduled
```

**Formal property.** The scheduled set satisfies:

```
∀ ωᵢ, ωⱼ ∈ scheduled, i ≠ j : Lᵢ ∩ Lⱼ = ∅
```

No two scheduled operations hold the same resource lock.

---

## F.7 Dependency Resolution

Some operations are relevant and constructive but not ready — their guard fails on the current observed state. The dependency resolver attempts to find **enabler** operations that can satisfy the unmet preconditions.

**Unmet clause extraction.** For a blocked operation `ω_b` with `G(ω_b)(S_o) = 0`, the resolver decomposes the guard into its atomic `Eq` clauses and identifies which ones fail:

```
unmet(ω_b) = { (k, v) | Eq(k, v) ∈ atoms(G(ω_b))  ∧  S_o(k) ≠ resolve(v, S_o) }
```

For compound guards (`And`, `Or`), the decomposition follows the structure: for `And`, all failing clauses are unmet; for `Or`, only the first satisfiable branch is considered.

**Enabler search.** For each unmet clause `(k, v)`, the resolver searches for an enabler operation:

```
∃ ω_e ∈ Ω : E_e(k) = v  ∧  G_e(S_o) = 1  ∧  L_e ∩ L_claimed = ∅
```

where `L_claimed` is the set of resources already reserved by previously scheduled operations and other enablers.

**Resource pre-reservation.** When an enabler is found, its resources are immediately added to `L_claimed` before the main greedy pass.

**Dependency chain depth.** Dependencies are resolved to depth 1. Deeper chains are naturally resolved over multiple ticks by the convergence loop.

---

## F.8 Anti-Oscillation Guards

Without safeguards, the scheduler could enter infinite cycles — for example, `power_on` and `power_off` alternating each tick. Two guards prevent the most common oscillation patterns.

**Guard 1 — Dominance deferral.** An operation `ω` is deferred if it would undo the effect of a dependency action scheduled in the same tick:

```
ω deferred if ∃ ω_d ∈ deps, k ∈ P_ω ∩ P_d : E_ω(k) ≠ E_d(k)
```

**Guard 2 — Competitor blocking deferral.** An operation `ω` is deferred if its effect would falsify the guard of another ready operation that competes for the same resource:

```
ω deferred if ∃ ω_c ∈ R, L_ω ∩ L_c ≠ ∅ : conflicts_with_effect(G_c, k, E_ω(k), S_o) for some k
```

**Limitations.** These guards prevent 1-tick and 2-tick oscillation patterns but are **not a formal proof of termination**:

1. **Longer cycles** (3+ ticks) could theoretically occur with complex circular dependencies.
2. **Energy function non-monotonicity.** Dependency resolution can temporarily increase `|Δ|`.

**Safety net: visited-state detection.** The engine can optionally track visited state fingerprints and detect if the same observed state recurs, indicating an oscillation.

**Formal characterization.** Define the "energy" of the system as `|Δ(S_o, S_d)|`. In a well-configured operation set:

- Each constructive operation reduces `|Δ|` by at least 1 for its primary key.
- Dependency operations may temporarily increase `|Δ|` but are bounded in depth.
- The anti-oscillation guards ensure the scheduler does not undo its own progress within a single tick.

Under these conditions, the convergence loop terminates in `O(|Δ₀| · d)` ticks, where `|Δ₀|` is the initial delta size and `d` is the maximum dependency chain depth.

---

## F.9 Convergence Loop

**State evolution.** After each tick, the observed state is updated:

```
S_o(t+1) = S_o(t) ⊕ ⋃{ E_ω | ω ∈ actions(t) }
```

where `⊕` denotes state update (overwriting existing keys with new values from the effects).

**Termination conditions.** The loop terminates when:

1. **Converged:** `Δ(S_o, S_d) = ∅`.
2. **Idle with non-empty delta:** `actions(t) = ∅` but `Δ ≠ ∅`. Indicates misconfiguration, deadlock, or a transient condition awaiting external state changes.

**Fixpoint characterization.** The converged state `S_o*` is a **fixpoint** of the convergence operator:

```
S_o* = F(S_o*, S_d)  ⟺  Δ(S_o*, S_d) = ∅
```

The engine is a fixpoint-seeking iteration: `S_o⁰, S_o¹, …, S_oⁿ = S_o*`.

**Tick pseudocode:**

```
function tick(S_o, S_d, operations):
    Δ ← delta(S_o, S_d)
    if Δ = ∅: return CONVERGED

    relevant ← { ω ∈ operations | P_ω ∩ Δ ≠ ∅ }
    constructive ← { ω ∈ relevant | ∃ k ∈ P_ω ∩ Δ : resolve(E_ω(k), S_o, S_d) = S_d(k) }
    ready ← { ω ∈ constructive | G_ω(S_o, S_d) = 1 }
    blocked ← constructive \ ready

    deps ← resolve_dependencies(blocked, operations, S_o, S_d)
    actions ← schedule(ready ∪ deps, anti_oscillation_context)

    for ω in actions:
        execute(ω.steps)
        S_o ← S_o ⊕ resolve_effects(E_ω, S_o, S_d)

    return (actions, S_o)
```
