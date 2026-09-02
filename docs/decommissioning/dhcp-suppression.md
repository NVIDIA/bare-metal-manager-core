# DHCP Suppression for Decommissioned BMC MAC Addresses

## Overview

As the final step of rack uningestion/decommissioning, the DHCP server must stop
leasing IP addresses to BMCs whose MAC addresses are marked as ignored. This
document describes the suppression mechanism added to NICo Core's `DiscoverDhcp`
RPC to support this.

No changes were required to the DHCP server binary itself. Suppression is handled
entirely within Core.

---

## Background

When a rack is decommissioned, the BMC MAC addresses for that rack are added to
the `ignored_bmc_macs` table with `suppress_dhcp = true`. This signals that the
DHCP server should no longer serve those MACs.

The desired behavior per DHCP message type:

| DHCP message | Expected behavior |
|---|---|
| `DHCPDISCOVER` | Ignore the request and record the suppression acknowledgement |
| `DHCPREQUEST` | Respond with `DHCPNAK` to signal the BMC to clear its configured IP |

---

## Implementation

### Where the change lives

`crates/api-core/src/dhcp/discover.rs`, inside the `DiscoverDhcp` RPC handler.

### What it does

Early in the `DiscoverDhcp` request path, after the MAC address is parsed,
the handler calls `db::bmc_suppression::acknowledge()`. This function:

1. Checks whether the MAC address has an active DHCP suppression entry in
   `ignored_bmc_macs` (`suppress_dhcp = true`)
2. If suppressed, atomically records `dhcp_discover_suppressed_at` (the
   timestamp at which the suppression was acknowledged)
3. Commits the transaction
4. Returns `true` to signal that suppression is active

When suppression is active the handler returns `FailedPrecondition` immediately,
before any lease logic runs:

```rust
if db::bmc_suppression::acknowledge(
    &mut txn,
    parsed_mac,
    model::bmc_suppression::BmcSuppressionSubsystem::Dhcp,
)
.await?
{
    txn.commit().await?;
    return Err(CarbideError::FailedPrecondition(format!(
        "dhcp suppressed for bmc mac {parsed_mac}"
    )));
}
```

The `FailedPrecondition` response causes the DHCP server to send a `DHCPNAK`,
which tells the BMC DHCP client to release its IP and return to the `INIT` state.

### Atomicity

The acknowledgement and timestamp write happen inside the same transaction as the
suppression check, so there is no window between checking and recording.

---

## Decommission Workflow Integration

The decommission workflow polls `dhcp_discover_suppressed_at` on each BMC's
suppression record to confirm the BMC DHCP client has received the NAK and
returned to `INIT` state. Only after this timestamp is set does the workflow
consider DHCP suppression complete for that BMC.

This polling ensures the decommission sequence does not advance until the BMC
has actually stopped holding a leased IP address.

---

## Cache Invalidation

The DHCP record cache can be invalidated independently of the suppression
mechanism to force a fresh lookup from the database. This is useful when
suppression records are added or modified outside of the normal decommission
flow.

---

## Known Limitations / Open Items

- The suppression check is currently only wired into `DiscoverDhcp`. A
  `DHCPREQUEST` that arrives without a preceding `DHCPDISCOVER` (e.g. on
  network reconnect) will still be served unless the DHCP server independently
  checks suppression status.
- `suppress_dhcp` must be set on the `ignored_bmc_macs` record before the
  decommission workflow polls for `dhcp_discover_suppressed_at`; the ordering
  is the caller's responsibility.
