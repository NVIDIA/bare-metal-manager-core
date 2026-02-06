# Release Instance API Enhancements

## What's New

The Release Instance API now supports **issue reporting** and **automated repair workflows**. When releasing an instance, you can report problems to help improve system reliability.

### Key Features
- **Report Issues**: Hardware, Network, Performance, or Other problems
- **Auto-Repair**: Makes machines available for repair plugins/systems to fix issues
- **Repair Integration**: Special handling for repair systems
- **Enhanced Labels**: Machine metadata labels for repair status tracking

## Quick Start

REST API:

### Basic Release (No Issues)
```bash
curl -X POST /api/v1/instances/release \
  -d '{"id": "instance-12345"}'
```

### Release with Issue Report
```bash
curl -X POST /api/v1/instances/release \
  -d '{
    "id": "instance-12345",
    "issue": {
      "category": "HARDWARE",
      "summary": "Memory errors during training",
      "details": "Job crashed with ECC errors on DIMM slot 2"
    }
  }'
```

## Issue Categories

| Category | When to Use | Examples |
|----------|-------------|----------|
| **HARDWARE** | Physical component failures | Memory errors, GPU failures, disk problems |
| **NETWORK** | Connectivity issues | Slow InfiniBand, packet loss, timeouts |
| **PERFORMANCE** | Slower than expected | Thermal throttling, reduced GPU performance |
| **OTHER** | Software/config issues | Driver problems, CUDA version mismatches |

## What Happens When You Report Issues

When you release an instance with issue reporting, the system automatically takes several actions to fix the machine and prevent the issue-reported machine from being allocated to tenants until resolved:

### Immediate Actions
1. **Health Override Application** - Marks machine with health status and prevents new allocations
2. **Issue Logging** - Records problem details for tracking and analysis
3. **Auto-Repair Signal** - Makes machine available for repair plugins to act on (if enabled)

### Health Override Types

The system uses two complementary health overrides to manage the repair workflow:

| Override | Purpose | Behavior | When Applied |
|----------|---------|----------|--------------|
| **`tenant-reported-issue`** | Documents tenant-reported problems | Prevents machine allocation until resolved | Always when issue is reported |
| **`repair-request`** | Signals automated repair needed | Triggers breakfix system to claim machine | When auto-repair is enabled or manually applied |

### Auto-Repair Behavior
- **Enabled**: Machine gets both overrides (`tenant-reported-issue` + `repair-request`) - repair plugins can act on the machine
- **Disabled**: Machine gets only `tenant-reported-issue` override (manual intervention needed)

### Carbide - Breakfix Integration Workflow

#### Workflow Overview

The breakfix integration follows this automated repair cycle:

1. **Issue Reporting**: Tenant releases instance and reports hardware/software problems via API
2. **Health Override Application**: System applies appropriate health overrides based on configuration
3. **Repair System Activation**: Breakfix system detects machines marked for repair and claims them
4. **Automated Repair**: Repair tenant diagnoses and fixes the reported issues
5. **Validation & Release**: Successfully repaired machines return to the available pool


#### Stage Details

1. **Normal Operation**: Machine serves tenant workloads without issues
2. **Issue Reported**: Tenant releases instance with problem details via API
3. **Quarantined**: Machine marked with health overrides, preventing new allocations
4. **Repair Process**:
   - If auto-repair enabled: Repair plugins automatically attempt fixes
   - If auto-repair disabled: Manual intervention required by operations team
5. **Resolution**: Machine either gets repaired successfully or escalated for further action
6. **Return to Pool**: Successfully repaired machines with `repair_status="Completed"` return to the available pool

## Repair Status Labels

Repair systems use machine metadata labels to communicate repair outcomes back to Forge:

### Critical Label: `repair_status`
| Value | Meaning | Result |
|-------|---------|--------|
| `"Completed"` | Repair successful | Machine returns to available pool |
| `"Failed"` | Repair couldn't fix issue | Escalated to operations team |
| `"InProgress"` | Repair still running | Treated as failed if instance released |

> **⚠️ Important**: Repair systems **must** set `repair_status` before releasing instances. Missing or invalid labels result in failed repair handling.

### Optional Labels
- `repair_details`: Explanation of what was done (e.g., `"thermal_paste_replaced"`)
- `repair_eta`: Expected completion time for planning purposes


## Configuration

### Auto-Repair Settings
```toml
>>carbide-api-site-config.toml
...
[auto_machine_repair_plugin]
enabled = true
...

```


## Frequently Asked Questions (FAQ)

### Q1: Tenant releases machine reporting issue but `auto_machine_repair_plugin.enabled` is false

**Scenario:** A tenant calls the release API with issue details, but automatic repair is disabled in the site configuration.

**What happens:**
- Machine is released and marked with issue details
- Health override `tenant-reported-issue` IS applied (issue is documented)
- Health override `repair-request` is NOT applied (no automatic repair triggered)
- Machine becomes unavailable for normal allocation due to tenant-reported-issue override

**Resolution:**
```bash
# Check current configuration (requires server access to config file)
# Auto-repair setting is in carbide-api-site-config.toml

# Manually trigger repair using health override
carbide-admin-cli machine health-override add <machine-id> --template RequestRepair \
  --message "Manual repair trigger for tenant-reported issue"

# To enable auto-repair site-wide, update carbide-api-site-config.toml:
# [auto_machine_repair_plugin]
# enabled = true
```

**Best Practice:** Enable auto-repair in production environments to ensure tenant-reported issues are automatically handled.

---

### Q2: Tenant releases machine reporting issue but repair tenant hasn't picked up the machine

**Scenario:** Auto-repair is enabled, tenant reports issue, health override is applied, but repair tenant hasn't started working on the machine.

**What happens:**
- Machine gets `tenant-reported-issue` health override (documents the issue)
- Machine gets `repair-request` health override (signals repair system)
- Machine becomes unavailable for normal tenant allocation
- Repair plugins should detect and claim the machine
- If repair tenant doesn't pick up machine, it remains in limbo

**Troubleshooting:**
```bash
# Check machine status and health overrides
carbide-admin-cli machine show <machine-id>
carbide-admin-cli machine health-override show <machine-id>

# Check repair system status (requires monitoring tools)
# - Check repair tenant instances
# - Verify repair system connectivity

# Manually assign repair override if needed
carbide-admin-cli machine health-override add <machine-id> --template RequestRepair \
  --message "Manual assignment for repair system"
```

**Common Causes:**
- Repair tenant is at capacity
- Repair plugins are not running
- Machine doesn't match repair tenant's allocation criteria
- Network connectivity issues between repair systems

---

### Q3: Repair tenant releases machine as "fixed" but machine still needs repair

**Scenario:** Repair tenant completes work and releases machine claiming it's fixed, but the underlying issue persists.

**What happens:**
- Health override `repair-request` is removed (repair claimed complete)
- If repair tenant reports new issues: `tenant-reported-issue` override is applied
- If repair tenant reports new issues: Machine does NOT return to available pool
- If no new issues reported: Both overrides removed, machine returns to available pool
- Auto-repair is NOT triggered again (prevents infinite repair loops)

**Detection and Response:**
```bash
# Check machine status and current health overrides
carbide-admin-cli machine show <machine-id>
carbide-admin-cli machine health-override show <machine-id>

# Check repair work status (requires access to repair system logs)
# - Review repair tenant instance logs
# - Check repair system monitoring

# If issue persists, escalate to manual intervention
carbide-admin-cli machine health-override add <machine-id> --template OutForRepair \
  --message "Repair unsuccessful, requires manual investigation"
```

**Prevention:**
- Implement repair validation tests
- Require repair tenants to provide detailed fix reports
- Set up monitoring to detect recurring issues on same machines
- Establish escalation procedures for failed repairs

---

### Q4: Repair tenant successfully fixes machine and reports completion

**Scenario:** The ideal case where repair tenant successfully resolves the issue and properly reports completion.

**What happens:**
- Repair tenant releases machine with success status (repair_status = "Completed")
- Health override `repair-request` is automatically removed
- Health override `tenant-reported-issue` is automatically removed
- Machine returns to healthy, available state
- Machine becomes available for normal tenant allocation

**Verification Steps:**
```bash
# Confirm machine is healthy and available
carbide-admin-cli machine show <machine-id>

# Check that health overrides are cleared
carbide-admin-cli machine health-override show <machine-id>

# Verify machine status (should show as available)
# Machine should appear in normal allocation pool

# Review repair work (requires access to repair system)
# - Check repair tenant instance completion status
# - Review repair system logs and reports
```

**Success Indicators:**
- ✅ Machine status: `Available`
- ✅ Health overrides: None or only non-blocking ones
- ✅ Recent allocation tests pass
- ✅ Repair logs show successful completion
- ✅ No recurring issues reported

---

### Q5: Repair tenant releases machine without setting repair_status

**Scenario:** Repair tenant completes work and releases machine but forgets to set the repair_status metadata or sets it to something other than "Completed".

**What happens:**
- Machine has existing `repair-request` health override
- Repair tenant releases machine without `repair_status = "Completed"`
- System treats this as **failed/incomplete repair**
- Health override `repair-request` is automatically removed
- Health override `tenant-reported-issue` is applied (or updated if already exists)
- Machine does NOT return to available pool
- Auto-repair is NOT triggered again (prevents infinite loops)

**Detection:**
```bash
# Check machine status after repair tenant release
carbide-admin-cli machine show <machine-id>
carbide-admin-cli machine health-override show <machine-id>

# Look for:
# - repair-request override: REMOVED
# - tenant-reported-issue override: PRESENT
# - Machine status: NOT available for allocation
```

**Resolution:**
```bash
# If repair was actually successful, manually clear the issue
carbide-admin-cli machine health-override remove <machine-id> tenant-reported-issue

# If repair was incomplete, escalate properly
carbide-admin-cli machine health-override add <machine-id> --template OutForRepair \
  --message "Repair incomplete - requires manual investigation"
```

**Prevention:**
- **Train repair tenants** to always set repair_status metadata
- **Implement validation** in repair workflows to ensure status is set
- **Monitor for machines** released by repair tenant without "Completed" status
- **Set up alerts** for machines with tenant-reported-issue after repair tenant release

**Best Practice:**
```bash
# Repair tenants should always set metadata before release:
# repair_status = "Completed"  # for successful repairs
# repair_status = "Failed"     # for unsuccessful repairs
# repair_status = "InProgress" # repair in progress
```

---

### General Troubleshooting Commands

**Check Auto-Repair Configuration:**
```bash
# Auto-repair settings are in carbide-api-site-config.toml
# [auto_machine_repair_plugin]
# enabled = true|false

# Check current runtime configuration
carbide-admin-cli version --show-runtime-config
```

**Monitor Issue Reporting:**
```bash
# Check machine status and health overrides
carbide-admin-cli machine show <machine-id>
carbide-admin-cli machine health-override show <machine-id>

# Monitor machine through repair cycle (requires external monitoring)
```

**Manual Intervention:**
```bash
# Remove specific health overrides
carbide-admin-cli machine health-override remove <machine-id> repair-request
carbide-admin-cli machine health-override remove <machine-id> tenant-reported-issue

# Apply manual repair override
carbide-admin-cli machine health-override add <machine-id> --template RequestRepair \
  --message "Manual repair assignment"

# Escalate to operations team
carbide-admin-cli machine health-override add <machine-id> --template OutForRepair \
  --message "Automated repair failed, requires manual investigation"
```

---

This enhanced API improves system reliability by enabling structured issue reporting, automated repairs, and better coordination between tenants, repair systems, and operations teams.
