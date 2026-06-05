# Operation Rules Versioning Strategy

## Overview

The `RuleDefinition` structure includes a `version` field to support forward compatibility. This allows safe schema evolution without breaking existing rules stored in the database.

## Current Version

**v1** - Initial rule definition schema with:
- `version` field (string)
- `steps` array (SequenceStep objects)

Each step includes:
- `component_type` - Device type to operate on
- `stage` - Execution stage number
- `max_parallel` - Component concurrency limit
- `delay_after` - Post-completion delay
- `timeout` - Step timeout
- `retry` - Retry policy configuration

## How Versioning Works

### Automatic Version Assignment

All rule definitions are automatically versioned:

```go
// When creating rules from YAML
RuleDefinition{
    Version: CurrentRuleDefinitionVersion, // "v1"
    Steps:   steps,
}

// When marshaling to database
func MarshalRuleDefinition(rd RuleDefinition) (json.RawMessage, error) {
    if rd.Version == "" {
        rd.Version = CurrentRuleDefinitionVersion
    }
    return json.Marshal(rd)
}
```

### Version-Aware Unmarshaling

When reading from database, the system checks the version:

```go
func UnmarshalRuleDefinition(data json.RawMessage) (*RuleDefinition, error) {
    // Peek at version field
    var versionCheck struct {
        Version string `json:"version"`
    }
    json.Unmarshal(data, &versionCheck)

    // Route to version-specific unmarshaler
    switch versionCheck.Version {
    case "v1":
        return unmarshalRuleDefinitionV1(data)
    case "v2":  // Future version
        return unmarshalRuleDefinitionV2(data)
    default:
        return nil, fmt.Errorf("unsupported version: %s", versionCheck.Version)
    }
}
```

### Backward Compatibility

Rules without a version field (shouldn't exist, but handle gracefully) are assumed to be v1:

```go
if version == "" {
    version = "v1"  // Assume v1 for missing version
}
```

## Adding a New Version

When you need to change the `RuleDefinition` structure:

### 1. Update the Constant

```go
// In internal/task/operationrules/rules.go
const CurrentRuleDefinitionVersion = "v2"
```

### 2. Define the New Structure

```go
// Keep v1 structure for unmarshalin
type RuleDefinitionV1 struct {
    Version string         `json:"version"`
    Steps   []SequenceStep `json:"steps"`
}

// Define v2 structure (example with new fields)
type RuleDefinition struct {
    Version      string         `json:"version"`
    Steps        []SequenceStep `json:"steps"`
    Dependencies []string       `json:"dependencies,omitempty"` // NEW in v2
    Metadata     map[string]string `json:"metadata,omitempty"`  // NEW in v2
}
```

### 3. Add Version-Specific Unmarshaler

```go
func unmarshalRuleDefinitionV2(data json.RawMessage) (*RuleDefinition, error) {
    var rd RuleDefinition
    if err := json.Unmarshal(data, &rd); err != nil {
        return nil, fmt.Errorf("failed to unmarshal v2 rule definition: %w", err)
    }

    if rd.Version == "" {
        rd.Version = "v2"
    }

    return &rd, nil
}
```

### 4. Update the Switch Statement

```go
switch version {
case "v1":
    return unmarshalRuleDefinitionV1(data)
case "v2":
    return unmarshalRuleDefinitionV2(data)
default:
    return nil, fmt.Errorf("unsupported version: %s", version)
}
```

### 5. Implement Migration (Optional)

If you want to auto-migrate old rules:

```go
func unmarshalRuleDefinitionV1(data json.RawMessage) (*RuleDefinition, error) {
    var v1 RuleDefinitionV1
    if err := json.Unmarshal(data, &v1); err != nil {
        return nil, err
    }

    // Convert v1 to v2
    v2 := &RuleDefinition{
        Version:      "v2",
        Steps:        v1.Steps,
        Dependencies: nil,        // New field, set default
        Metadata:     make(map[string]string), // New field, set default
    }

    return v2, nil
}
```

## Database Storage

The `rule_definition` column stores the entire JSON with version:

```json
{
  "version": "v1",
  "steps": [
    {
      "component_type": "powershelf",
      "stage": 1,
      "max_parallel": 1,
      "delay_after": "30s",
      "timeout": "10m",
      "retry": {
        "max_attempts": 3,
        "initial_interval": "5s",
        "backoff_coefficient": 2.0
      }
    }
  ]
}
```

## Migration Strategy

### Option 1: Lazy Migration (Recommended)

- Keep v1 unmarshaler working indefinitely
- Auto-convert v1 to v2 in memory when reading
- Write back as v2 when updating
- Old rules gradually migrate as they're edited

### Option 2: Explicit Migration

- Create a migration script
- Read all rules from database
- Convert to new version
- Write back to database

Example migration script:

```go
func MigrateRulesToV2(ctx context.Context, store Store) error {
    rules, _, err := store.ListRules(ctx, &ListOptions{}, &Pagination{Limit: 1000})
    if err != nil {
        return err
    }

    for _, rule := range rules {
        if rule.RuleDefinition.Version == "v1" {
            // Update version
            rule.RuleDefinition.Version = "v2"
            // Set new fields to defaults
            rule.RuleDefinition.Dependencies = nil
            rule.RuleDefinition.Metadata = make(map[string]string)

            // Save back to database
            if err := store.UpdateRule(ctx, rule.ID, &UpdateOptions{
                RuleDefinition: &rule.RuleDefinition,
            }); err != nil {
                return fmt.Errorf("failed to migrate rule %s: %w", rule.ID, err)
            }
        }
    }

    return nil
}
```

## Version Detection CLI

Add a command to check rule versions in the database:

```bash
# Check rule versions
flow rule versions

# Output:
# v1: 45 rules
# v2: 12 rules
# Total: 57 rules
```

## Best Practices

1. **Always increment version** when changing RuleDefinition structure
2. **Keep old unmarshalers** for backward compatibility
3. **Set version explicitly** in all new rules
4. **Test migration** before deploying schema changes
5. **Document changes** in this file for each version
6. **Consider lazy migration** instead of forced migration
7. **Add validation** for new fields in new versions

## Version History

### v1 (Initial - 2026-02-04)

**Structure:**
- `version` - Schema version
- `steps` - Array of execution steps

**Features:**
- Stages for sequential/parallel execution
- Component-level batching (max_parallel)
- Per-step delays, timeouts, retries
- Component type targeting

**Use Case:** Basic operation sequencing with parallelism control

---

### v2 (Future - Example)

**Structure:**
- `version` - Schema version
- `steps` - Array of execution steps
- `dependencies` - Rule dependencies (NEW)
- `metadata` - Custom metadata (NEW)

**Features:**
- Rule dependencies for complex workflows
- Custom metadata for tracking/reporting
- All v1 features retained

**Migration:** Auto-convert v1 rules by adding empty dependencies and metadata

---

## Testing Versioning

### Test Unmarshaling Old Version

```go
func TestUnmarshalV1Rule(t *testing.T) {
    v1JSON := `{
        "version": "v1",
        "steps": [
            {
                "component_type": "compute",
                "stage": 1,
                "max_parallel": 8,
                "delay_after": "10s",
                "timeout": "20m"
            }
        ]
    }`

    rd, err := UnmarshalRuleDefinition(json.RawMessage(v1JSON))
    assert.NoError(t, err)
    assert.Equal(t, "v1", rd.Version)
    assert.Len(t, rd.Steps, 1)
}
```

### Test Version Upgrade

```go
func TestVersionUpgrade(t *testing.T) {
    // Create v1 rule
    v1Rule := &RuleDefinition{
        Version: "v1",
        Steps:   []SequenceStep{...},
    }

    // Marshal and unmarshal
    data, _ := json.Marshal(v1Rule)
    v2Rule, err := UnmarshalRuleDefinition(data)

    // Should auto-convert to v2 with defaults
    assert.NoError(t, err)
    assert.Equal(t, "v2", v2Rule.Version)
    assert.NotNil(t, v2Rule.Dependencies)
}
```

## Summary

The versioning system provides:
- ✅ **Forward compatibility** - Old rules work with new code
- ✅ **Schema evolution** - Add new fields without breaking existing rules
- ✅ **Gradual migration** - No forced database migrations
- ✅ **Clear versioning** - Explicit version in every rule
- ✅ **Error handling** - Graceful failures for unsupported versions
