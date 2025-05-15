"""
Module to validate machine capabilities against expected configuration.

This module provides functionality to validate a machine's hardware components
against expected capabilities defined in a JSON file. It supports validating
both component counts and specific hardware properties.
"""

import json
import sys


def load_expected_capabilities(machine_id):
    """
    Load expected capabilities for a machine from capabilities.json file.

    Args:
        machine_id: ID of the machine to validate

    Returns:
        Dictionary containing expected capabilities for the machine

    Raises:
        ValueError: If the machine is not found in capabilities.json
    """
    try:
        # Look for capabilities.json in current directory
        with open("capabilities.json", "r") as f:
            capabilities_data = json.load(f)

        # Find the entry for the specified machine_id
        for entry in capabilities_data:
            if entry.get("machine_id") == machine_id:
                return entry.get("capabilities", {})

        # Machine not found in capabilities.json
        msg = f"Machine {machine_id} not found in capabilities.json."
        msg += " Run generate_capabilities.py to create an entry."
        raise ValueError(msg)

    except (FileNotFoundError, json.JSONDecodeError) as e:
        # Handle file not found or JSON parsing errors
        raise ValueError(f"Failed to load capabilities.json: {str(e)}")


def get_machine_capabilities(machine_id, admin_cli):
    """
    Get actual capabilities of a machine using admin_cli.

    Args:
        machine_id: ID of the machine to get capabilities for
        admin_cli: admin_cli module to use for querying the machine

    Returns:
        Dictionary containing actual capabilities of the machine
    """
    # Get machine data using admin_cli
    machine_data = admin_cli.get_machine_from_mh_show(machine_id)

    if not machine_data:
        raise ValueError(f"Failed to get data for machine {machine_id}")

    # Extract capabilities from machine data
    capabilities = {}
    discovery_info = machine_data.get("discovery_info", {})

    # Map component types to their discovery_info keys
    component_types = [
        "network_interfaces",
        "cpus",
        "block_devices",
        "nvme_devices",
        "infiniband_interfaces",
        "gpus",
        "memory_devices"
    ]

    for component_type in component_types:
        capabilities[component_type] = discovery_info.get(component_type, [])

    # DPUs are not in discovery_info but at the top level
    # Extract DPU information including model from discovery_info when available
    dpus = []
    for dpu in machine_data.get("dpus", []):
        dpu_info = {
            "serial_number": dpu.get("serial_number"),
            "bmc_firmware_version": dpu.get("bmc_firmware_version")
        }

        # Extract model from DPU discovery_info if available
        if ("discovery_info" in dpu and 
                "dpu_info" in dpu["discovery_info"]):
            dpu_details = dpu["discovery_info"]["dpu_info"]
            if "part_description" in dpu_details:
                dpu_info["model"] = dpu_details["part_description"]

        dpus.append(dpu_info)

    capabilities["dpus"] = dpus

    return capabilities


def match_specific_properties(actual_items, expected_items):
    """
    Match specific properties between actual and expected items.

    Args:
        actual_items: List of dictionaries with actual component properties
        expected_items: List of dictionaries with expected component properties

    Returns:
        Tuple of (match_count, mismatches)
        - match_count: Number of matched items
        - mismatches: List of dictionaries with details of mismatches
    """
    # If expected items are empty objects, only check count
    if all(not item for item in expected_items):
        return len(actual_items), []

    # Try to match each expected item with an actual item
    matches = 0
    mismatches = []

    # Track which actual items have been matched
    matched_indices = set()

    for expected_item in expected_items:
        # Skip empty objects (placeholder items)
        if not expected_item:
            matches += 1
            continue

        # Try to find a matching item that hasn't been matched already
        found_match = False

        # First try to match by serial_number if it exists (especially for DPUs)
        if "serial_number" in expected_item:
            for i, actual_item in enumerate(actual_items):
                if i in matched_indices:
                    continue

                serial_match = (actual_item.get("serial_number") == 
                               expected_item["serial_number"])
                if serial_match:
                    # Found match by serial number, check other properties
                    is_match = True
                    mismatch_props = {}

                    for prop, expected_value in expected_item.items():
                        actual_value = actual_item.get(prop)
                        if actual_value != expected_value:
                            is_match = False
                            mismatch_props[prop] = {
                                "expected": expected_value,
                                "actual": actual_value
                            }

                    # Even if there are mismatches in other properties,
                    # we consider this the right item to match against
                    matches += 1
                    matched_indices.add(i)

                    # Record any mismatches found with this item
                    if not is_match:
                        mismatches.append({
                            "expected": expected_item,
                            "mismatched_properties": mismatch_props
                        })

                    found_match = True
                    break

        # If no match by serial number, try regular property matching
        if not found_match:
            for i, actual_item in enumerate(actual_items):
                if i in matched_indices:
                    continue

                # Check if all expected properties match
                is_match = True
                mismatch_props = {}

                for prop, expected_value in expected_item.items():
                    actual_value = actual_item.get(prop)
                    if actual_value != expected_value:
                        is_match = False
                        mismatch_props[prop] = {
                            "expected": expected_value,
                            "actual": actual_value
                        }

                if is_match:
                    matches += 1
                    matched_indices.add(i)
                    found_match = True
                    break

            if not found_match:
                mismatches.append({
                    "expected": expected_item,
                    "mismatched_properties": mismatch_props
                })

    return matches, mismatches


def validate_capabilities(expected, actual):
    """
    Validate actual capabilities against expected capabilities.

    Args:
        expected: Dictionary of expected capabilities
        actual: Dictionary of actual capabilities

    Returns:
        Tuple of (valid, validation_results)
        - valid: Boolean indicating whether validation passed
        - validation_results: Dictionary with detailed validation results
    """
    validation_results = {}
    all_valid = True

    # Validate each component type
    for component_type, expected_items in expected.items():
        actual_items = actual.get(component_type, [])
        expected_count = len(expected_items)
        actual_count = len(actual_items)

        # Check if component count matches
        count_valid = actual_count >= expected_count

        # Check specific properties if component count is sufficient
        property_mismatches = []
        if count_valid:
            matches, property_mismatches = match_specific_properties(
                actual_items, expected_items
            )
            properties_valid = matches >= expected_count
        else:
            properties_valid = False

        # Overall validation for this component type
        component_valid = count_valid and properties_valid

        # Store validation results
        validation_results[component_type] = {
            "valid": component_valid,
            "count_valid": count_valid,
            "properties_valid": properties_valid,
            "expected_count": expected_count,
            "actual_count": actual_count,
            "mismatches": property_mismatches
        }

        # Update overall validation result
        all_valid = all_valid and component_valid

    return all_valid, validation_results


def print_validation_results(validation_results, verbose=True):
    """
    Print validation results in a human-readable format.

    Args:
        validation_results: Dictionary with validation results
        verbose: Whether to print detailed information about mismatches
    """
    print("\nMachine Capabilities Validation Results:")

    for component_type, result in validation_results.items():
        status = "✓" if result["valid"] else "✗"

        print(f"{status} {component_type}: "
              f"{result['actual_count']}/{result['expected_count']}")

        # Print detailed mismatches if verbose and there are mismatches
        if verbose and not result["valid"]:
            if not result["count_valid"]:
                print(f"  Insufficient count: Found {result['actual_count']}, "
                      f"expected {result['expected_count']}")

            # Print property mismatches
            if result["mismatches"]:
                print("  Property mismatches:")
                for i, mismatch in enumerate(result["mismatches"], 1):
                    print(f"  Item {i}:")
                    for prop, values in mismatch.get("mismatched_properties", {}).items():
                        print(f"    {prop}: expected={values['expected']}, "
                              f"actual={values['actual']}")


def validate_machine_capabilities(machine_id, expected_capabilities, admin_cli):
    """
    Validate machine capabilities against expected configuration.

    Args:
        machine_id: ID of the machine to validate
        admin_cli: admin_cli module to use for querying the machine

    Returns:
        True if validation succeeds, False otherwise
    """
    try:
        # Get actual machine capabilities
        print(f"Retrieving actual capabilities for machine {machine_id}...")
        actual_capabilities = get_machine_capabilities(machine_id, admin_cli)

        # Validate capabilities
        print("Validating machine capabilities...")
        valid, validation_results = validate_capabilities(
            expected_capabilities, actual_capabilities
        )

        # Print validation results
        print_validation_results(validation_results)

        if valid:
            print("\nMachine capabilities validation passed.")
        else:
            print("\nMachine capabilities validation failed.")
            print("The machine does not meet the expected hardware " 
                  "capabilities.")
            print("Consider putting the machine into maintenance mode.")

        return valid

    except ValueError as e:
        print(f"Error validating machine capabilities: {e}", file=sys.stderr)
        return False
