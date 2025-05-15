import argparse
import json
import os
import admin_cli


def get_machine_info(machine_id):
    """Get detailed information about a machine."""
    return admin_cli.run_forge_admin_cli(["managed-host", "show", machine_id])


def extract_essential_properties(item_list, essential_props):
    """
    Extract a list of items with only essential properties.

    Args:
        item_list: List of items (e.g., GPUs, CPUs)
        essential_props: List of property names to keep

    Returns:
        List of items with only essential properties
    """
    result = []
    for item in item_list:
        filtered_item = {}
        for prop in essential_props:
            if prop in item:
                filtered_item[prop] = item[prop]
        result.append(filtered_item)
    return result


def extract_capability_structure(machine_data):
    """Extract the capability structure with essential hardware properties."""
    capabilities = {}
    discovery_info = machine_data.get("discovery_info", {})

    # Network interfaces - keep essential properties
    network_props = ["mac_address", "pci_properties"]
    capabilities["network_interfaces"] = extract_essential_properties(
        discovery_info.get("network_interfaces", []),
        network_props
    )

    # CPUs - keep essential properties
    cpu_props = ["vendor", "model", "frequency", "socket"]
    capabilities["cpus"] = extract_essential_properties(
        discovery_info.get("cpus", []),
        cpu_props
    )

    # Block devices - keep essential properties
    block_device_props = ["model", "serial"]
    capabilities["block_devices"] = extract_essential_properties(
        discovery_info.get("block_devices", []),
        block_device_props
    )

    # NVMe devices - keep essential properties
    nvme_props = ["model", "firmware_rev"]
    capabilities["nvme_devices"] = extract_essential_properties(
        discovery_info.get("nvme_devices", []),
        nvme_props
    )

    # InfiniBand interfaces
    capabilities["infiniband_interfaces"] = discovery_info.get(
        "infiniband_interfaces", []
    )

    # GPUs - keep essential properties
    gpu_props = ["name", "total_memory"]
    capabilities["gpus"] = extract_essential_properties(
        discovery_info.get("gpus", []),
        gpu_props
    )

    # Memory devices - keep essential properties
    memory_props = ["size_mb", "mem_type"]
    capabilities["memory_devices"] = extract_essential_properties(
        discovery_info.get("memory_devices", []),
        memory_props
    )

    # DPUs require special handling since they're not in discovery_info
    dpu_props = ["serial_number", "bmc_firmware_version"]
    capabilities["dpus"] = []
    for dpu in machine_data.get("dpus", []):
        dpu_info = {}
        for prop in dpu_props:
            if prop in dpu:
                dpu_info[prop] = dpu[prop]

        # Include DPU model from discovery_info if available
        if ("discovery_info" in dpu and 
                "dpu_info" in dpu["discovery_info"]):
            dpu_details = dpu["discovery_info"]["dpu_info"]
            if "part_description" in dpu_details:
                dpu_info["model"] = dpu_details["part_description"]

        capabilities["dpus"].append(dpu_info)

    return capabilities


def process_machine(machine_id, counts_only):
    """
    Process a single machine and return its capabilities entry.

    Args:
        machine_id: ID of the machine to process
        counts_only: Whether to only store counts rather than properties

    Returns:
        Dictionary with machine_id and capabilities structure
    """
    print(f"Querying machine {machine_id}...")
    machine_data = get_machine_info(machine_id)

    # Extract capabilities with properties
    capabilities = extract_capability_structure(machine_data)

    # If counts-only is specified, replace with empty objects
    if counts_only:
        for component_type, components in capabilities.items():
            capabilities[component_type] = [{} for _ in range(len(components))]

    # Return structured entry for capabilities.json
    return {
        "machine_id": machine_id,
        "capabilities": capabilities
    }


def print_capability_summary(capabilities, machine_id):
    """Print a summary of the capabilities for a machine.

    Args:
        capabilities: Dictionary of component capabilities
        machine_id: ID of the machine for labeling the summary
    """
    print(f"\nCapability Summary for {machine_id}:")
    for component, items in capabilities.items():
        detail = ""
        if component == "gpus" and items and "name" in items[0]:
            models = set(item.get("name", "Unknown") for item in items)
            detail = f" ({', '.join(models)})"
        elif component == "dpus" and items and "model" in items[0]:
            models = set(item.get("model", "Unknown") for item in items)
            detail = f" ({', '.join(models)})"
        print(f"  {component}: {len(items)} items{detail}")


def generate_capabilities(machine_ids, counts_only=False):
    """
    Generate capabilities.json for a list of machine IDs.

    Args:
        machine_ids: List of machine IDs to generate capabilities for
        counts_only: Whether to only store component counts, not detailed properties

    Returns:
        If single machine_id is provided, returns the capabilities dictionary for that machine.
        Otherwise returns list of dictionaries containing machine_id and capabilities for all machines.
    """
    capabilities_data = []
    existing_machine_ids = set()

    # Process each machine
    for machine_id in machine_ids:
        capabilities_entry = process_machine(machine_id, counts_only)

        # Print a summary of the captured capabilities
        print_capability_summary(
            capabilities_entry["capabilities"], 
            machine_id
        )

        # Replace entry if machine already exists, otherwise append
        if machine_id in existing_machine_ids:
            for i, entry in enumerate(capabilities_data):
                if entry.get("machine_id") == machine_id:
                    capabilities_data[i] = capabilities_entry
                    break
        else:
            capabilities_data.append(capabilities_entry)
            existing_machine_ids.add(machine_id)
            print(f"Added new entry for {machine_id}")

    # If only one machine was requested, return just its capabilities dictionary
    if len(machine_ids) == 1:
        return capabilities_data[0]["capabilities"]

    return capabilities_data
