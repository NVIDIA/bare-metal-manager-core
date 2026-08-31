-- Let an operator pin the Redfish BMC vendor for a host, holding a RedfishVendor
-- variant name that is forced into libredfish. NULL means automatic detection.
ALTER TABLE expected_machines ADD COLUMN bmc_vendor_override text;
