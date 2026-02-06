# Updating Expected Machines Manifest

There is a table in the carbide-api database, that holds the following information about the expected machines:
* Chassis Serial Number
* BMC MAC Address
* BMC manufacturer's set login
* BMC manufacturer's set password
* DPU's chassis serial number (only needed for DGX-H100, or other machines that do not have NetworkAdapter Serial number available in the host redfish).

There is a `carbide-admin-cli` command to manipulate expected machines table. `update`, `add`, `delete` commands allow operating on individual elements of the expected machines table. `erase` and `replace-all` operate on all the entries at once.

Additionally, the expected machines table can be exported as a JSON file with `carbide-admin-cli -f json em show` command. Likewise, a JSON file can be used to import and overwrite all existing values with `forge-admin-cli em replace-all <filename>` command.
