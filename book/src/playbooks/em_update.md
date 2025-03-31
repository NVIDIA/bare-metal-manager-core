# Updating Expected Machines Manifest

There is a table in the carbide-api database, that holds the following information about the expected machines:
* Chassis Serial Number
* BMC MAC Address
* BMC manufacturer's set login
* BMC manufacturer's set password
* DPU's chassis serial number (only needed for Vikings).

There is a `forge-admin-cli` command to manipulate expected machines table. `update`, `add`, `delete` commands allow operating on individual elements of the expected machines table. `erase` and `replace-all` operate on all the entries at once.

Additionally, the expected machines table can be exported as a JSON file with `forge-admin-cli -f json em show` command. Likewise, a JSON file can be used to import and overwrite all existing values with `forge-admin-cli em replace-all <filename>` command.

Currently, the https://gitlab-master.nvidia.com/nvmetal/deployments repository contains the latest versions of expected machine manifests in JSON format for each site. The procedure for updating expected machines table for a site is this:
1. Create a branch out of deployment's main branch.
2. Update corresponding expected machines manifests file, e.g. `az23_expected_machines.json`.
3. Retrieve existing expected machines list with `forge-admin-cli -f json em show`.
4. Using a JSON diff tool compare the new version with the existing one to make sure there are no inadvertent overwrites.
5. Raise the MR and merge it back into main.
6. Finally, update the expected machines table with e.g. `forge-admin-cli em replace-all az23_expected_machines.json`.

# Further Reading

* Please see [FORGE-4120](https://jirasw.nvidia.com/browse/FORGE-4120) on the initial attempt to create expected machines manifests from the available data.
* [This comment](https://jirasw.nvidia.com/browse/FORGE-4120?focusedId=13555392&page=com.atlassian.jira.plugin.system.issuetabpanels%3Acomment-tabpanel#comment-13555392) describes how the expected machines manifests were generated.
* [This is the latest version](https://gitlab-master.nvidia.com/nvmetal/tools/-/blob/main/em-transform.source?ref_type=heads) of script that was used to generate expected machines manifests.
* [This document](https://nvidia-my.sharepoint.com/:x:/r/personal/apatten_nvidia_com/Documents/Desktop/forge_mac_addresses.xlsx?d=w4ee5c82042734023a2b2cbb22b48850f&csf=1&web=1&e=LnoGKb) contains some of the inventory information for non-az sites (specific access request may be required).
* [This table](https://docs.google.com/spreadsheets/d/1Hr567WqyDSJt6Sw5MsoKObFWtKTWktZb8FklsP8Rhgk/edit?usp=sharing) contains some inventory information for az sites (specific access request may be required).



