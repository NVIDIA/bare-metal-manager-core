# `nico-admin-cli redfish dpu firmware update`

_[Hardware commands](../../hardware.md) › [redfish](./redfish.md) › [dpu](./redfish-dpu.md) › [firmware](./redfish-dpu-firmware.md) › **update**_

## NAME

nico-admin-cli-redfish-dpu-firmware-update - Update BMC firmware to the
given firmware package

## SYNOPSIS

**nico-admin-cli redfish dpu firmware update** \<**-p**\|**--package**\>
\[**--extended**\] \[**--sort-by**\] \[**-h**\|**--help**\]

## DESCRIPTION

Update BMC firmware to the given firmware package

## OPTIONS

**-p**, **--package** *\<PACKAGE\>*  
FW package to install

**--extended**  
Extended result output.

This used by measured boot, where basic output contains just what you
probably care about, and "extended" output also dumps out all the
internal UUIDs that are used to associate instances.

**--sort-by** *\<SORT_BY\>* \[default: primary-id\]  
Sort output by specified field\

\
*Possible values:*

- primary-id: Sort by the primary id

- state: Sort by state

**-h**, **--help**  
Print help (see a summary with -h)

## Examples

```sh
nico-admin-cli redfish --address 192.0.2.10 --username admin --password mypassword dpu firmware update --package ./bmc-fw.fwpkg
```

---

**See also:** [Hardware commands](../../hardware.md) · [CLI reference index](../../README.md)
