# `nico-admin-cli boot-interface show`

_[Hardware commands](../../hardware.md) › [boot-interface](./boot-interface.md) › **show**_

## NAME

nico-admin-cli-boot-interface-show - Show boot interfaces for a machine
from every store (troubleshooting)

## SYNOPSIS

**nico-admin-cli boot-interface show** \[**--extended**\]
\[**--sort-by**\] \[**-h**\|**--help**\] \<*MACHINE*\>

## DESCRIPTION

Gather the boot-interface view for one machine from all four stores and
print them together: the managed \`machine_interfaces\` rows
(authoritative for a managed machine), \`predicted_machine_interfaces\`
(pre-first-lease candidates), the \`explored_endpoints\` default (for
endpoints without a machine), and the retained post-deletion pairs
(including stale records). Also reports the effective boot interface the
system would select and flags when the stores disagree. Read-only.

## OPTIONS

**--extended**  
Extended result output.

This used by measured boot, where basic output contains just what you
probably care about, and "extended" output also dumps out all the
internal UUIDs that are used to associate instances.

**--sort-by** *\<SORT_BY\>* \[default: primary-id\]  
Sort output by specified field  

  
*Possible values:*

> - primary-id: Sort by the primary id
>
> - state: Sort by state

**-h**, **--help**  
Print help (see a summary with -h)

\<*MACHINE*\>  
The machine ID whose boot interfaces to gather

## Examples

```sh
nico-admin-cli boot-interface show 12345678-1234-5678-90ab-cdef01234567
nico-admin-cli --format json boot-interface show 12345678-1234-5678-90ab-cdef01234567
nico-admin-cli --format yaml boot-interface show 12345678-1234-5678-90ab-cdef01234567
```

---

**See also:** [Hardware commands](../../hardware.md) · [CLI reference index](../../README.md)
