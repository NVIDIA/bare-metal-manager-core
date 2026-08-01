# `nico-admin-cli boot-interface candidates`

_[Hardware commands](../../hardware.md) › [boot-interface](./boot-interface.md) › **candidates**_

## NAME

nico-admin-cli-boot-interface-candidates - List boot-interface
candidates for a machine and the picks among them

## SYNOPSIS

**nico-admin-cli boot-interface candidates** \[**--extended**\]
\[**--sort-by**\] \[**-h**\|**--help**\] \<*MACHINE*\>

## DESCRIPTION

List every NIC that could be the boot interface for a machine -- the
managed `machine_interfaces` rows and the pre-first-lease predictions --
and mark the picks among them: `current` (what resolution targets now:
the primary interface if one is set, else the lowest-MAC non-underlay
interface), `default` (what the automatic selection would choose if no
primary interface were set), and `explored` (the default site-explorer
recorded for the BMC endpoint of the machine). Underlay rows are listed
but marked ineligible. Every pick is computed server-side by the same
selection code the machine-controller acts on. Read-only.

## OPTIONS

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

\<*MACHINE*\>  
The machine ID whose boot-interface candidates to list

## Examples

```sh
nico-admin-cli boot-interface candidates 12345678-1234-5678-90ab-cdef01234567
nico-admin-cli --format json boot-interface candidates 12345678-1234-5678-90ab-cdef01234567
```

---

**See also:** [Hardware commands](../../hardware.md) · [CLI reference index](../../README.md)
