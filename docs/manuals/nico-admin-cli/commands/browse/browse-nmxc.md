# `nico-admin-cli browse nmxc`

_[Hardware commands](../../hardware.md) › [browse](./browse.md) › **nmxc**_

## NAME

nico-admin-cli-browse-nmxc - Run an NMX-C browse operation via the API
server

## SYNOPSIS

**nico-admin-cli browse nmxc** \<**--chassis-serial**\>
\<**--operation**\> \[**--gpu-uid**\] \[**--extended**\]
\[**--sort-by**\] \[**-h**\|**--help**\]

## DESCRIPTION

Run an NMX-C browse operation via the API server

## OPTIONS

**--chassis-serial** *\<CHASSIS_SERIAL\>*  
Chassis serial number

**--operation** *\<OPERATION\>*  
NMX-C browse operation to run\

\
*Possible values:*

- compute-node-info-list

- gpu-info

- gpu-info-list

**--gpu-uid** *\<GPU_UID\>* \[default: 0\]  
GPU UID (used by the gpu-info operation)

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
nico-admin-cli browse nmxc --chassis-serial 1234567890 --operation gpu-info-list
nico-admin-cli browse nmxc --chassis-serial 1234567890 --operation compute-node-info-list
nico-admin-cli browse nmxc --chassis-serial 1234567890 --operation gpu-info --gpu-uid 42
```

---

**See also:** [Hardware commands](../../hardware.md) · [CLI reference index](../../README.md)
