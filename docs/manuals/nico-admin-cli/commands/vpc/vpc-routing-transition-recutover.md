# `nico-admin-cli vpc routing-transition recutover`

_[Network commands](../../network.md) › [vpc](./vpc.md) › [routing-transition](./vpc-routing-transition.md) › **recutover**_

## NAME

nico-admin-cli-vpc-routing-transition-recutover - Switch a rolled-back
transition to its retained target again

## SYNOPSIS

**nico-admin-cli vpc routing-transition recutover**
\[**--if-version-match**\] \[**--extended**\] \[**--sort-by**\]
\[**-h**\|**--help**\] \<*ID*\>

## DESCRIPTION

Switch a rolled-back transition to its retained target again

## OPTIONS

**--if-version-match** *\<IF_VERSION_MATCH\>*  
Expected transition version; omit to read the current version
immediately before the action

**--extended**  
Extended result output.

This used by measured boot, where basic output contains just what you
probably care about, and "extended" output also dumps out all the
internal UUIDs that are used to associate instances.

**--sort-by** *\<SORT_BY\>* \[default: primary-id\]  
Sort output by specified field  

  
*Possible values:*

> - primary-id: Sort by the primary ID
>
> - state: Sort by state

**-h**, **--help**  
Print help (see a summary with -h)

\<*ID*\>  
Transition operation ID

## Examples

```sh
nico-admin-cli --cloud-unsafe-op=my_username vpc routing-transition recutover abcdef01-2345-6789-abcd-ef0123456789
```

---

**See also:** [Network commands](../../network.md) · [CLI reference index](../../README.md)
