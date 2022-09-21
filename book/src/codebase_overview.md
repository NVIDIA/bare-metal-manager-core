# Codebase overview

api - forge primary entrpoint for GRPC API calls. This component receives all the  GRPC calls

book/ - architecture of forge book.  aka "the book"

cli/ - a command line client for the carbide API server

dev/ - a catch all directory for things that are not code related but are used
to support forge.  e.g. Dockerfiles, kubernetes yaml, etc.

dhcp/ - kea dhcp plugin.  Forge uses ISC Kea for a dhcp event loop.  This code
intercepts `DHCPDISCOVER`s from dhcp-relays and passes the info to carbide-api

include/ - contains additional makefiles that are used by `cargo make` - as specified in `Makefile.toml`.

dns/ - provides DNS resolution for assets in forge databse

ipmi/ - a rust FFI library around FreeIPMI.  This is used for issuing IPMI
commands to machines

pxe/ - forge-pxe is a web service which provides iPXE and cloud-init data to
machines

rpc/ - protobuf definitions and a rust library which handles marshalling
data from/to GRPC to native rust types

vendor/ - external libraries

vpc/ - local copy of forge-vpc code. Used when building local containers
