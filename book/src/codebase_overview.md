# Codebase overview


bluefield/ - `forge-dpu-agent` and other tools running on the DPU

book/ - architecture of forge book.  aka "the book"

- admin/ - `carbide-admin-cli`: A command line client for the carbide API server
- api/ - forge primary entrypoint for GRPC API calls. This component receives all the  GRPC calls
- scout/ - `forge-scout`. A binary that runs on Forge managed hosts and DPUs and executes various parts workflows on behalf of the site controller

dev/ - a catch all directory for things that are not code related but are used to support forge.  e.g. Dockerfiles, kubernetes yaml, etc.

dhcp/ - kea dhcp plugin.  Forge uses ISC Kea for a dhcp event loop.  This code intercepts `DHCPDISCOVER`s from dhcp-relays and passes the info to carbide-api

dhcp-server/ - DHCP Server written in Rust. This server runs on the DPU and serves Host DHCP requests

dns/ - provides DNS resolution for assets in forge database

include/ - contains additional makefiles that are used by `cargo make` - as specified in `Makefile.toml`.

log-parser/ - Service which parses SSH console logs and generates health alerts based on them

pxe/ - forge-pxe is a web service which provides iPXE and cloud-init data to
machines

rpc/ - protobuf definitions and a rust library which handles marshalling
data from/to GRPC to native rust types

crates/

