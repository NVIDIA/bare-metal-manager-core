#!/usr/bin/env bash

mkdir -p /tmp/ipmi_state
ipmi_sim -c ${REPO_ROOT}/dev/ipmi/lan.conf -f ${REPO_ROOT}/dev/ipmi/cmd.conf -s /tmp/ipmi_state
