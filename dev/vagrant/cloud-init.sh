#!/usr/bin/env bash

set -ex

SUCCESS_INDICATOR=/opt/.vagrant_provision_success
# check if vagrant_provision has run before
[[ -f $SUCCESS_INDICATOR ]] && exit 0

cp -f /tmp/vagrant/50-custom.cfg /etc/cloud/cloud.cfg.d/50-custom.cfg

# re-reun cloud-init with 50-custom.cfg
cloud-init clean
cloud-init init
cloud-init modules
cloud-init modules --mode final

# create vagrant_provision on successful run
touch $SUCCESS_INDICATOR

exit 0
