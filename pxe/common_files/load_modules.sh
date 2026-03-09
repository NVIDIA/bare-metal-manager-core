#!/bin/bash

udevadm trigger --wait-daemon --type=devices --subsystem-match=pci --action=add --settle
