#!/bin/bash

devices=$(lsblk -n | grep " 1 disk" | awk '{print $1}')

for dev in ${devices}
do
	basedev=$(echo $dev | sed 's/n[0-9][0-9]*$//')
	ns=$(echo $dev | sed 's/.*n\([0-9][0-9]*\)$/\1/')
	bse=$(nvme id-ns /dev/${dev} | grep "in use" | awk '{print $5}' | cut -d: -f2)
	bs=$((2 ** $bse))
	cap=$(nvme id-ns /dev/${dev} | grep -i nvmcap | awk '{print $NF}')
	capb=$(($cap / $bs))
	ctrl=$(nvme id-ctrl /dev/${dev} | grep "^cntlid" | awk '{print $NF}')
	echo "Device ${dev} capacity ${cap} blocksize ${bs} blocks ${capb} controller ${ctrl}"

	nvme delete-ns /dev/${basedev} -n ${ns}
	nvme create-ns /dev/${basedev} --nsze=${capb} --ncap=${capb} --flbas=0 -dps=0
	nvme attach-ns /dev/${basedev} --namespace-id=${ns} -controllers=${ctrl}
	nvme ns-rescan /dev/${basedev}
done

