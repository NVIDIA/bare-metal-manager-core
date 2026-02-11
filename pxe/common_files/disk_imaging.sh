#!/bin/bash
#
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
file=
root_dev=
rootfs_uuid=
rootfs_label=
bootfs_uuid=
efifs_uuid=
efi_dev=
efi_label=
image_disk=
image_url=
image_sha=
image_auth_type=
image_auth_token=
distro_name=
distro_version=
distro_release=
serial_port=
serial_port_num=
log_output=
forge_test_user=
forge_test_pass=
update_grub_template="yes"
update_grub_cfg="yes"

function curl_url() {
	url=$1
	auth=$2
	curl --retry 5 --retry-all-errors -k -L -O $auth $url 2>&1 | tee $log_output
}

function verify_sha() {
	sha=$1

	len=$(expr length $sha)
	if [ $len -eq 40 ]; then
		shasum=shasum
	elif [ $len -eq 64 ]; then
		shasum=sha256sum
	elif [ $len -eq 96 ]; then
		shasum=sha384sum
	elif [ $len -eq 128 ]; then
		shasum=sha512sum
	else
		echo "Unknown sha digest length" | tee $log_output
		exit 1;
	fi
	echo "$sha $file" | $shasum --check 2>&1 | tee $log_output
}

function find_bootdisk() {
	if [ -b /dev/nvme0n1 ]; then
		image_disk="/dev/nvme0n1"
	elif [ -b /dev/sda ]; then
		image_disk="/dev/sda"
	else
		echo "Boot drive not detected or specified" | tee $log_output
		exit 1;
	fi
}

function get_distro_image() {
	arch=$(uname -m)
	if [ "$distro_name" == "ubuntu" ]; then
		if [ "$arch" == "x86_64" ]; then
			arch=amd64
		elif [ "$arch" == "aarch64" ]; then
			arch=arm64
		fi
		if [ "$distro_version" == "24.04" ]; then
			codename=noble
		elif [ "$distro_version" == "23.04" ]; then
			codename=lunar
		elif [ "$distro_version" == "22.10" ]; then
			codename=kinetic
		elif [ "$distro_version" == "22.04" ]; then
			codename=jammy
		elif [ "$distro_version" == "21.10" ]; then
			codename=impish
		elif [ "$distro_version" == "21.04" ]; then
			codename=hirsute
		elif [ "$distro_version" == "20.10" ]; then
			codename=groovy
		elif [ "$distro_version" == "20.04" ]; then
			codename=focal
		else
			echo "Ubuntu version $distro_version not supported" | tee $log_output
			exit 1;
		fi

		efi_label="UEFI"
		image_url=https://cloud-images.ubuntu.com/releases/$codename/release/ubuntu-$distro_version-server-cloudimg-$arch.img
		shaurl=https://cloud-images.ubuntu.com/releases/$codename/release/SHA256SUMS
	elif [ "$distro_name" == "debian" ]; then
		if [ "$arch" == "x86_64" ]; then
			arch=amd64
		elif [ "$arch" == "aarch64" ]; then
			arch=arm64
		fi
		if [ "$distro_version" == "10" ]; then
			codename=buster
		elif [ "$distro_version" == "11" ]; then
			codename=bullseye
		elif [ "$distro_version" == "12" ]; then
			codename=bookworm
		elif [ "$distro_version" == "sid" ]; then
			codename=sid
		else
			echo "Debian version $distro_version not supported" | tee $log_output
			exit 1;
		fi
		image_url=http://cdimage.debian.org/cdimage/cloud/$codename/daily/latest/debian-$distro_version-generic-$arch-daily.qcow2
		shaurl=http://cdimage.debian.org/cdimage/cloud/$codename/daily/latest/SHA512SUMS
	elif [ "$distro" == "centos" ]; then
		image_url=https://cloud.centos.org/centos/$distro_version-stream/$arch/images/CentOS-Stream-GenericCloud-$distro_version-latest.$arch.qcow2
		shaurl=https://cloud.centos.org/centos/$distro_version-stream/$arch/images/CentOS-Stream-GenericCloud-$distro_version-latest.$arch.SHA256SUM
	else
		echo "Distro $distro_name not supported" | tee $log_output
		exit 1;
	fi
	curl --retry 5 --retry-all-errors -k -L $shaurl --output shafile 2>&1 | tee $log_output
	file=$(basename $image_url)
	image_sha=$(grep -m 1 $file shafile)
}

function add_cloud_init() {
	echo "fetching from cloud-init url: $cloud_init_url" | tee $log_output
	if [ -d /mnt/etc/cloud/cloud.cfg.d ]; then
		echo "datasource_list: [ NoCloud, None ]" | tee /mnt/etc/cloud/cloud.cfg.d/98-forge-dslist.cfg
		curl --retry 5 --retry-all-errors -k "$cloud_init_url/user-data" --output /mnt/etc/cloud/cloud.cfg.d/99-user-data.cfg 2>&1 | tee $log_output
	fi
}

function expand_root_fs() {
	is_nvme=$(echo $root_dev | grep nvme)
	if [ ! -z "$is_nvme" ]; then
		part_num=$(echo $root_dev | cut -d'p' -f2)
		growpart "$image_disk" "$part_num" 2>&1 | tee $log_output
		partprobe $image_disk 2>&1 | tee $log_output
		udevadm trigger 2>&1 | tee $log_output
		resize2fs -fF "$root_dev" 2>&1 | tee $log_output
	fi
	# not handling lvm resize currently
}

function get_root_dev() {
	if [ ! -z "$rootfs_uuid" ]; then
		root_dev=$(blkid -U $rootfs_uuid)
	elif [ ! -z "$rootfs_label" ]; then
		root_dev=$(blkid -L $rootfs_label)
	else
		echo "rootfs_uuid not specified and rootfs_label not determined" | tee $log_output
		echo "skipping root device changes" | tee $log_output
	fi
	if [ ! -z "$efi_label" ]; then
		efi_dev=$(blkid -L $efi_label)
	fi
}

function is_port_in_list() {
	my_test_port=$1
	my_port_list=$2
	my_serial_port=""

	for port in $my_port_list
	do
		if [ "$port" == "$my_test_port" ]; then
			my_serial_port=$port
			break
		fi
	done
	echo $my_serial_port
}

function get_serial_port() {
	serial_port=""
	candidate_serial_ports="ttyS0 ttyS1 ttyAMA0"
	working_serial_ports=""
	preferred_port_arm="ttyAMA0"
	preferred_port_lenovo_supermicro="ttyS1"
	default_port="ttyS0"
	my_arch=$(uname -m)

	# See which ports we can write to
	for test_port in $candidate_serial_ports
	do
		echo "" >/dev/$test_port 2>/dev/null
		if [ $? -eq 0 ]; then
			working_serial_ports="$working_serial_ports $test_port"
		fi
	done
	working_serial_ports=$(echo "$working_serial_ports" | sed -e 's/^ *//g' -e 's/ *$//g')
	echo "Working serial ports = [${working_serial_ports}]"

	preferred_port=$default_port
	if [ "$my_arch" == "aarch64" ]; then
		preferred_port=$preferred_port_arm
	else
		if [ -f "/sys/class/dmi/id/sys_vendor" ]; then
			sys_vendor=$(</sys/class/dmi/id/sys_vendor)
			if [[ "$sys_vendor" =~ Lenovo || "$sys_vendor" =~ Supermicro ]]; then
				preferred_port=$preferred_port_lenovo_supermicro
			fi
		fi
	fi
	serial_port=$(is_port_in_list $preferred_port "$working_serial_ports")

	# If we couldn't find a preferred serial port, drop back to the first working one
	if [ "$serial_port" == "" ]; then
		serial_port=$(echo $working_serial_ports | awk '{print $1}')
		# If we still don't have one, default to console
		if [ "$serial_port" == "" ]; then
			serial_port="console"
		fi
	fi

	if [ "$serial_port" == "console" ]; then
		serial_port_num=0
	else
		serial_port_num=$(echo $serial_port | sed 's/[^0-9]//g' )
	fi

	log_output="/dev/$serial_port"
	echo "Using serial port: [$serial_port] ($serial_port_num)" | tee $log_output
}

function modify_grub_cfg() {
	efi_mounted=
	if [ ! -d "/mnt/boot/grub" ]; then
		boot_part=
		if [ ! -z "$bootfs_uuid" ]; then
			boot_part=$(blkid -U $bootfs_uuid)
		fi
		is_nvme=$(echo $image_disk | grep nvme)
		if [ -z "$boot_part" ]; then
			if [ ! -z "$is_nvme" ]; then
				boot_part="$image_disk"p1
			else
				boot_part="$image_disk"1
			fi
		fi

		if [ ! -b "$boot_part" ]; then
			# This is not error, as CentOS, for example, does not have dedicated /boot partition
			echo "Boot partition $boot_part not found or is not a block device" | tee $log_output
		else
			mount "$boot_part" /mnt/boot
		fi
		# we want to mount efi now as it can contain uefi grub.cfg
		mount_efi
		efi_mounted=true
		grub_cfg=
		if [ -f "/mnt/boot/grub/grub.cfg" ]; then
			grub_cfg="/mnt/boot/grub/grub.cfg"
		elif [ -f "/mnt/boot/grub.cfg" ]; then
			grub_cfg="/mnt/boot/grub.cfg"
		elif [ -f "/mnt/boot/grub2/grub.cfg" ]; then
			grub_cfg="/mnt/boot/grub2/grub.cfg"
		else
			grub_cfg=$(find /mnt/boot -name grub.cfg -print -quit)
		fi
		if [ -z "$grub_cfg" ]; then
			echo "grub.cfg not found" | tee $log_output
			umount /mnt/boot
			return 0
		fi
	fi
	mount -o bind /dev /mnt/dev
	mount -o bind /proc /mnt/proc
	mount -o bind /sys /mnt/sys
	echo "Updating grub configuration" | tee $log_output
	# if we skipped grub mount before we want to mount efi now
	if [ -z "$efi_mounted" ]; then
		mount_efi
	fi
	# Check if grub2-mkconfig exists, means we are in rhel distro, falback to update-grub if not found
	if [ -f "/mnt/usr/sbin/grub2-mkconfig" ]; then
		is_bls=$(chroot /mnt /bin/sh -c "grub2-mkconfig --help" | grep "\-\-update-bls-cmdline")
		grub_bls_cmd=
		if [ ! -z "$is_bls" ]; then
			grub_bls_cmd="--update-bls-cmdline"
		fi
		chroot /mnt /bin/sh -c "grub2-mkconfig $grub_bls_cmd -o ${grub_cfg#'/mnt'}" 2>&1 | tee $log_output
	else
		chroot /mnt /bin/sh -c update-grub 2>&1 | tee $log_output
	fi
	umount /mnt/boot/efi 2>&1 | tee $log_output
	umount /mnt/sys
	umount /mnt/proc
	umount /mnt/dev
	if [[ $(grep '\/mnt\/boot' /proc/mounts) ]]; then
		umount /mnt/boot
	fi
}

function mount_efi() {
	if [ ! -z "$efifs_uuid" ]; then
		efi_dev=$(blkid -U $efifs_uuid)
	fi
	if [ ! -z "$efi_dev" ]; then
		mount $efi_dev /mnt/boot/efi 2>&1 | tee $log_output
	else
		chroot /mnt /bin/sh -c 'mount /boot/efi' 2>&1 | tee $log_output
	fi
}

function add_testing_user() {
	if [ -z "$forge_test_user" ]; then
		return 0
	fi
	if [ ! -f "/mnt/etc/passwd" ]; then
		return 0
	fi
	echo "useradd -s /bin/bash -d /home/$forge_test_user -m -G sudo $forge_test_user" > /mnt/test_user.sh 2>&1 | tee $log_output
	echo "echo \"$forge_test_user:$forge_test_pass\" | chpasswd" >> /mnt/test_user.sh 2>&1 | tee $log_output
	echo "passwd --expire $forge_test_user" >> /mnt/test_user.sh 2>&1 | tee $log_output
	chmod +x /mnt/test_user.sh 2>&1 | tee $log_output
	chroot /mnt /bin/sh -c ./test_user.sh 2>&1 | tee $log_output
	rm -f /mnt/test_user.sh 2>&1 | tee $log_output
}

function modify_grub_template() {
	if [ ! -f "/mnt/etc/default/grub" ]; then
		return 0
	fi
	new_grub_template="/mnt/grub_default"
	echo > $new_grub_template
	cmdline_found=
	serial_found=
	terminal_found=
	while read -r tmp; do
		if [[ "$tmp" =~ ^\ *# ]]; then
			echo "$tmp" >> $new_grub_template
		else
			if [[ "$tmp" =~ GRUB_CMDLINE_LINUX= ]]; then
				first_console_set=
				second_console_set=
				if [ -z "$cmdline_found" ]; then
					# ensure console is set
					echo -n "GRUB_CMDLINE_LINUX=\"" >> $new_grub_template
					cmdline_args=$(echo $tmp | sed s/GRUB_CMDLINE_LINUX=//g | sed s/^\"//g | sed s/\"$//g)
					for i in $(echo $cmdline_args); do
						kernel_arg=$(echo $i|grep console)
						if [ ! -z "$kernel_arg" ]; then
							if [ -z "$first_console_set" ]; then
								echo -n "console=tty0 " >> $new_grub_template
								first_console_set=true
							elif [ -z "$second_console_set" ]; then
								echo -n "console=$serial_port " >> $new_grub_template
								second_console_set=true
							else
								echo -n "$kernel_arg " >> $new_grub_template
							fi
						else
							echo -n "$i " >> $new_grub_template
						fi
					done
					# parsed grub cmdline for linux and didnt find any console specified, add it
					if [ -z "$first_console_set" ]; then
						echo -n "console=tty0 " >> $new_grub_template
						first_console_set=true
					fi
					if [ -z "$second_console_set" ]; then
						echo -n "console=$serial_port,115200" >> $new_grub_template
						second_console_set=true
					fi
					echo "\"" >> $new_grub_template
					cmdline_found="started"
				fi
			elif [[ "$tmp" =~ GRUB_TERMINAL ]]; then
				if [ -z "$terminal_found" ]; then
					echo "GRUB_TERMINAL=serial" >> $new_grub_template
					terminal_found=true
				fi
			elif [[ "$tmp" =~ GRUB_SERIAL_COMMAND ]]; then
				if [ -z "$serial_found" ]; then
					echo "GRUB_SERIAL_COMMAND=\"serial --speed=115200 --unit=$serial_port_num --word=8 --parity=no --stop=1\"" >> $new_grub_template
					serial_found=true
				fi
			else
				echo "$tmp" >> $new_grub_template
			fi
		fi
	done < "/mnt/etc/default/grub"
	# done parsing the file, didn't find the grub args
	if [ -z "$cmdline_found" ]; then
		echo "GRUB_CMDLINE_LINUX=\"console=tty0 console=$serial_port,115200\"" >> $new_grub_template
	fi
	if [ -z "$serial_found" ]; then
		echo "GRUB_SERIAL_COMMAND=\"serial --speed=115200 --unit=$serial_port_num --word=8 --parity=no --stop=1\"" >> $new_grub_template
	fi
	if [ -z "$terminal_found" ]; then
		echo "GRUB_TERMINAL=serial" >> $new_grub_template
	fi
	cat $new_grub_template > /mnt/etc/default/grub
}

function main() {

	get_serial_port
	# look for a distro and version (and release for centos)
	#  image_distro_name=ubuntu
	#  image_distro_version=20.04
	# or a url for a disk image (and a sha256 optionally)
	#  image_url=<url>
	#  image_sha=[sha1/sha256/sha384/sha512]
	# use the disk the tenant specified optionally
	#  image_disk=/dev/nvme0n1
	for i in `cat /proc/cmdline`
	do
		#echo $line
		line=$(echo $i|grep image_url)
		if [ ! -z "$line" ]; then
			image_url=$(echo $line|cut -d'=' -f2)
		fi
		line=$(echo $i|grep image_sha)
		if [ ! -z "$line" ]; then
			image_sha=$(echo $line|cut -d'=' -f2)
		fi
		line=$(echo $i|grep image_auth_type)
		if [ ! -z "$line" ]; then
			image_auth_type=$(echo $line|cut -d'=' -f2)
		fi
		line=$(echo $i|grep image_auth_token)
		if [ ! -z "$line" ]; then
			image_auth_token=$(echo $line|cut -d'=' -f2)
		fi
		line=$(echo $i|grep image_disk)
		if [ ! -z "$line" ]; then
			image_disk=$(echo $line|cut -d'=' -f2)
		fi
		line=$(echo $i|grep image_distro_name)
		if [ ! -z "$line" ]; then
			distro_name=$(echo $line|cut -d'=' -f2|tr '[:upper:]' '[:lower:]')
		fi
		line=$(echo $i|grep image_distro_version)
		if [ ! -z "$line" ]; then
			distro_version=$(echo $line|cut -d'=' -f2)
		fi
		line=$(echo $i|grep image_distro_release)
		if [ ! -z "$line" ]; then
			distro_release=$(echo $line|cut -d'=' -f2)
		fi
		line=$(echo $i|grep 'ds=nocloud-net;s')
		if [ ! -z "$line" ]; then
			cloud_init_url=$(echo $line|cut -d'=' -f3)
		fi
		line=$(echo $i|grep 'create_forge_test_user')
		if [ ! -z "$line" ]; then
			user_pass=$(echo $line|cut -d'=' -f2)
			forge_test_user=$(echo $user_pass|cut -d':' -f1)
			forge_test_pass=$(echo $user_pass|cut -d':' -f2)
		fi
		line=$(echo $i|grep 'rootfs_uuid')
		if [ ! -z "$line" ]; then
			rootfs_uuid=$(echo $line|cut -d'=' -f2)
		fi
		line=$(echo $i|grep 'rootfs_label')
		if [ ! -z "$line" ]; then
			rootfs_label=$(echo $line|cut -d'=' -f2)
		else
			rootfs_label="cloudimg-rootfs" #default rootfs name for cloud images
		fi
		line=$(echo $i|grep 'bootfs_uuid')
		if [ ! -z "$line" ]; then
			bootfs_uuid=$(echo $line|cut -d'=' -f2)
		fi
		line=$(echo $i|grep 'efifs_uuid')
		if [ ! -z "$line" ]; then
			efifs_uuid=$(echo $line|cut -d'=' -f2)
		fi
		line=$(echo $i|grep 'update_grub_template')
		if [ ! -z "$line" ]; then
			update_grub_template=$(echo $line|cut -d'=' -f2)
		fi
		line=$(echo $i|grep 'update_grub_cfg')
		if [ ! -z "$line" ]; then
			update_grub_cfg=$(echo $line|cut -d'=' -f2)
		fi

	done

	if [ ! -z "$distro_name" ]; then
		get_distro_image
	fi

	if [ -z "$image_url" ]; then
		echo "Could not resolve disk image to use from arguments in /proc/cmdline" | tee $log_output
		return 1;
	fi

	if [ -z $file ]; then
		file=$(basename $image_url)
	fi

	if [ ! -z "$image_auth_token" ]; then
		if [ -z "$image_auth_type" ]; then
		       image_auth_type=Bearer
		fi
		image_auth="-H \"Authorization: $image_auth_type $image_auth_token\""
	fi

	echo "Downloading image from $image_url" | tee $log_output
	curl_url $image_url $image_auth
	if [ ! -z "$image_sha" ]; then
		echo "Verifying image with digest $image_sha" | tee $log_output
		verify_sha $image_sha
		if [ $? -ne 0 ]; then
			echo "Image checksum validation failed" | tee $log_output
			return 1;
		fi
	fi
	if [ -z "$image_disk" ]; then
		find_bootdisk
	fi

	echo "Imaging $file to $image_disk" | tee $log_output
	qemu-img convert -p -O raw $file $image_disk 2>&1 | tee $log_output
	ret=$?
	if [ $ret -ne 0 ]; then
		echo "Imaging failed $ret" | tee $log_output
		return $ret;
	fi

	sgdisk -epv $image_disk 2>&1 | tee $log_output
	partprobe $image_disk 2>&1 | tee $log_output
	for cmd in pvscan vgscan lvscan
	do
		$cmd | tee $log_output
		udevadm settle | tee $log_output
	done
	if [ ! -z "$rootfs_uuid" -o ! -z "$rootfs_label" ]; then
		# find the root partition/volume
		get_root_dev
		echo "Root device [$root_dev]" | tee $log_output
		if [ -b "$root_dev" ]; then
			mount "$root_dev" /mnt 2>&1 | tee $log_output
			if [ "${update_grub_template}" == "yes" ]; then
				echo "Updating grub template" | tee $log_output
				modify_grub_template
			fi
			if [ "${update_grub_cfg}" == "yes" ]; then
				echo "Updating grub cfg" | tee $log_output
				modify_grub_cfg
			fi
			if [ ! -z "$cloud_init_url" ]; then
				add_cloud_init
			fi
			add_testing_user
			umount /mnt 2>&1 | tee $log_output
			expand_root_fs
		fi
	fi
}

main
echo "Rebooting" | tee $log_output
systemctl reboot | tee $log_output
