#!/bin/bash
file=
root_dev=
rootfs_uuid=
rootfs_label=
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

function curl_url() {
	url=$1
	auth=$2
	file=$(basename $url)
	curl -k -L $auth $url --output $file 2>&1 | tee $log_output
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
		fi
		if [ "$distro_version" == "23.04" ]; then
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
		rootfs_label="cloudimg-rootfs"
		efi_label="UEFI"
		image_url=https://cloud-images.ubuntu.com/releases/$codename/release/ubuntu-$distro_version-server-cloudimg-$arch.img
		shaurl=https://cloud-images.ubuntu.com/releases/$codename/release/SHA256SUMS
	elif [ "$distro_name" == "debian" ]; then
		if [ "$arch" == "x86_64" ]; then
			arch=amd64
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
	curl -k -L $shaurl --output shafile 2>&1 | tee $log_output
	file=$(basename $image_url)
	image_sha=$(grep -m 1 $file shafile)
}

function add_cloud_init() {
	echo "fetching from cloud-init url: $cloud_init_url" | tee $log_output
	if [ -d /mnt/etc/cloud/cloud.cfg.d ]; then
		curl -k "$cloud_init_url/user-data" --output /mnt/etc/cloud/cloud.cfg.d/user-data.cfg 2>&1 | tee $log_output
		echo "verifying cloud-init user data written to /etc/cloud/cloud.cfg.d/user-data.cfg" | tee $log_output
		chroot /mnt /bin/sh -c 'cloud-init schema --config-file /etc/cloud/cloud.cfg.d/user-data.cfg' 2>&1 | tee $log_output
	fi
}

function expand_root_fs() {
	is_nvme=$(echo $root_dev | grep nvme)
	if [ ! -z "$is_nvme" ]; then
		part_num=$(echo $root_dev | cut -d'p' -f2)
		growpart "$image_disk" "$part_num" 2>&1 | tee $log_output
		partprobe $image_disk 2>&1 | tee $log_output
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

function get_serial_port() {
	serial_port="ttyS0"
	serial_port_num="0"
	if [ -f "/sys/class/dmi/id/sys_vendor" ]; then
		sys_vendor=$(</sys/class/dmi/id/sys_vendor)
		if [[ "$sys_vendor" =~ Lenovo ]]; then
			serial_port="ttyS1"
			serial_port_num="1"
		fi
	fi
	log_output="/dev/$serial_port"
	echo "Using serial port: $serial_port" | tee $log_output
}

function modify_grub_cfg() {
	if [ ! -d "/mnt/boot/grub" ]; then
		is_nvme=$(echo $image_disk | grep nvme)
		boot_part=
		if [ ! -z "$is_nvme" ]; then
			boot_part="$image_disk"p1
		else
			boot_part="$image_disk"1
		fi
		if [ ! -b "$boot_part" ]; then
			echo "Boot partition $boot_part not found or is not a block device" | tee $log_output
			return 0
		fi
		mount "$boot_part" /mnt/boot
		grub_cfg=
		if [ -f "/mnt/boot/grub/grub.cfg" ]; then
			grub_cfg="/mnt/boot/grub/grub.cfg"
		elif [ -f "/mnt/boot/grub.cfg" ]; then
			grub_cfg="/mnt/boot/grub.cfg"
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
	if [ ! -z "$efi_dev" ]; then
		mount $efi_dev /mnt/boot/efi 2>&1 | tee $log_output
	else
		chroot /mnt /bin/sh -c 'mount /boot/efi' 2>&1 | tee $log_output
	fi
	chroot /mnt /bin/sh -c update-grub 2>&1 | tee $log_output
	umount /mnt/boot/efi 2>&1 | tee $log_output
	umount /mnt/sys
	umount /mnt/proc
	umount /mnt/dev
	if [[ $(grep '\/mnt\/boot' /proc/mounts) ]]; then
		umount /mnt/boot
	fi
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
			if [[ "$tmp" =~ GRUB_CMDLINE_LINUX ]]; then
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
						echo -n "console=$serial_port" >> $new_grub_template
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
		echo "GRUB_CMDLINE_LINUX=\"console=tty0 console=$serial_port\"" >> $new_grub_template
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
		line=$(echo $i|grep 'rootfs_uuid')
		if [ ! -z "$line" ]; then
			rootfs_uuid=$(echo $line|cut -d'=' -f2)
		fi
	done

	if [ ! -z "$distro_name" ]; then
		get_distro_image
	fi

	if [ -z "$image_url" ]; then
		echo "Could not resolve disk image to use from arguments in /proc/cmdline" | tee $log_output
		return 1;
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

	echo Fix | parted ---pretend-input-tty $image_disk print
	partprobe $image_disk 2>&1 | tee $log_output
	if [ ! -z "$rootfs_uuid" -o ! -z "$rootfs_label" ]; then
		# find the root partition/volume
		get_root_dev
		if [ -b "$root_dev" ]; then
			mount "$root_dev" /mnt 2>&1 | tee $log_output
			modify_grub_template
			modify_grub_cfg
			if [ ! -z "$cloud_init_url" ]; then
				add_cloud_init
			fi
			umount /mnt 2>&1 | tee $log_output
			expand_root_fs
		fi
	fi
}

main
echo "Rebooting" | tee $log_output
systemctl reboot | tee $log_output
