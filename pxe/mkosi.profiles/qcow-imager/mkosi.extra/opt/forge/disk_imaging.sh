#!/bin/bash
file=
root_partition=

function curl_url() {
	url=$1
	auth=$2
	file=$(basename $url)
	curl -k -L $auth $url --output $file
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
		echo "Unknown sha digest length"
		exit 1;
	fi
	echo "$sha $file" | $shasum --check
}

function find_bootdisk() {
	if [ -b /dev/nvme0n1 ]; then
		image_disk="/dev/nvme0n1"
	elif [ -b /dev/sda ]; then
		image_disk="/dev/sda"
	else
		echo "Boot drive not detected or specified"
		exit 1;
	fi
}

function get_distro_image() {
	arch=$(uname -m)
	if [ "$distro" == "ubuntu" ]; then
		if [ "$arch" == "x86_64" ]; then
			arch=amd64
		fi
		if [ "$version" == "23.04" ]; then
			codename=lunar
		elif [ "$version" == "22.10" ]; then
			codename=kinetic
		elif [ "$version" == "22.04" ]; then
			codename=jammy
		elif [ "$version" == "21.10" ]; then
			codename=impish
		elif [ "$version" == "21.04" ]; then
			codename=hirsute
		elif [ "$version" == "20.10" ]; then
			codename=groovy
		elif [ "$version" == "20.04" ]; then
			codename=focal
		else
			echo "Ubuntu version $version not supported"
			exit 1;
		fi
		image_url=https://cloud-images.ubuntu.com/releases/$codename/release/ubuntu-$version-server-cloudimg-$arch.img
		shaurl=https://cloud-images.ubuntu.com/releases/$codename/release/SHA256SUMS
	elif [ "$distro" == "debian" ]; then
		if [ "$arch" == "x86_64" ]; then
			arch=amd64
		fi
		if [ "$version" == "10" ]; then
			codename=buster
		elif [ "$version" == "11" ]; then
			codename=bullseye
		elif [ "$version" == "12" ]; then
			codename=bookworm
		elif [ "$version" == "sid" ]; then
			codename=sid
		else
			echo "Debian version $version not supported"
			exit 1;
		fi
		image_url=http://cdimage.debian.org/cdimage/cloud/$codename/daily/latest/debian-$version-generic-$arch-daily.qcow2
		shaurl=http://cdimage.debian.org/cdimage/cloud/$codename/daily/latest/SHA512SUMS
	elif [ "$distro" == "centos" ]; then
		image_url=https://cloud.centos.org/centos/$version-stream/$arch/images/CentOS-Stream-GenericCloud-$version-latest.$arch.qcow2
		shaurl=https://cloud.centos.org/centos/$version-stream/$arch/images/CentOS-Stream-GenericCloud-$version-latest.$arch.SHA256SUM
	else
		echo "Distro $distro not supported"
		exit 1;
	fi
	curl -k -L $shaurl --output shafile
	file=$(basename $image_url)
	image_sha=$(grep -m 1 $file shafile)
}

function add_cloud_init() {
	echo "fetching from cloud-init url: $cloud_init_url"
	if [ -b "$root_partition" ]; then
		mount $root_partition /mnt
		if [ -d /mnt/etc/cloud/cloud.cfg.d ]; then
			curl -k "$cloud_init_url/user-data" --output /mnt/etc/cloud/cloud.cfg.d/user-data.cfg
		fi
		umount /mnt
	fi
}

function expand_root_fs() {
	if [ -b "$root_partition" ]; then
		is_nvme=$(echo $root_partition | grep nvme)
		if [ ! -z "$is_nvme" ]; then
			part_num=$(echo $root_partition | cut -d'p' -f2)
			growpart $image_disk $part_num
			resize2fs -fF $root_partition
		fi
	fi
}

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
	echo $line
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
		distro=$(echo $line|cut -d'=' -f2|tr '[:upper:]' '[:lower:]')
	fi
	line=$(echo $i|grep image_distro_version)
	if [ ! -z "$line" ]; then
		version=$(echo $line|cut -d'=' -f2)
	fi
	line=$(echo $i|grep image_distro_release)
	if [ ! -z "$line" ]; then
		release=$(echo $line|cut -d'=' -f2)
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

if [ ! -z "$distro" ]; then
	get_distro_image
fi

if [ -z "$image_url" ]; then
	echo "Could not resolve disk image to use from arguments in /proc/cmdline"
	exit 1;
fi

if [ ! -z "$image_auth_token" ]; then
	if [ -z "$image_auth_type" ]; then
	       image_auth_type=Bearer
	fi
	image_auth="-H \"Authorization: $image_auth_type $image_auth_token\""
fi

echo "Downloading image from $image_url"
curl_url $image_url $image_auth
if [ ! -z "$image_sha" ]; then
	echo "Verifying image with digest $image_sha"
	verify_sha $image_sha
	if [ $? -ne 0 ]; then
		echo "Image checksum validation failed"
		exit 1;
	fi
fi
if [ -z "$image_disk" ]; then
	find_bootdisk
fi

echo "Imaging $file to $image_disk"
qemu-img convert -p -O raw $file $image_disk
ret=$?
if [ $ret -ne 0 ]; then
	exit $ret;
fi

echo Fix | parted ---pretend-input-tty $image_disk print

if [ ! -z "$rootfs_uuid" ]; then
	# find the root partition
	root_partition=$(blkid -U $rootfs_uuid)
	if [ ! -z "$cloud_init_url" ]; then
		add_cloud_init
	fi
	expand_root_fs
fi

echo "Rebooting"
systemctl reboot
