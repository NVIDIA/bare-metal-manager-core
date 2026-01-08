#!/usr/bin/env sh
for i in `cat /proc/cmdline`
do
        line=`echo $i|grep machine_id`
        if [ ! -z "$line" ] ;
        then
                machine_id=`echo $line|cut -d'=' -f2`
        fi
        line=`echo $i|grep server_uri`
        if [ ! -z "$line" ] ;
        then
                server_uri=`echo $line|cut -d'=' -f2`
        fi
        line=`echo $i|grep cli_cmd`
        if [ ! -z "$line" ] ;
        then
                cli_cmd=`echo $line|cut -d'=' -f2`
        fi
done
rm "/opt/forge/forge-scout.env"
cat "/opt/forge/forge-scout.env.template" > "/opt/forge/forge-scout.env"
echo server_uri=$server_uri >> "/opt/forge/forge-scout.env"
echo machine_id=$machine_id >> "/opt/forge/forge-scout.env"
echo cli_cmd=$cli_cmd >> "/opt/forge/forge-scout.env"

curl --retry 5 --retry-all-errors -v -o /opt/forge/forge_root.pem http://carbide-pxe.forge/api/v0/tls/root_ca

mkdir -p ~/.ssh

if [ ! -f ~/.ssh/privatekey.pem ]; then
	ssh-keygen -t rsa -b 4096 -f ~/.ssh/privatekey.pem -q -N ""
	ssh-keyscan -p "22" 127.0.0.1 > ~/.ssh/known_hosts
	cat ~/.ssh/privatekey.pem.pub >> ~/.ssh/authorized_keys
fi

rmmod mlx5_ib || true
udevadm settle
modprobe mlx5_ib || true
udevadm settle
