#!/usr/bin/env sh
forge_opt_dir="/opt/forge"
forge_log_dir="/var/log/forge"

forge_ca_root=$forge_opt_dir/forge_root.pem
forge_scout=$forge_opt_dir/forge-scout
forge_log=$forge_log_dir/forge-scout.log
mkdir -p $forge_log_dir

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
        line=`echo $i|grep forge_root_ca_uri`
        if [ ! -z "$line" ] ;
        then
                forge_root_ca_uri=`echo $line|cut -d'=' -f2`
        fi
done

curl --retry 5 --retry-all-errors -v -o $forge_ca_root $forge_root_ca_uri
exec $forge_scout --api=$server_uri $cli_cmd --uuid=$machine_id 2>&1 | tee $forge_log
