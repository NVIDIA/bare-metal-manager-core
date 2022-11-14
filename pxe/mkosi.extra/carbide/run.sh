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

exec /carbide/carbide-cli --api=$server_uri $cli_cmd --uuid=$machine_id
