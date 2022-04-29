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
done

exec /carbide/carbide-cli --listen=$server_uri discovery --uuid=$machine_id
