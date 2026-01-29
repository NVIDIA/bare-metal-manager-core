#!/usr/bin/env sh

for nic in $(ip --json -4 a | jq -r '.[] | select(.addr_info[].local | test("^169\\.254\\.")) | .ifname')
do
  ifconfig $nic 0.0.0.0 down
done

cat > "/opt/agent.config.env" <<EOF 
# Agent Information
AGENT_VERSION=28.1.90
AGENT_MOUNT_ON_PREM=true
ALLOW_SUDO=true
NODE_EXPORTER_VERSION=v1.6.1
NODE_EXPORTER_DISABLE=1
AGENT_IMAGE='shorelinesoftware/agent'
AGENT_IMAGE_TAG=release-\${AGENT_VERSION}-multiarch-lt
SSH_PORT=22
NODE_IP=127.0.0.1
POD_IP=127.0.0.1
HOSTNAME=127.0.0.1
AUTO_START=true
SSH_PORT=22
SSH_USERNAME=root
REFRESH_ENDPOINT_INTERVAL=86400000
EOF

mkdir -p /tmp/machine_validation/external_config
mkdir -p /opt/shorelineagent/shoreline
mkdir -p /opt/shorelineagent/databases
mkdir -p /opt/shorelineagent/onprem
mkdir -p /opt/shorelineagent/secrets
touch /opt/shorelineagent/scraper.yml

mkdir -p ~/.ssh

if [ ! -f ~/.ssh/privatekey.pem ]; then
	ssh-keygen -t rsa -b 4096 -f ~/.ssh/privatekey.pem -q -N ""
	ssh-keyscan -p "22" 127.0.0.1 > ~/.ssh/known_hosts
	cat ~/.ssh/privatekey.pem.pub >> ~/.ssh/authorized_keys
fi


for i in `cat /proc/cmdline`
do
        line=`echo $i | grep SECRET`
        if [ ! -z "$line" ] ;
        then
                SECRET=`echo $line | cut -d'=' -f2`
                echo "SECRET=$SECRET" >> /opt/agent.config.env
        fi


        line=`echo $i | grep BACKEND_ADDRESS`
        if [ ! -z "$line" ] ;
        then
                backend_address=`echo $line | cut -d'=' -f2`
                echo "BACKEND_ADDRESS=$backend_address" >> /opt/agent.config.env
        fi

        line=`echo $i | grep CUSTOMER_ID`
        if [ ! -z "$line" ] ;
        then
                customer_id=`echo $line | cut -d'=' -f2`
                echo "CUSTOMER_ID=$customer_id" >> /opt/agent.config.env
        fi

        use_nginx=false
        line=`echo $i | grep NGINX`
        if [ ! -z "$line" ] ;
        then
                use_nginx=`echo "$line" | cut -d'=' -f2`
        fi
done


# echo "$(curl -s http://169.254.169.254:7777/latest/meta-data/public-ipv4 | sed 's/\./-/g')" > /etc/hostip
ip --json -4 a | jq -r '.[] | select(.operstate == "UP") | .addr_info[] | select(.scope == "global") | .local' | head -n 1 | sed 's/\./-/g' > /etc/hostip
hostname $(cat /etc/hostip)

echo "HAMED- start"

echo "Downloading shoreline agent container from pxe server"
if [ "$use_nginx" = false ]; then
    curl http://carbide-pxe.forge/public/blobs/internal/x86_64/shoreline_agent.tar.gz -o /root/shoreline_agent.tar.gz
else
    curl http://carbide-static-pxe.forge/public/blobs/internal/x86_64/shoreline_agent.tar.gz -o /root/shoreline_agent.tar.gz
fi

rm -rf /root/shoreline_agent.tar
echo "Loading shoreline agent container into containerd"
gunzip /root/shoreline_agent.tar.gz
ctr images import /root/shoreline_agent.tar

ctr i ls 

ctr task kill -s 9 shoreline_agent
ctr container rm shoreline_agent

echo "Starting shoreline agent"

ctr run  \
                                --rm \
                                --privileged \
                                --no-pivot \
                                --net-host \
                                --env-file /opt/agent.config.env \
                                --mount type=bind,src=/,dst=/host,options=rbind:rw \
                                --mount type=bind,src=/opt/shorelineagent/databases,dst=/agent/databases,options=rbind:rw \
                                --mount type=bind,src=/opt/shorelineagent/onprem,dst=/agent/onprem,options=rbind:rw \
                                --mount type=bind,src=/opt/shorelineagent/secrets,dst=/agent/secrets,options=rbind:rw \
                                --mount type=bind,src=/opt/shorelineagent/scraper.yml,dst=/agent/etc/scraper.yml,options=rbind:rw \
                                --mount type=bind,src=/root/.ssh,dst=/agent/.host_ssh,options=rbind:ro \
                                --mount type=bind,src=/opt/shorelineagent/shoreline,dst=/agent/host-etc-shoreline,options=rbind:ro \
                                --memory-limit 524288000 \
                                --cpus 0.5 \
                                nvcr.io/nvidian/shoreline/agent:release-28.1.90-multiarch-lt shoreline_agent
echo "HAMED- installing torch"
