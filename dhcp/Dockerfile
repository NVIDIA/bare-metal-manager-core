FROM carbide-runtime:latest

WORKDIR /app/code

# This is copying the examples instead of the dev/ resource that the base image contains
# Should this be removed altogether?
COPY examples/kea-dhcp4-carbide.conf /etc/kea/kea-dhcp4-carbide.conf

EXPOSE 1079
