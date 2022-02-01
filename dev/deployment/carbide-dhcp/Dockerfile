FROM carbide:latest as carbide-dhcp
COPY dev/deployment/carbide-dhcp/kea-dhcp4-carbide.conf /etc/kea/kea-dhcp4-carbide.conf
CMD ["/usr/sbin/kea-dhcp4", "-c", "/etc/kea/kea-dhcp4-carbide.conf"]
EXPOSE 67

