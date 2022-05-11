FROM ubuntu:20.04 as build

ARG OVS_VERSION="2.16.0"
ARG OVN_VERSION="21.06.0"


# Install dependencies for building OVS deb packages
# We only install python3 packages and we only support building OVS >= 2.13.0.
RUN apt-get update && \
    DEBIAN_FRONTEND="noninteractive" apt-get install -y --no-install-recommends wget curl git ca-certificates build-essential fakeroot graphviz \
            bzip2 autoconf automake debhelper dh-python dh-autoreconf libssl-dev libtool openssl procps \
            python3-all python3-twisted python3-zope.interface python3-sphinx \
            libunbound-dev

# Download OVS source code and build debs
RUN wget -q -O - https://www.openvswitch.org/releases/openvswitch-$OVS_VERSION.tar.gz  | tar xz -C /tmp && \
    cd /tmp/openvswitch* && \
    DEB_BUILD_OPTIONS='parallel=8 nocheck' fakeroot debian/rules binary && \
    cd /tmp && mkdir debs && \
    mv libopenvswitch_*.deb openvswitch-common_*.deb openvswitch-switch_*.deb python*-openvswitch_*.deb \
       openvswitch-ipsec_*.deb debs/ && \
    (dpkg -i /tmp/debs/*.deb || apt-get -f -y --no-install-recommends install)

RUN wget -q -O - https://github.com/ovn-org/ovn/archive/refs/tags/v$OVN_VERSION.tar.gz | tar xz -C /tmp && \
    cd /tmp/ovn-$OVN_VERSION && \
    DEB_BUILD_OPTIONS='parallel=8 nocheck' OVSDIR=/tmp/openvswitch-$OVS_VERSION fakeroot debian/rules binary && \
    cd /tmp && \
    mv ovn-central_*.deb ovn-common_*.deb ovn-host_*.deb ovn-controller-vtep_*.deb debs/ && \
    ls /tmp/debs

FROM ubuntu:20.04

LABEL maintainer="suw@nvidia.com"
LABEL description="A Docker image containing ovn and ovs built from source."

COPY --from=build /tmp/debs/* /tmp/debs/

# Install OVS debs, iptables, logrotate, and strongSwan; update the OVS
# logrotate config file; update the strongSwan logging config.
# We clean-up apt cache after installing packages to reduce the size of the
# final image.
RUN apt-get update && \
    apt-get install -y --no-install-recommends iptables logrotate && \
    (dpkg -i /tmp/debs/*.deb || apt-get -f -y --no-install-recommends install) && \
    rm -rf /var/cache/apt/* /var/lib/apt/lists/* && \
    sed -i "/rotate /a\    #size 100M" /etc/logrotate.d/openvswitch-switch && \
    rm -rf /tmp/*
RUN ovs-vsctl --version && ovs-ofctl --version
RUN ovn-nbctl --version && ovn-sbctl --version
