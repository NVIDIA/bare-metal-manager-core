FROM rust:latest

RUN apt update
RUN apt -y install apt-transport-https ca-certificates curl gnupg2 software-properties-common
RUN curl -fsSL https://download.docker.com/linux/debian/gpg | apt-key add -
RUN add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/debian $(lsb_release -cs) stable"

RUN apt update && apt install -y curl && apt -y install docker-ce

RUN curl -LO https://storage.googleapis.com/kubernetes-release/release/v1.13.5/bin/linux/amd64/kubectl
RUN chmod +x ./kubectl
RUN mv ./kubectl /usr/local/bin/kubectl

RUN curl -SsL https://get.helm.sh/helm-v2.16.9-linux-amd64.tar.gz | tar -xz
RUN mv linux-amd64/helm /usr/bin/helm && chmod 755 /usr/bin/helm

RUN curl -Lo skaffold https://storage.googleapis.com/skaffold/releases/v1.16.0/skaffold-linux-amd64
RUN install skaffold /usr/local/bin/

RUN curl -o /usr/local/bin/nvinit-0.4.1 https://gitlab-master.nvidia.com/svcngcc/nvinit-public-mirror/raw/v0.4.1/nvinit-0.4.1-linux-amd64
RUN chmod 755 /usr/local/bin/nvinit-0.4.1

RUN adduser --disabled-password --gecos "" --uid 26576 --gid 30 --shell /bin/bash svcngcc && \
    echo 'svcngcc ALL=NOPASSWD: ALL' >> /etc/sudoers
USER svcngcc
WORKDIR /home/svcngcc/
