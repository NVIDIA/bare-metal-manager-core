FROM golang:1.16


RUN echo "deb http://deb.debian.org/debian bullseye-backports main" >> /etc/apt/sources.list
RUN export DEBIAN_FRONTEND=noninteractive
RUN apt-get update
RUN apt install -y unzip gettext-base lsb-release software-properties-common
RUN curl -fsSL https://download.docker.com/linux/debian/gpg | apt-key add -
RUN add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/debian $(lsb_release -cs) stable"
RUN apt-get update
RUN apt install -y unzip gettext-base lsb-release
RUN apt -y install apt-transport-https ca-certificates curl gnupg2 software-properties-common
RUN apt-get install -y --no-install-recommends unzip curl openvswitch-switch ovn-common ovn-host ovn-central docker-ce
RUN curl -LO https://github.com/protocolbuffers/protobuf/releases/download/v3.12.4/protoc-3.12.4-linux-x86_64.zip
RUN unzip protoc-3.12.4-linux-x86_64.zip -d /usr
RUN go install github.com/golang/mock/mockgen@v1.6.0
RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.28
RUN go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.2
RUN export PATH="$PATH:$(go env GOPATH)/bin"
RUN curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
RUN chmod +x kubectl


