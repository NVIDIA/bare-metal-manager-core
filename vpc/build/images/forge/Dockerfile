# Build the manager binary
FROM golang:1.16 as builder

WORKDIR /workspace
# Copy the Go Modules manifests
COPY go.mod go.mod
COPY go.sum go.sum
# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
RUN go mod download

# Copy the go source
COPY apis/ apis/
COPY controllers/ controllers/
COPY pkg pkg/
COPY rpc/ rpc/
COPY cmd/ cmd/
COPY config/forge.yaml .

# Build
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o manager cmd/controller/main.go
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o grpc-server cmd/rpc/main.go
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o agent cmd/agent/main.go

# Use distroless as minimal base image to package the manager binary
# Refer to https://github.com/GoogleContainerTools/distroless for more details
# FROM gcr.io/distroless/static:nonroot
FROM quay.io/nvidia/nvmetal-hydrazine-ovn:v21.06
RUN groupadd -r -g 65532 forge && useradd --no-log-init -r -u 65532 -g 65532 forge
RUN apt-get update && apt-get install -y curl isc-dhcp-relay
RUN curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
RUN chmod +x kubectl
# end ubuntu

WORKDIR /
COPY --from=builder /workspace/manager .
COPY --from=builder /workspace/grpc-server .
COPY --from=builder /workspace/agent .
COPY --from=builder /workspace/forge.yaml .
COPY build/images/ovn/scripts/*.sh /

USER 65532:65532

