FROM golang:1.16

RUN apt update && apt install -y unzip && rm -rf /var/lib/apt/lists/*
RUN curl -LO https://github.com/protocolbuffers/protobuf/releases/download/v3.12.4/protoc-3.12.4-linux-x86_64.zip
RUN unzip protoc-3.12.4-linux-x86_64.zip -d /usr
RUN chmod og+x /usr/bin/protoc
RUN chmod og+r -R /usr/include/google/
RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.28
RUN go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.2

ENTRYPOINT ["/usr/bin/protoc"]

# Refer to https://github.com/GoogleContainerTools/distroless for more details
##FROM gcr.io/distroless/static:nonroot
##COPY --from=builder /usr/bin/protoc /
##USER nonroot:nonroot
##CMD ["/protoc"]


