FROM golang:1.16
RUN go install sigs.k8s.io/controller-tools/cmd/controller-gen@v0.4.1
ENTRYPOINT ["/go/bin/controller-gen"]
