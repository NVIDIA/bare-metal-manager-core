FROM golang:1.18
RUN go install sigs.k8s.io/controller-tools/cmd/controller-gen@v0.9.0
ENTRYPOINT ["/go/bin/controller-gen"]
