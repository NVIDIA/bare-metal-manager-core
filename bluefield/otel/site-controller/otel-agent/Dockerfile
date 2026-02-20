FROM arm64v8/ubuntu:22.04

# Bump this to build an updated agent on the DPU
LABEL otel.agent.version="1"

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY otel-agent /app/otel-agent

ENTRYPOINT ["/app/otel-agent"]
