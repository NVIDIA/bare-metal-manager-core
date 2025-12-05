# sbom

SBOM license attribution and Debian package management tool for distroless containers.


### Expected SBOM Format

The tool expects the `sourceInfo` field to contain copyright file paths:

```json
{
  "name": "libcurl4",
  "sourceInfo": "acquired package info from DPKG DB: /path/to/status, /path/to/copyright"
}
```

The tool extracts the path after the last comma as the copyright file location.

## Copyright File Format

The tool parses Debian-format copyright files that follow this structure:

```
License: MIT
 Permission is hereby granted, free of charge, to any person obtaining
 a copy of this software and associated documentation files...
 
License: Apache-2.0
 Licensed under the Apache License, Version 2.0...
```

Each license section:
- Starts with `License: <name>`
- Contains indented license text
- Ends when a non-indented line is encountered

## Output Format

The ATTRIBUTION.txt file contains deduplicated license texts:

```
LICENSE: curl
================================================================================
All rights reserved.

Permission is hereby granted, free of charge...

LICENSE: BSD-3-Clause
================================================================================
Redistribution and use in source and binary forms...
```

## deps.json Format

The `deps.json` file specifies runtime dependencies:

```json
{
    "runtime_dependencies": [
        "libcurl4",
        "libyaml-cpp0.7",
        "libldap-2.5-0"
    ],
}
```

Fields:
- `runtime_dependencies`: Debian packages needed at runtime (aliases: `debian_archives`)

## Docker Integration

### Complete Workflow Example

This shows all commands working together to create a compliant distroless container:

```dockerfile
# Application build with dependencies
FROM debian:bookworm AS builder

# Install sbom and syft tools
COPY --from=nvcr.io/nvidian/nvforge/sbom-tools:latest /app/sbom /usr/local/bin/sbom
COPY --from=anchore/syft:latest /syft /usr/local/bin/syft

# Optionally Build your application
WORKDIR /build
RUN ./configure && make && make install DESTDIR=/rootfs

# Copy deps.json configuration
COPY deps.json /build/deps.json

# Step 1: Install packages to /distroless
RUN sbom install-packages -f /build/deps.json

# Step 2: Download source packages for compliance
RUN sbom download-sources -f /build/deps.json -o /distroless/src

# Step 3: Copy package files to distroless structure (excludes base packages)
RUN sbom copy-files -f /build/deps.json -d /distroless

# Step 4: Assemble staging directory that mirrors final runtime filesystem
RUN sbom stage \
  --rootfs /rootfs \
  --app-dir /app \
  --distroless-dir /distroless \
  --include /build/myapp-1.0.tar.gz:app/packages/myapp-1.0.tar.gz \
  --include /var/lib/dpkg/status.d/myapp:var/lib/dpkg/status.d/myapp \
  --include /var/log/sbom/sbom.log:app/install.log \
  --syft-config /build/.syft.yaml \
  -o /sbom-staging

# Step 5: Generate SBOM from staging directory
RUN mkdir -p /sbom-staging/sbom && \
  syft scan dir:/sbom-staging \
  --output spdx-json=/sbom-staging/sbom/sbom-runtime.json \
  --config /sbom-staging/.syft.yaml

# Step 6: Generate license attribution from SBOM
RUN sbom attribution /sbom-staging/sbom/sbom-runtime.json \
  -o /sbom-staging/app/ATTRIBUTION.txt

# Final runtime image
FROM gcr.io/distroless/base-debian12:latest
WORKDIR /app

# Single COPY ensures final image matches EXACTLY what was scanned for SBOM
COPY --from=builder /sbom-staging /

CMD ["/app/your-binary"]
```
