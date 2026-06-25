-- Trusted NVIDIA BlueField device root CA certificates. A DPU's IRoT
-- device-identity certificate chain (fetched from the DPU BMC over SPDM/Redfish)
-- is validated against these. Expected to be populated at site creation, like
-- tpm_ca_certs.
CREATE TABLE dpu_device_ca_certs(
    id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    not_valid_before TIMESTAMPTZ NOT NULL,
    not_valid_after TIMESTAMPTZ NOT NULL,
    ca_cert_der BYTEA NOT NULL,
    -- cert subject stored as DER to avoid parser-formatting differences,
    -- matching the tpm_ca_certs convention.
    cert_subject BYTEA NOT NULL,

    CONSTRAINT dpu_device_ca_certs_unique_ca_cert_der UNIQUE(ca_cert_der)
);

-- Records that a DPU's device-identity certificate was verified against a
-- trusted root and the machine_id it was bound to. One row per machine; the
-- machine_id is the device-rooted id when a verified cert was available.
CREATE TABLE dpu_device_cert_status(
    -- machine id assigned to the DPU
    machine_id text NOT NULL,
    -- sha256 of the verified leaf device certificate (DER)
    device_cert_sha256 BYTEA NOT NULL,
    -- device serial (leaf subject common name), for operator display
    device_serial text NOT NULL,
    -- the trusted root that signed the chain, when recorded
    ca_id INT,
    verified_at TIMESTAMPTZ NOT NULL,

    PRIMARY KEY(machine_id),
    FOREIGN KEY(ca_id) REFERENCES dpu_device_ca_certs(id)
);
