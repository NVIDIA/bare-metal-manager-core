# Structured log inventory

1 production Rust file, 6 fields, 1 message, 0 unsupported sites, 0 findings.

## Fields

| Source key | Rendered key | Count | Surfaces | Metric label | Formats | Known contract |
|---|---|---:|---|---|---|---|
| error | error | 1 | instrumented_event_log | no | display | Error: Normalize incidental bindings such as e and err to error. instrumented_event_log: Allowed. |
| http.url | http_url | 1 | plain_tracing_event | no | display | ExternalSemanticConvention: OpenTelemetry HTTP URL. plain_tracing_event: Unspecified. |
| machine_id | machine_id | 2 | plain_tracing_event, span | no | display | Identifier family: Derive the default key from the concrete identifier type. |
| stage | stage | 2 | instrumented_event_log, metric_label | yes | display |  |

## Messages

| Macro | Kind | Count | Text |
|---|---|---:|---|
| info | static | 1 | request received |

## Findings

| Location | Surface | Rule | Subject | Enforcement |
|---|---|---|---|---|

## Unsupported syntax

| Location | Surface | Detail |
|---|---|---|
