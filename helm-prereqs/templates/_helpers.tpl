{{/*
Generate an ed25519 SSH host private key (PKCS8 PEM format).
Reuses the existing secret on helm upgrade (idempotent).
No Job required — avoids network dependency for apk.
*/}}
{{- define "prereqs.sshPrivateKey" -}}
{{- $existing := (lookup "v1" "Secret" .Values.namespace "ssh-host-key") -}}
{{- if $existing -}}
  {{- index $existing.data "ssh_host_ed25519_key" | b64dec -}}
{{- else -}}
  {{- genPrivateKey "ed25519" -}}
{{- end -}}
{{- end -}}
