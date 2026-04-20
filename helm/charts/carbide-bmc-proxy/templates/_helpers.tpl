{{/*
Allow the release namespace to be overridden for multi-namespace deployments.
*/}}
{{- define "carbide-bmc-proxy.namespace" -}}
{{- default .Release.Namespace .Values.namespaceOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "carbide-bmc-proxy.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
What image to use: Use subchart-local image if defined, fall back on global
image. In devspace deployments, carbide-bmc-proxy gets its own image. In other
deployments, the main carbide image contains all binaries, so we can use that.
*/}}
{{- define "carbide-bmc-proxy.image" -}}
{{- if not (eq (toString (.Values.image.repository | default "")) "") }}
{{- .Values.image.repository }}:{{ .Values.image.tag | default "latest" }}
{{- else }}
{{- .Values.global.image.repository }}:{{ .Values.global.image.tag }}
{{- end }}
{{- end }}

{{- define "carbide-bmc-proxy.labels" -}}
helm.sh/chart: {{ include "carbide-bmc-proxy.chart" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: site-controller
app.kubernetes.io/name: carbide-bmc-proxy
app.kubernetes.io/component: bmc-proxy
{{- end }}

{{- define "carbide-bmc-proxy.selectorLabels" -}}
app.kubernetes.io/name: carbide-bmc-proxy
app.kubernetes.io/component: bmc-proxy
{{- end }}

{{- define "carbide-bmc-proxy.certificateSpec" -}}
duration: {{ .global.certificate.duration }}
renewBefore: {{ .global.certificate.renewBefore }}
commonName: {{ printf "%s.%s.svc.cluster.local" .cert.serviceName .namespace }}
dnsNames:
  - {{ printf "%s.%s.svc.cluster.local" .cert.serviceName .namespace }}
{{- if not (eq (toString (.cert.includeShortDnsName | default true)) "false") }}
  - {{ printf "%s.%s" .cert.serviceName .namespace }}
{{- end }}
{{- range .cert.extraDnsNames | default list }}
  - {{ . }}
{{- end }}
uris:
  - {{ printf "spiffe://%s/%s/sa/%s" .global.spiffe.trustDomain .namespace .cert.serviceName }}
{{- range .cert.extraUris | default list }}
  - {{ . }}
{{- end }}
privateKey:
  algorithm: {{ .global.certificate.privateKey.algorithm }}
  size: {{ .global.certificate.privateKey.size }}
issuerRef:
  kind: {{ .global.certificate.issuerRef.kind }}
  name: {{ .global.certificate.issuerRef.name }}
  group: {{ .global.certificate.issuerRef.group }}
secretName: {{ .name }}
{{- end }}

{{- define "carbide-bmc-proxy.serviceMonitorSpec" -}}
endpoints:
  - honorLabels: false
    interval: {{ .monitor.interval }}
    port: {{ .port }}
    scheme: http
    scrapeTimeout: {{ .monitor.scrapeTimeout }}
namespaceSelector:
  matchNames:
    - {{ .namespace }}
selector:
  matchLabels:
    app.kubernetes.io/metrics: {{ .name }}
{{- end }}
