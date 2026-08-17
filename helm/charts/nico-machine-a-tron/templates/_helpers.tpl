{{/*
Effective namespace for chart resources.
Uses global.namespaceOverride if set, otherwise Release.Namespace.
*/}}
{{- define "nico-machine-a-tron.namespace" -}}
{{- if and .Values.global .Values.global.namespaceOverride -}}
{{- .Values.global.namespaceOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- .Release.Namespace -}}
{{- end -}}
{{- end -}}

{{/*
Resource name prefix. Defaults to the chart name; override with nameOverride.
*/}}
{{- define "nico-machine-a-tron.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "nico-machine-a-tron.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
What image to use: Use subchart-local image if defined, fall back on global
image. In devspace deployments, {{ include "nico-machine-a-tron.name" . }} gets its own image.
In other deployments, the main nico image contains all binaries.
*/}}
{{- define "nico-machine-a-tron.image" -}}
{{- if not (eq (toString (.Values.image.repository | default "")) "") }}
{{- .Values.image.repository }}:{{ .Values.image.tag | default "latest" }}
{{- else if and .Values.global.image (not (eq (toString (.Values.global.image.repository | default "")) "")) (not (eq (toString (.Values.global.image.tag | default "")) "")) }}
{{- .Values.global.image.repository }}:{{ .Values.global.image.tag }}
{{- else }}
{{- "nico:latest" }}
{{- end }}
{{- end }}

{{- define "nico-machine-a-tron.labels" -}}
helm.sh/chart: {{ include "nico-machine-a-tron.chart" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: site-controller
app.kubernetes.io/name: {{ include "nico-machine-a-tron.name" . }}
app.kubernetes.io/component: machine-a-tron
{{- end }}

{{- define "nico-machine-a-tron.selectorLabels" -}}
app.kubernetes.io/name: {{ include "nico-machine-a-tron.name" . }}
app.kubernetes.io/component: machine-a-tron
{{- end }}

{{/*
Return true when a pod has generated machine groups, generated racks, or a full config override.
*/}}
{{- define "nico-machine-a-tron.podIsActive" -}}
{{- $matConfigs := .root.Values.configFiles.matConfigs | default dict -}}
{{- $matConfig := index $matConfigs .podName -}}
{{- $podConfig := .podConfig | default dict -}}
{{- $machines := $podConfig.machines | default dict -}}
{{- $racks := $podConfig.racks | default dict -}}
{{- if or (gt (len $machines) 0) (gt (len $racks) 0) $matConfig -}}
true
{{- end -}}
{{- end }}

{{/*
Count active pods.
*/}}
{{- define "nico-machine-a-tron.activePods" -}}
{{- $activePods := 0 -}}
{{- $root := . -}}
{{- range $podName, $podConfig := .Values.pods -}}
{{- if include "nico-machine-a-tron.podIsActive" (dict "root" $root "podName" $podName "podConfig" $podConfig) -}}
{{- $activePods = add $activePods 1 -}}
{{- end -}}
{{- end -}}
{{- print $activePods -}}
{{- end }}

{{- define "nico-machine-a-tron.certificateSpec" -}}
duration: {{ .global.certificate.duration }}
renewBefore: {{ .global.certificate.renewBefore }}
commonName: {{ printf "%s.%s.svc.cluster.local" (.cert.serviceName | default .svcName) (.cert.identityNamespace | default .namespace) }}
dnsNames:
{{- if .cert.dnsNames }}
{{- range .cert.dnsNames }}
  - {{ . }}
{{- end }}
{{- else }}
  - {{ printf "%s.%s.svc.cluster.local" (.cert.serviceName | default .svcName) (.cert.identityNamespace | default .namespace) }}
{{- if ne (toString .cert.includeShortDnsName) "false" }}
  - {{ printf "%s.%s" (.cert.serviceName | default .svcName) (.cert.identityNamespace | default .namespace) }}
{{- end }}
{{- range .cert.extraDnsNames | default list }}
  - {{ . }}
{{- end }}
{{- end }}
uris:
{{- if .cert.uris }}
{{- range .cert.uris }}
  - {{ . }}
{{- end }}
{{- else }}
  - {{ printf "spiffe://%s/%s/sa/%s" .global.spiffe.trustDomain (.cert.identityNamespace | default .namespace) (.cert.spiffeServiceName | default .cert.serviceName | default .svcName) }}
{{- range .cert.extraUris | default list }}
  - {{ . }}
{{- end }}
{{- end }}
privateKey:
  algorithm: {{ .global.certificate.privateKey.algorithm }}
  size: {{ .global.certificate.privateKey.size }}
issuerRef:
  kind: {{ .global.certificate.issuerRef.kind }}
  name: {{ .global.certificate.issuerRef.name }}
  group: {{ .global.certificate.issuerRef.group }}
secretName: {{ .secretName | default .name }}
{{- end }}

{{- define "nico-machine-a-tron.serviceMonitorSpec" -}}
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
