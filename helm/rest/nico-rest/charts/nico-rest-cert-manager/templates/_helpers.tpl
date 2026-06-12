{{- define "nico-rest-cert-manager.namespace" -}}
{{- default .Release.Namespace .Values.namespaceOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "nico-rest-cert-manager.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "nico-rest-cert-manager.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "nico-rest-cert-manager.labels" -}}
helm.sh/chart: {{ include "nico-rest-cert-manager.chart" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: nico-rest
app.kubernetes.io/name: nico-rest-cert-manager
app.kubernetes.io/component: cert-manager
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "nico-rest-cert-manager.selectorLabels" -}}
app: nico-rest-cert-manager
app.kubernetes.io/name: nico-rest-cert-manager
app.kubernetes.io/component: cert-manager
{{- end }}

{{- define "nico-rest-cert-manager.image" -}}
{{ .Values.global.image.repository }}/{{ .Values.image.name }}:{{ .Values.global.image.tag }}
{{- end }}
