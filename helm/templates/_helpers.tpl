{{/*
Create the chart name and version as used by the chart label.
*/}}
{{- define "nico.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a release-scoped name for the packaged Grafana dashboards.
*/}}
{{- define "nico.grafanaDashboardsName" -}}
{{- printf "%s-grafana-dashboards" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Labels for the Grafana dashboard ConfigMap. User-provided global and dashboard
labels override the chart defaults, in that order.
*/}}
{{- define "nico.grafanaDashboardLabels" -}}
{{- $labels := dict
  "helm.sh/chart" (include "nico.chart" .)
  "app.kubernetes.io/name" .Chart.Name
  "app.kubernetes.io/instance" .Release.Name
  "app.kubernetes.io/component" "observability"
  "app.kubernetes.io/managed-by" .Release.Service
-}}
{{- with .Values.global.labels }}
{{- $labels = mergeOverwrite $labels . }}
{{- end }}
{{- with .Values.grafanaDashboards.labels }}
{{- $labels = mergeOverwrite $labels . }}
{{- end }}
{{- toYaml $labels -}}
{{- end -}}
