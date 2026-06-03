{{/*
Allow the release namespace to be overridden for multi-namespace deployments.
*/}}
{{- define "nico-dhcp.namespace" -}}
{{- default .Release.Namespace .Values.namespaceOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Expand the name of the chart.
*/}}
{{- define "nico-dhcp.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "nico-dhcp.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "nico-dhcp.labels" -}}
helm.sh/chart: {{ include "nico-dhcp.chart" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: site-controller
app.kubernetes.io/name: {{ include "nico-dhcp.name" . }}
app.kubernetes.io/component: dhcp
{{- end }}

{{/*
Selector labels
*/}}
{{- define "nico-dhcp.selectorLabels" -}}
app.kubernetes.io/name: {{ include "nico-dhcp.name" . }}
app.kubernetes.io/component: dhcp
{{- end }}

{{/*
Global image reference
*/}}
{{- define "nico-dhcp.image" -}}
{{ .Values.global.image.repository }}:{{ .Values.global.image.tag }}
{{- end }}

{{/*
Certificate spec
*/}}
{{- define "nico-dhcp.certificateSpec" -}}
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
secretName: {{ .name }}
{{- end }}

{{/*
Resolve the API service name with a safe fallback. Both the structured
keaConfigJson helper and the raw escape-hatch substitution route through
this so an explicit-null / empty `.Values.apiServiceName` falls back to
`nico-api` instead of producing a malformed hostname like
`https://.<ns>.svc.cluster.local`. Override via `.Values.apiServiceName`
under the dual-deployment scheme (PR #2062 — e.g. set to `carbide-api`).
*/}}
{{- define "nico-dhcp.apiServiceName" -}}
{{- .Values.apiServiceName | default "nico-api" -}}
{{- end }}

{{/*
Assemble kea_config.json from the structured config.kea block in values.
Fields are renamed from camelCase YAML to the hyphenated keys kea-dhcp4
expects. nicoApiUrl defaults to the in-cluster API service when left
empty — built from `nico-dhcp.apiServiceName` (which honours
`.Values.apiServiceName`) so the dual-deployment scheme flows through
here without operators needing to override hookParameters.nicoApiUrl.
nameservers / ntpServer / provisioningServer are passed through
verbatim — operators provide the real IPs via the umbrella
helm-prereqs/values/nico-core.yaml.

Robustness contract — every value the helper interpolates into JSON
runs through `toJson` (numbers, bools, lists, structures) or `quote`
(strings) so a partial override that nils a field fails CLOSED at
template-render time rather than producing `<no value>` in the config
and crashlooping kea at startup. Scalar string fields likewise default
to the chart placeholder so a `null` override doesn't leak into the
DHCP advertisement.

Note on toJson use: any field that is a free-form structure (subnets,
pools, lease database backend) is serialised with toJson so future
additions to those shapes don't require further template edits. Scalar
fields with hyphenated JSON keys are emitted explicitly so the template
controls the YAML→JSON name mapping.
*/}}
{{- define "nico-dhcp.keaConfigJson" -}}
{{- $ns := include "nico-dhcp.namespace" . -}}
{{- $apiSvc := include "nico-dhcp.apiServiceName" . -}}
{{- $k := .Values.config.kea -}}
{{/* Nil-safe access: `hookParameters: null` from an overlay shouldn't panic. */}}
{{- $hp := default (dict) $k.hookParameters -}}
{{- $apiUrl := default "" $hp.nicoApiUrl -}}
{{- if not $apiUrl -}}
{{- $apiUrl = printf "https://%s.%s.svc.cluster.local:1079" $apiSvc $ns -}}
{{- end -}}
{{- $libPath := default "/usr/lib/x86_64-linux-gnu/kea/hooks/libdhcp.so" $k.hookLibraryPath -}}
{{- $extraHooks := default (list) $k.additionalHooksLibraries -}}
{{- $ic := default (dict) $k.interfacesConfig -}}
{{- $interfaces := default (list "eth0") $ic.interfaces -}}
{{- $socketType := default "udp" $ic.dhcpSocketType -}}
{{- $ld := default (dict) $k.leaseDatabase -}}
{{- $subnets := default (list) $k.subnet4 -}}
{{- $loggers := default (list) $k.loggers -}}
{
  "Dhcp4": {
    "interfaces-config": {
      "interfaces": {{ $interfaces | toJson }},
      "dhcp-socket-type": {{ $socketType | quote }}
    },
    "lease-database": {
      "type": {{ default "memfile" $ld.type | quote }},
      "lfc-interval": {{ default 3600 $ld.lfcInterval | toJson }}
    },
    "match-client-id": {{ default false $k.matchClientId | toJson }},
    "authoritative": {{ default true $k.authoritative | toJson }},
    "renew-timer": {{ default 900 $k.renewTimer | toJson }},
    "rebind-timer": {{ default 1800 $k.rebindTimer | toJson }},
    "valid-lifetime": {{ default 3600 $k.validLifetime | toJson }},
    "hooks-libraries": [
      {
        "library": {{ $libPath | quote }},
        "parameters": {
          "nico-api-url": {{ $apiUrl | quote }},
          "nico-metrics-endpoint": {{ default "[::]:1089" $hp.nicoMetricsEndpoint | quote }},
          "nico-nameservers": {{ default "127.0.0.1" $hp.nameservers | quote }},
          "nico-ntpserver": {{ default "127.0.0.1" $hp.ntpServer | quote }},
          "nico-provisioning-server-ipv4": {{ default "127.0.0.1" $hp.provisioningServer | quote }}
        }
      }
{{- range $i, $extra := $extraHooks }},
      {{ $extra | toJson }}
{{- end }}
    ],
    "subnet4": [
{{- range $i, $s := $subnets }}
{{- if $i }},{{ end }}
      {
        "subnet": {{ $s.subnet | quote }},
        "pools": [
{{- range $j, $p := default (list) $s.pools }}
{{- if $j }},{{ end }}
{{- if kindIs "string" $p }}
          { "pool": {{ $p | quote }} }
{{- else if kindIs "map" $p }}
          {{ $p | toJson }}
{{- else }}
{{- fail (printf "nico-dhcp: config.kea.subnet4[%d].pools[%d] must be a pool-range string (e.g. \"0.0.0.0-255.255.255.255\") or a kea pool object; got %s" $i $j (kindOf $p)) }}
{{- end }}
{{- end }}
        ]
      }
{{- end }}
    ],
    "loggers": [
{{- range $i, $l := $loggers }}
{{- if $i }},{{ end }}
      {
        "name": {{ $l.name | quote }},
        "severity": {{ default "INFO" $l.severity | quote }},
        "output_options": {{ default (list (dict "output" "stdout")) $l.outputOptions | toJson }}
      }
{{- end }}
    ]
  }
}
{{- end -}}

{{/*
Service monitor spec
*/}}
{{- define "nico-dhcp.serviceMonitorSpec" -}}
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
