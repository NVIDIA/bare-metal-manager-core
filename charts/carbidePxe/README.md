# carbidePxe

![Version: 0.0.16](https://img.shields.io/badge/Version-0.0.16-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) ![AppVersion: 0.0.1](https://img.shields.io/badge/AppVersion-0.0.1-informational?style=flat-square)

A Helm chart for Forge carbide-pxe component

## Requirements

| Repository | Name | Version |
|------------|------|---------|
| https://helm.ngc.nvidia.com/nvidian/forge | common | 2.2.1 |

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| bootArtifactsContainer.container.image.baseRepository | string | `"nvidian/forge/boot-artifacts"` |  |
| bootArtifactsContainer.container.image.pullPolicy | string | `"IfNotPresent"` |  |
| bootArtifactsContainer.container.image.registry | string | `"nvcr.io"` |  |
| bootArtifactsContainer.container.image.tag | string | `"latest"` |  |
| bootArtifactsContainer.enabled | bool | `false` | set to true to pull artifacts container. set to 'develop' to allow manually copy artifacts to container path. set to false to use hostPath |
| bootArtifactsHostPath | string | `"/srv/forge-boot-artifacts"` |  |
| carbideApiUrl | string | `"-"` | When set to "-" Helm will automatically attempt to determine the correct service name of carbide-api |
| carbidePxeUrl | string | `"-"` | When set to "-" Helm will automatically attempt to determine the correct service name of carbide-pxe |
| clusterDomain | string | `"cluster.local"` | Kubernetes cluster domain name |
| commonAnnotations | object | `{}` | Annotations to add to all deployed objects |
| commonLabels | object | `{}` | Labels to add to all deployed objects |
| container.affinity | object | `{}` |  |
| container.args[0] | string | `"-s"` |  |
| container.args[1] | string | `"/forge-boot-artifacts"` |  |
| container.autoscaling.enabled | bool | `false` | Autoscaling configuration ref: https://kubernetes.io/docs/tasks/run-application/horizontal-pod-autoscale/ |
| container.autoscaling.maxReplicas | string | `""` |  |
| container.autoscaling.minReplicas | string | `""` |  |
| container.autoscaling.targetCPU | string | `""` |  |
| container.autoscaling.targetMemory | string | `""` |  |
| container.command[0] | string | `"/opt/carbide/carbide"` |  |
| container.containerPorts.http | int | `8080` |  |
| container.containerPorts.https | int | `8443` |  |
| container.containerSecurityContext.enabled | bool | `false` | Configure Container Security Context ref: https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-the-security-context-for-a-container |
| container.containerSecurityContext.readOnlyRootFilesystem | bool | `false` |  |
| container.containerSecurityContext.runAsNonRoot | bool | `true` |  |
| container.containerSecurityContext.runAsUser | int | `1001` |  |
| container.customLivenessProbe | object | `{}` |  |
| container.customReadinessProbe | object | `{}` |  |
| container.customStartupProbe | object | `{}` |  |
| container.existingConfigmap | string | `nil` |  |
| container.extraEnvVars | list | `[]` |  |
| container.extraEnvVarsCM | string | `""` |  |
| container.extraEnvVarsSecret | string | `""` |  |
| container.extraVolumeMounts | list | `[]` |  |
| container.extraVolumes | list | `[]` |  |
| container.hostAliases | list | `[]` |  |
| container.image.debug | bool | `false` |  |
| container.image.digest | string | `""` |  |
| container.image.pullPolicy | string | `"IfNotPresent"` |  |
| container.image.pullSecrets[0] | string | `"imagepullsecret"` |  |
| container.image.registry | string | `"nvcr.io"` |  |
| container.image.repository | string | `"nvidian/forge/nvmetal-carbide"` |  |
| container.image.tag | string | `"latest"` |  |
| container.initContainers | list | `[]` |  |
| container.lifecycleHooks | object | `{}` |  |
| container.livenessProbe.enabled | bool | `true` | Configure extra options for carbide containers' liveness and readiness probes ref: https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-probes/#configure-probes |
| container.livenessProbe.failureThreshold | int | `3` |  |
| container.livenessProbe.initialDelaySeconds | int | `20` |  |
| container.livenessProbe.periodSeconds | int | `10` |  |
| container.livenessProbe.successThreshold | int | `1` |  |
| container.livenessProbe.tcpSocket.port | int | `8080` |  |
| container.livenessProbe.timeoutSeconds | int | `5` |  |
| container.nodeAffinityPreset.key | string | `""` |  |
| container.nodeAffinityPreset.type | string | `""` | Node carbidePxe.affinity preset ref: https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/#node-affinity |
| container.nodeAffinityPreset.values | list | `[]` |  |
| container.nodeSelector | object | `{}` |  |
| container.pdb.create | bool | `false` | Pod Disruption Budget configuration ref: https://kubernetes.io/docs/tasks/run-application/configure-pdb |
| container.pdb.maxUnavailable | string | `""` |  |
| container.pdb.minAvailable | int | `1` |  |
| container.podAffinityPreset | string | `""` |  |
| container.podAnnotations | object | `{}` |  |
| container.podAntiAffinityPreset | string | `"soft"` |  |
| container.podLabels | object | `{}` |  |
| container.podManagementPolicy | string | `"OrderedReady"` |  |
| container.podSecurityContext.enabled | bool | `false` | Configure Pods Security Context ref: https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-the-security-context-for-a-pod |
| container.podSecurityContext.fsGroup | int | `1001` |  |
| container.priorityClassName | string | `""` |  |
| container.readinessProbe.enabled | bool | `false` |  |
| container.readinessProbe.failureThreshold | int | `3` |  |
| container.readinessProbe.initialDelaySeconds | int | `30` |  |
| container.readinessProbe.periodSeconds | int | `5` |  |
| container.readinessProbe.successThreshold | int | `2` |  |
| container.readinessProbe.timeoutSeconds | int | `30` |  |
| container.replicaCount | int | `1` |  |
| container.resources.limits | object | `{}` | container resource requests and limits ref: http://kubernetes.io/docs/user-guide/compute-resources/ |
| container.resources.requests | object | `{}` |  |
| container.schedulerName | string | `""` |  |
| container.sidecars | list | `[]` |  |
| container.startupProbe.enabled | bool | `false` |  |
| container.startupProbe.failureThreshold | int | `2` |  |
| container.startupProbe.initialDelaySeconds | int | `30` |  |
| container.startupProbe.periodSeconds | int | `5` |  |
| container.startupProbe.successThreshold | int | `2` |  |
| container.startupProbe.timeoutSeconds | int | `30` |  |
| container.terminationGracePeriodSeconds | string | `""` |  |
| container.tolerations | list | `[]` |  |
| container.topologySpreadConstraints | list | `[]` |  |
| container.updateStrategy.type | string | `"RollingUpdate"` |  |
| diagnosticMode.args | list | `["infinity"]` | Args to override all containers in the deployment |
| diagnosticMode.command | list | `["sleep"]` | Command to override all containers in the deployment |
| diagnosticMode.enabled | bool | `false` | Enable diagnostic mode (all probes will be disabled and the command will be overridden) |
| extraDeploy | list | `[]` | Array of extra objects to deploy with the release |
| forgeRootCaFilePath | string | `"/run/secrets/spiffe.io/ca.crt"` | where the forge root CA is on disk |
| fullnameOverride | string | `"carbide-pxe"` | String to fully override common.names.fullname |
| global.imagePullSecrets | list | `[]` | Global Docker registry secret names as an array |
| global.imageRegistry | string | `""` | Global Docker image registry |
| global.storageClass | string | `""` | Global StorageClass for Persistent Volume(s) |
| ingress.annotations | object | `{}` | Additional annotations for the Ingress resource. To enable certificate autogeneration, place here your cert-manager annotations. Use this parameter to set the required annotations for cert-manager, see ref: https://cert-manager.io/docs/usage/ingress/#supported-annotations e.g: annotations:   kubernetes.io/ingress.class: nginx |
| ingress.apiVersion | string | `""` | Force Ingress API version (automatically detected if not set) |
| ingress.enabled | bool | `false` | Enable ingress record generation for carbide |
| ingress.extraHosts | list | `[]` | An array with additional hostname(s) to be covered with the ingress record e.g: extraHosts:   - name: carbide-pxe.local     path: / |
| ingress.extraPaths | list | `[]` | An array with additional arbitrary paths that may need to be added to the ingress under the main host e.g: extraPaths: - path: /*   backend:     serviceName: ssl-redirect     servicePort: use-annotation |
| ingress.extraRules | list | `[]` | Additional rules to be covered with this ingress record ref: https://kubernetes.io/docs/concepts/services-networking/ingress/#ingress-rules e.g: extraRules: - host: example.local     http:       path: /       backend:         service:           name: example-svc           port:             name: http |
| ingress.extraTls | list | `[]` | TLS configuration for additional hostname(s) to be covered with this ingress record ref: https://kubernetes.io/docs/concepts/services-networking/ingress/#tls e.g: extraTls: - hosts:     - carbide-pxe.local   secretName: carbide-pxe.local-tls |
| ingress.hostname | string | `".local"` | Default host for the ingress record |
| ingress.ingressClassName | string | `""` | IngressClass that will be be used to implement the Ingress (Kubernetes 1.18+) This is supported in Kubernetes 1.18+ and required if you have more than one IngressClass marked as the default for your cluster . ref: https://kubernetes.io/blog/2020/04/02/improvements-to-the-ingress-api-in-kubernetes-1.18/ |
| ingress.path | string | `"/"` | Default path for the ingress record NOTE: You may need to set this to '/*' in order to use this with ALB ingress controllers |
| ingress.pathType | string | `"ImplementationSpecific"` | Ingress path type |
| ingress.secrets | list | `[]` | Custom TLS certificates as secrets NOTE: 'key' and 'certificate' are expected in PEM format NOTE: 'name' should line up with a 'secretName' set further up If it is not set and you're using cert-manager, this is unneeded, as it will create a secret for you with valid certificates If it is not set and you're NOT using cert-manager either, self-signed certificates will be created valid for 365 days It is also possible to create and manage the certificates outside of this helm chart Please see README.md for more information e.g: secrets:   - name: carbide-pxe.local-tls     key: |-       -----BEGIN RSA PRIVATE KEY-----       ...       -----END RSA PRIVATE KEY-----     certificate: |-       -----BEGIN CERTIFICATE-----       ...       -----END CERTIFICATE----- |
| ingress.selfSigned | bool | `false` | Create a TLS secret for this ingress record using self-signed certificates generated by Helm |
| ingress.tls | bool | `false` | Enable TLS configuration for the host defined at `ingress.hostname` parameter TLS certificates will be retrieved from a TLS secret with name: `{{- printf "%s-tls" .Values.ingress.hostname }}` You can:   - Use the `ingress.secrets` parameter to create this TLS secret   - Rely on cert-manager to create it by setting the corresponding annotations   - Rely on Helm to create self-signed certificates by setting `ingress.selfSigned=true` |
| kubeVersion | string | `""` | Override Kubernetes version |
| nameOverride | string | `"carbide-pxe"` | String to partially override common.names.name |
| namespaceOverride | string | `""` | String to fully override common.names.namespace |
| ntpServerIP | string | `""` | IP address of working NTP server |
| persistence.accessModes | list | `["ReadWriteOnce"]` | Persistent Volume Access Modes |
| persistence.annotations | object | `{}` | Persistent Volume Claim annotations |
| persistence.dataSource | object | `{}` | Custom PVC data source |
| persistence.enabled | bool | `false` | Enable persistence using Persistent Volume Claims |
| persistence.existingClaim | string | `""` | The name of an existing PVC to use for persistence |
| persistence.mountPath | string | `"/mnt/persistence"` | Path to mount the volume at. |
| persistence.selector | object | `{}` | Selector to match an existing Persistent Volume for WordPress data PVC If set, the PVC can't have a PV dynamically provisioned for it E.g. selector:   matchLabels:     app: my-app |
| persistence.size | string | `"8Gi"` | Size of data volume |
| persistence.storageClass | string | `""` | Storage class of backing PVC If defined, storageClassName: <storageClass> |
| persistence.subPath | string | `""` | The subdirectory of the volume to mount to, useful in dev environments and one PV for multiple services |
| rbac.create | bool | `true` | Specifies whether RBAC resources should be created |
| rbac.rules | list | `[]` | Custom RBAC rules to set e.g: rules:   - apiGroups:       - ""     resources:       - pods     verbs:       - get       - list |
| rocketConfigPath | string | `"/tmp/carbide/Rocket.toml"` | Path to ROCKET config file |
| rocketEnv | string | `"production"` | What environment is this running in |
| rocketTemplateDir | string | `"/opt/carbide/pxe/templates"` | Where to search for templates |
| service.annotations | object | `{}` | Additional custom annotations for carbide service |
| service.clusterIP | string | `""` | carbide service Cluster IP e.g.: clusterIP: None |
| service.externalTrafficPolicy | string | `"Cluster"` | carbide service external traffic policy ref: http://kubernetes.io/docs/tasks/access-application-cluster/create-external-load-balancer/#preserving-the-client-source-ip |
| service.extraPorts | list | `[]` | Extra ports to expose in carbide service (normally used with the `sidecars` value) |
| service.loadBalancerIP | string | `""` | carbide service Load Balancer IP ref: https://kubernetes.io/docs/concepts/services-networking/service/#type-loadbalancer |
| service.loadBalancerSourceRanges | list | `[]` | carbide service Load Balancer sources ref: https://kubernetes.io/docs/tasks/access-application-cluster/configure-cloud-provider-firewall/#restrict-access-for-loadbalancer-service e.g: loadBalancerSourceRanges:   - 10.10.10.0/24 |
| service.nodePorts | object | `{"http":8080,"https":31443}` | Node ports to expose NOTE: choose port between <30000-32767> |
| service.nodePorts.http | int | `8080` | Node port for HTTP |
| service.nodePorts.https | int | `31443` | Node port for HTTPS |
| service.ports.http | int | `8080` | carbide service HTTP port |
| service.ports.https | int | `8443` | carbide service HTTPS port |
| service.sessionAffinity | string | `"None"` | Control where client requests go, to the same pod or round-robin Values: ClientIP or None ref: https://kubernetes.io/docs/user-guide/services/ |
| service.sessionAffinityConfig | object | `{}` | Additional settings for the sessionAffinity sessionAffinityConfig:   clientIP:     timeoutSeconds: 300 |
| service.type | string | `"NodePort"` | carbide service type |
| serviceAccount.annotations | object | `{}` | Additional Service Account annotations (evaluated as a template) |
| serviceAccount.automountServiceAccountToken | bool | `true` |  |
| serviceAccount.create | bool | `true` | Specifies whether a ServiceAccount should be created |
| serviceAccount.name | string | `"carbide-pxe"` | The name of the ServiceAccount to use. If not set and create is true, a name is generated using the common.names.fullname template |
| templateDir | string | `"/opt/carbide/pxe/templates"` | location of ipxe templates in container |
| trustDomain | string | `"forge.local"` | spiffe trust domain |
| useTLS | bool | `false` | Listen on HTTPS for incoming connections NOTE container will fail to start if certificate is not present |
| volumePermissions.containerSecurityContext.runAsUser | int | `0` | Set init container's Security Context runAsUser NOTE: when runAsUser is set to special value "auto", init container will try to chown the   data folder to auto-determined user&group, using commands: `id -u`:`id -G | cut -d" " -f2`   "auto" is especially useful for OpenShift which has scc with dynamic user ids (and 0 is not allowed) |
| volumePermissions.enabled | bool | `false` | Enable init container that changes the owner/group of the PV mount point to `runAsUser:fsGroup` |
| volumePermissions.image.pullPolicy | string | `"IfNotPresent"` | Bitnami Shell image pull policy |
| volumePermissions.image.pullSecrets | list | `[]` | Bitnami Shell image pull secrets Optionally specify an array of imagePullSecrets. Secrets must be manually created in the namespace. ref: https://kubernetes.io/docs/tasks/configure-pod-container/pull-image-private-registry/ |
| volumePermissions.image.registry | string | `"nvcr.io"` | Bitnami Shell image registry |
| volumePermissions.image.repository | string | `"nvidian/forge/bitnami-shell"` | Bitnami Shell image repository |
| volumePermissions.image.tag | string | `"latest"` | Bitnami Shell image tag (immutable tags are recommended) |
| volumePermissions.resources.limits | object | `{}` | The resources limits for the init container |
| volumePermissions.resources.requests | object | `{}` | The requested resources for the init container |

----------------------------------------------
Autogenerated from chart metadata using [helm-docs v1.11.0](https://github.com/norwoodj/helm-docs/releases/v1.11.0)
