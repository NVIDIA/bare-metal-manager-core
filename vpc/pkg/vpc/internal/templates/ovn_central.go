package templates

import (
	"context"
	"time"

	v1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	OVNLabelKey                 = "app"
	OVNNodeSelectorKey          = "vpc.forge.nvidia.com/node"
	OVNNodeSelectorValueControl = "control"
)

var (
	replica = int32(1)
	userID  = int64(0)

	ovnServiceTemplate = &corev1.Service{
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{
					Name:     "north",
					Protocol: "TCP",
					Port:     6641,
				},
				{
					Name:     "south",
					Protocol: "TCP",
					Port:     6642,
				},
			},
			Selector: map[string]string{OVNLabelKey: ""},
			Type:     corev1.ServiceTypeClusterIP,
		},
	}
	ovnDeploymentTemplate = v1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{OVNLabelKey: ""},
		},
		Spec: v1.DeploymentSpec{
			Replicas: &replica,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{OVNLabelKey: ""},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{OVNLabelKey: ""},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:    "ovn-central",
							Image:   "quay.io/nvidia/forge-connectivity:latest",
							Command: []string{"/start_ovn_central.sh"},
							Env: []corev1.EnvVar{
								{Name: "OVN_SSL_ENABLE", Value: "no"},
							},
							Resources: corev1.ResourceRequirements{
								Requests: corev1.ResourceList{
									"cpu":    resource.MustParse("100m"),
									"memory": resource.MustParse("300Mi"),
								},
							},
							ImagePullPolicy: corev1.PullIfNotPresent,
							SecurityContext: &corev1.SecurityContext{
								Capabilities: &corev1.Capabilities{Add: []corev1.Capability{"SYS_NICE"}},
								RunAsUser:    &userID,
							},
						},
					},
					NodeSelector: map[string]string{OVNNodeSelectorKey: OVNNodeSelectorValueControl},
				},
			},
		},
	}
)

func generateResource(name, ns string) (*corev1.Service, *v1.Deployment) {
	ovnService := ovnServiceTemplate.DeepCopy()
	ovnService.Name = name
	ovnService.Namespace = ns
	ovnService.Spec.Selector[OVNLabelKey] = name
	ovnDeployment := ovnDeploymentTemplate.DeepCopy()
	ovnDeployment.Name = name
	ovnDeployment.Namespace = ns
	ovnDeployment.Labels[OVNLabelKey] = name
	ovnDeployment.Spec.Selector.MatchLabels[OVNLabelKey] = name
	ovnDeployment.Spec.Template.Labels[OVNLabelKey] = name
	return ovnService, ovnDeployment
}

func CreateOvnService(name, ns string, cl client.Client) error {
	ovnService, ovnDeployment := generateResource(name, ns)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*20)
	defer cancel()
	if err := cl.Create(ctx, ovnService); err != nil && !errors.IsAlreadyExists(err) {
		return err
	}
	if err := cl.Create(ctx, ovnDeployment); err != nil && !errors.IsAlreadyExists(err) {
		return err
	}
	return nil
}

func DeleteOvnService(name, ns string, client client.Client) error {
	ovnService, ovnDeployment := generateResource(name, ns)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*20)
	defer cancel()
	if err := client.Delete(ctx, ovnService); err != nil && !errors.IsNotFound(err) {
		return err
	}
	if err := client.Delete(ctx, ovnDeployment); err != nil && !errors.IsNotFound(err) {
		return err
	}
	return nil
}

/*
type OvnCentralTemplateParameters struct {
	ServiceName string
	Namespace   string
}


var OvnCentralTemplate = `
apiVersion: v1
kind: Service
metadata:
  name: {{ .ServiceName }}
  namespace: {{ .Namespace }}
spec:
  selector:
    app: {{ .ServiceName }}
  ports:
    - name: north
      port: 6641
      protocol: TCP
      targetPort: 6641
    - name: south
      port: 6642
      protocol: TCP
      targetPort: 6642
  sessionAffinity: None
  type: ClusterIP
---
kind: Deployment
apiVersion: apps/v1
metadata:
  name: {{ .ServiceName }}
  namespace: {{ .Namespace }}
  labels:
    app: {{ .ServiceName }}
spec:
  selector:
    matchLabels:
      app: {{ .ServiceName }}
  replicas: 1
  template:
    metadata:
      labels:
        app: {{ .ServiceName }}
    spec:
      containers:
        - name: ovn-central
          image: "quay.io/nvidia/forge-connectivity:latest"
          imagePullPolicy: "IfNotPresent"
          command:
            - /start_ovn_central.sh
          securityContext:
            runAsUser: 0
            capabilities:
              add: ["SYS_NICE"]
          terminationMessagePolicy: FallbackToLogsOnError
          resources:
            requests:
              cpu: 100m
              memory: 300Mi
          env:
            - name: OVN_SSL_ENABLE
              value: "no"
      nodeSelector:
        vpc.forge.nvidia.com/node: control
`
*/
