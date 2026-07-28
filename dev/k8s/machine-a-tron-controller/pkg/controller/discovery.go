// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// DefaultDiscoverySelector is the default label selector for discovering
// machine-a-tron bmc-mock Services.
const DefaultDiscoverySelector = "nvidia-infra-controller/mat-service=true"

// DiscoveredInstance represents a discovered machine-a-tron instance.
type DiscoveredInstance struct {
	URL     string
	PodName string
}

// MatPodDiscovery discovers machine-a-tron pods via their bmc-mock Services.
type MatPodDiscovery struct {
	clientset     kubernetes.Interface
	namespace     string
	port          int
	labelSelector string
}

// NewMatPodDiscovery creates a new MatPodDiscovery.
// If labelSelector is empty, uses DefaultDiscoverySelector.
func NewMatPodDiscovery(clientset kubernetes.Interface, namespace string, port int, labelSelector string) *MatPodDiscovery {
	if labelSelector == "" {
		labelSelector = DefaultDiscoverySelector
	}
	return &MatPodDiscovery{
		clientset:     clientset,
		namespace:     namespace,
		port:          port,
		labelSelector: labelSelector,
	}
}

// Discover finds all machine-a-tron bmc-mock services and returns their URLs with pod names.
func (d *MatPodDiscovery) Discover(ctx context.Context) ([]DiscoveredInstance, error) {
	services, err := d.clientset.CoreV1().Services(d.namespace).List(ctx, metav1.ListOptions{
		LabelSelector: d.labelSelector,
	})
	if err != nil {
		return nil, fmt.Errorf("listing services with selector %q: %w", d.labelSelector, err)
	}

	var instances []DiscoveredInstance
	for _, svc := range services.Items {
		url := fmt.Sprintf("https://%s.%s.svc.cluster.local:%d", svc.Name, d.namespace, d.port)
		podName := svc.Labels[LabelPodName]
		instances = append(instances, DiscoveredInstance{
			URL:     url,
			PodName: podName,
		})
	}

	return instances, nil
}
