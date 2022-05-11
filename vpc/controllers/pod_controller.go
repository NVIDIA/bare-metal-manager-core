/*
Copyright 2021 NVIDIA CORPORATION & AFFILIATES.
*/

package controllers

import (
	"context"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	OVNKeyLabel = "app"
)

var (
	PodController *PodReconciler
)

func NewPodController(cl client.Client, scheme *runtime.Scheme, namespace string) *PodReconciler {
	return &PodReconciler{
		Client:    cl,
		Scheme:    scheme,
		namespace: namespace,
		listeners: make(map[string]chan<- *corev1.Pod),
	}
}

type PodReconciler struct {
	sync.Mutex
	client.Client
	namespace string
	Scheme    *runtime.Scheme
	listeners map[string]chan<- *corev1.Pod
}

func (r *PodReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)
	log.V(1).Info("Received update", "Pod", req)

	pod := &corev1.Pod{}
	if err := r.Get(ctx, req.NamespacedName, pod); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	labelName, ok := pod.GetLabels()[OVNKeyLabel]
	if !ok {
		return ctrl.Result{}, nil
	}
	r.Lock()
	defer r.Unlock()
	listener, ok := r.listeners[labelName]
	if !ok {
		return ctrl.Result{}, nil
	}
	log.V(1).Info("Notify change", "Pod", req)
	listener <- pod
	return ctrl.Result{}, nil
}

func (r *PodReconciler) RegisterListener(labelName string, listener chan<- *corev1.Pod) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	podList := &corev1.PodList{}
	// TODO, hardcoded
	if err := r.List(ctx, podList, client.InNamespace(r.namespace)); err != nil {
		logf.Log.Error(err, "Pod controller failed to list pods during listener registration",
			"ListenerLabel", labelName)
	}
	for _, pod := range podList.Items {
		if ln, ok := pod.GetLabels()[OVNKeyLabel]; ok && labelName == ln {
			go func() { listener <- &pod }()
			break
		}
	}
	r.Lock()
	defer r.Unlock()
	r.listeners[labelName] = listener
	// Handle the case where Pod already exists.
}

func (r *PodReconciler) UnregisterListener(labelName string) {
	r.Lock()
	defer r.Unlock()
	delete(r.listeners, labelName)
}

func (r *PodReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Pod{}).
		Complete(r)

}
