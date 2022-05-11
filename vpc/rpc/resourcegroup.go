/*
Copyright 2021 NVIDIA CORPORATION & AFFILIATES.
*/

package rpc

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	vpcresource "gitlab-master.nvidia.com/forge/vpc/apis/resource/v1alpha1"
)

const (
	managedResourceIndexerByGroup = ".spec.resourcegroup"
)

var (
	_      ResourceGroupServer = &resourceGroupServer{}
	scheme                     = runtime.NewScheme()

	K8sNamespace string
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(vpcresource.AddToScheme(scheme))
}

type resourceGroupServer struct {
	UnimplementedResourceGroupServer
	client client.Client
	logger logr.Logger
}

func validateResourceGroup(_ *ResourceGroupSpec) bool {
	// TODO later
	return true
}

func validateManagedResource(_ *ManagedResourceSpec) bool {
	// TODO later
	return true
}

func NewResourceGroupServer(logger logr.Logger) (ResourceGroupServer, error) {
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:             scheme,
		MetricsBindAddress: "0",
	})
	if err != nil {
		logger.Error(err, "Failed to create K8s controller manager")
		return nil, err
	}
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &vpcresource.ManagedResource{}, managedResourceIndexerByGroup,
		func(obj client.Object) []string {
			mr := obj.(*vpcresource.ManagedResource)
			return []string{mr.Spec.ResourceGroup}
		}); err != nil {
		logger.Error(err, "Failed to create indexer", "Indexer", managedResourceIndexerByGroup)
		return nil, err
	}
	return &resourceGroupServer{
		client: mgr.GetClient(),
		logger: logger,
	}, nil
}

func (s *resourceGroupServer) CreateResourceGroup(ctx context.Context, spec *ResourceGroupSpec) (*ServiceStatus, error) {
	if !validateResourceGroup(spec) {
		s.logger.Error(nil, "Failed to validate", "ResourceGroup", spec)
		err := fmt.Errorf("invalid ResourceGroup")
		return &ServiceStatus{Status: ErrorCode_Invalid, Message: err.Error()}, err
	}
	ctx, cancel := context.WithTimeout(ctx, time.Second*2)
	defer cancel()
	rg := &vpcresource.ResourceGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name:      spec.Name,
			Namespace: K8sNamespace,
		},
		Spec: vpcresource.ResourceGroupSpec{
			TenantIdentifier: spec.TenantIdentifier,
			Network: &vpcresource.IPNet{
				IP:           vpcresource.IPAddress(net.IP(spec.Network.Ip).String()),
				PrefixLength: spec.Network.PrefixLength,
				Gateway:      vpcresource.IPAddress(net.IP(spec.Network.Gateway).String()),
			},
			NetworkImplementationType: vpcresource.OverlayNetworkImplementationType(spec.NetworkImplementationType.String()),
		},
	}
	if err := s.client.Create(ctx, rg); err != nil {
		s.logger.Error(err, "Create ResourceGroup failed", "ResourceGroup", rg)
		return &ServiceStatus{
			Status:  ErrorCode_OpFailed,
			Message: err.Error(),
		}, err
	}
	return &ServiceStatus{Status: ErrorCode_OK}, nil
}

func (s *resourceGroupServer) UpdateResourceGroup(ictx context.Context, spec *ResourceGroupSpec) (*ServiceStatus, error) {
	if !validateResourceGroup(spec) {
		s.logger.Error(nil, "Failed to validate", "ResourceGroup", spec)
		err := fmt.Errorf("invalid ResourceGroup")
		return &ServiceStatus{Status: ErrorCode_Invalid, Message: err.Error()}, err
	}
	ctx, cancel := context.WithTimeout(ictx, time.Second*2)
	defer cancel()
	rg := &vpcresource.ResourceGroup{
		ObjectMeta: metav1.ObjectMeta{
			Name:      spec.Name,
			Namespace: K8sNamespace,
		},
		Spec: vpcresource.ResourceGroupSpec{
			TenantIdentifier: spec.TenantIdentifier,
			Network: &vpcresource.IPNet{
				IP:           vpcresource.IPAddress(net.IP(spec.Network.Ip).String()),
				PrefixLength: spec.Network.PrefixLength,
				Gateway:      vpcresource.IPAddress(net.IP(spec.Network.Gateway).String()),
			},
			NetworkImplementationType: vpcresource.OverlayNetworkImplementationType(spec.NetworkImplementationType.String()),
		},
	}
	if err := s.client.Update(ctx, rg); err != nil {
		s.logger.Error(err, "Update ResourceGroup failed", "ResourceGroup", rg)
		return &ServiceStatus{
			Status:  ErrorCode_OpFailed,
			Message: err.Error(),
		}, err
	}

	// TODO, using LastTransactionTime to determine if Update has been applied
	time.Sleep(time.Millisecond * 100)
	key := client.ObjectKey{
		Namespace: K8sNamespace,
		Name:      spec.Name,
	}
	ctx, cancel = context.WithTimeout(ictx, time.Second*2)
	defer cancel()
	if err := s.client.Get(ctx, key, rg); err != nil {
		return &ServiceStatus{
			Status:  ErrorCode_OpFailed,
			Message: err.Error(),
		}, err
	}
	if len(rg.Status.Conditions) == 0 {
		return &ServiceStatus{
			Status:  ErrorCode_InProgress,
			Message: ErrorCode_InProgress.String(),
		}, fmt.Errorf("operation in progress")
	}
	opStatus := ErrorCode_OK
	msg := ""
	if rg.Status.Conditions[0].Status != corev1.ConditionTrue {
		opStatus = ErrorCode_OpFailed
		msg = rg.Status.Conditions[0].Message
	}
	return &ServiceStatus{Status: opStatus, Message: msg}, nil
}

// ListResourceGroup get one or all ResourceGroups.
func (s *resourceGroupServer) ListResourceGroup(name *ResourceGroupName, stream ResourceGroup_ListResourceGroupServer) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
	defer cancel()
	rgList := &vpcresource.ResourceGroupList{}
	if err := s.client.List(ctx, rgList, client.InNamespace(K8sNamespace)); err != nil {
		s.logger.Error(err, "Failed to list ResourceGroups")
		return err
	}
	for _, rg := range rgList.Items {
		if name == nil || name.Name == rg.Name {
			opStatus := ErrorCode_OK
			msg := ""
			if rg.Status.Conditions[0].Status != corev1.ConditionTrue {
				opStatus = ErrorCode_OpFailed
				msg = rg.Status.Conditions[0].Message
			}
			rgs := &ResourceGroupStatus{
				Name: rg.Name,
				Status: &ServiceStatus{
					Status:  opStatus,
					Message: msg,
				},
			}
			for _, snat := range rg.Status.SNATIPs {
				rgs.SnatIPs = append(rgs.SnatIPs, net.IP(snat))
			}
			if err := stream.Send(rgs); err != nil {
				s.logger.Error(err, "Failed to reply ResourceGroup list request", "Name", name.Name)
				return err
			}
		}
		if name != nil {
			break
		}
	}
	return nil
}

func (s *resourceGroupServer) DeleteResourceGroup(ictx context.Context, rgSpec *ResourceGroupSpec) (*ServiceStatus, error) {
	// Delete all ManagedResources belong to the ResourceGroup.
	ctx, cancel := context.WithTimeout(ictx, time.Second*2)
	defer cancel()
	mrList := &vpcresource.ManagedResourceList{}
	if err := s.client.List(ctx, mrList,
		client.InNamespace(K8sNamespace), client.MatchingFields{managedResourceIndexerByGroup: rgSpec.Name}); err != nil {
		s.logger.Error(err, "Failed to list ManagedResources")
		return &ServiceStatus{Status: ErrorCode_OpFailed, Message: err.Error()}, err
	}
	for _, mr := range mrList.Items {
		if err := func() error {
			ctx, cancel = context.WithTimeout(ictx, time.Second*2)
			defer cancel()
			if err := s.client.Delete(ctx, &mr); err != nil {
				s.logger.Error(err, "Failed to delete", "ManagedResource", mr)
				return err
			}
			return nil
		}(); err != nil {
			return &ServiceStatus{Status: ErrorCode_OpFailed, Message: err.Error()}, err
		}
	}

	// Delete the ResourceGroup.
	ctx, cancel = context.WithTimeout(ictx, time.Second*2)
	defer cancel()
	rg := &vpcresource.ResourceGroup{}
	rgKey := client.ObjectKey{
		Namespace: K8sNamespace,
		Name:      rgSpec.Name,
	}
	if err := s.client.Get(ctx, rgKey, rg); err != nil {
		s.logger.Error(err, "Failed to get", "ResourceGroup", rgKey)
		return &ServiceStatus{Status: ErrorCode_OpFailed, Message: err.Error()}, err
	}
	ctx, cancel = context.WithTimeout(ictx, time.Second*30)
	defer cancel()
	if err := s.client.Delete(ctx, rg); err != nil {
		s.logger.Error(err, "Failed to delete", "ResourceGroup", rgKey)
		return &ServiceStatus{Status: ErrorCode_OpFailed, Message: err.Error()}, err
	}
	return nil, nil
}
func (s *resourceGroupServer) UpdateManagedResource(ictx context.Context, mrSpec *ManagedResourceSpec) (*ServiceStatus, error) {
	if !validateManagedResource(mrSpec) {
		s.logger.Error(nil, "Failed to validate", "ManagedResource", mrSpec)
		err := fmt.Errorf("invalid ManagedResource")
		return &ServiceStatus{Status: ErrorCode_Invalid, Message: err.Error()}, err
	}
	ctx, cancel := context.WithTimeout(ictx, time.Second*2)
	defer cancel()
	mr := &vpcresource.ManagedResource{}
	mrKey := client.ObjectKey{
		Namespace: K8sNamespace,
		Name:      mrSpec.Name,
	}
	isCreate := true
	if err := s.client.Get(ctx, mrKey, mr); err != nil {
		if !errors.IsNotFound(err) {
			s.logger.Error(err, "Failed to get", "ManagedResource", mr)
			return &ServiceStatus{Status: ErrorCode_OpFailed, Message: err.Error()}, err
		}
		isCreate = false
	}
	mr.Spec = vpcresource.ManagedResourceSpec{
		ResourceGroup:       mrSpec.ResourceGroup,
		Type:                vpcresource.ResourceType(mrSpec.ResourceType.String()),
		State:               vpcresource.ManagedResourceState(mrSpec.DpuState.String()),
		HostInterfaceIP:     vpcresource.IPAddress(net.IP(mrSpec.HostIP).String()),
		HostInterfaceMAC:    vpcresource.MACAddress(net.HardwareAddr(mrSpec.HostMAC).String()),
		HostInterfaceAccess: vpcresource.HostAccess(mrSpec.HostAccess.String()),
	}
	for _, ip := range mrSpec.DPUIPs {
		mr.Spec.DPUIPs = append(mr.Spec.DPUIPs, vpcresource.IPAddress(net.IP(ip).String()))
	}
	ctx, cancel = context.WithTimeout(ictx, time.Second*30)
	defer cancel()
	var err error
	if isCreate {
		err = s.client.Create(ctx, mr)
	} else {
		err = s.client.Update(ctx, mr)
	}
	if err != nil {
		s.logger.Error(err, "Failed to create/update", "ManagedResource", mr)
		return &ServiceStatus{Status: ErrorCode_OpFailed, Message: err.Error()}, err
	}
	return nil, nil
}

func (s *resourceGroupServer) ListManagedResource(rgName *ResourceGroupName, stream ResourceGroup_ListManagedResourceServer) error {
	ictx := context.Background()
	ctx, cancel := context.WithTimeout(ictx, time.Second*2)
	defer cancel()
	rg := &vpcresource.ResourceGroup{}
	rgKey := client.ObjectKey{
		Namespace: K8sNamespace,
		Name:      rgName.Name,
	}
	if err := s.client.Get(ctx, rgKey, rg); err != nil {
		s.logger.Error(err, "Failed to get", "ResourceGroup", rgKey)
		return err
	}
	ctx, cancel = context.WithTimeout(ictx, time.Second*2)
	defer cancel()
	mrList := &vpcresource.ManagedResourceList{}
	if err := s.client.List(ctx, mrList,
		client.InNamespace(K8sNamespace), client.MatchingFields{managedResourceIndexerByGroup: rgName.Name}); err != nil {
		s.logger.Error(err, "Failed to list ManagedResources")
		return err
	}
	for _, mr := range mrList.Items {
		status := &ManagedResourceStatus{
			Name: mr.Name,
			HostAccessIPs: &IPAssociation{
				HostIP:   []byte(net.ParseIP(string(mr.Status.HostAccessIPs.HostIP))),
				FabricIP: []byte(net.ParseIP(string(mr.Status.HostAccessIPs.FabricIP))),
			},
		}
		opStatus := ErrorCode_OK
		msg := ""
		if len(mr.Status.Conditions) == 0 {
			opStatus = ErrorCode_InProgress
			msg = ErrorCode_InProgress.String()
		}
		if rg.Status.Conditions[0].Status != corev1.ConditionTrue {
			opStatus = ErrorCode_OpFailed
			msg = rg.Status.Conditions[0].Message
		}
		status.Status = &ServiceStatus{
			Status:  opStatus,
			Message: msg,
		}
		if err := stream.Send(status); err != nil {
			s.logger.Error(err, "Failed to send ManagedResource")
			return err
		}
	}
	return nil
}
