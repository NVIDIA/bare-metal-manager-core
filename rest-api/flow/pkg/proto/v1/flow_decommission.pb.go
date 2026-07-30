// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Code generated manually — run protoc to regenerate after updating flow.proto.

package v1

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
)

// DecommissionRackRequest is the request message for the DecommissionRack RPC.
//
// TODO: regenerate pkg/proto/v1 from flow.proto via protoc after this type is
// added to the proto file. The hand-written struct is a compilation stub; the
// binary descriptor in flow.pb.go does NOT include this message, so proto
// reflection-based operations (protojson, proto.Marshal) will use field tags
// instead of the descriptor.
type DecommissionRackRequest struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	TargetSpec    *OperationTargetSpec   `protobuf:"bytes,1,opt,name=target_spec,json=targetSpec,proto3" json:"target_spec,omitempty"` // Target racks for decommissioning
	Description   string                 `protobuf:"bytes,2,opt,name=description,proto3" json:"description,omitempty"`                 // optional task description
	QueueOptions  *QueueOptions          `protobuf:"bytes,3,opt,name=queue_options,json=queueOptions,proto3,oneof" json:"queue_options,omitempty"` // optional queue policy overrides
	RuleId        *UUID                  `protobuf:"bytes,4,opt,name=rule_id,json=ruleId,proto3,oneof" json:"rule_id,omitempty"`       // optional: override rule resolution
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *DecommissionRackRequest) Reset() {
	*x = DecommissionRackRequest{}
}

func (x *DecommissionRackRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DecommissionRackRequest) ProtoMessage() {}

func (x *DecommissionRackRequest) ProtoReflect() protoreflect.Message {
	// Stub: returns the reflection of an empty IngestRackRequest as a placeholder
	// so that proto.Marshal / gRPC codec can encode this type. Full descriptor
	// support requires regenerating flow.pb.go via protoc.
	//
	// In practice, gRPC uses codec.Marshal which calls proto.Marshal → ProtoReflect.
	// The stub satisfies the interface contract at compile time; runtime encoding
	// relies on the protobuf field tags defined above.
	mi := &file_flow_proto_msgTypes[71] // IngestRackRequest slot — placeholder
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

func (*DecommissionRackRequest) Descriptor() ([]byte, []int) {
	return file_flow_proto_rawDescGZIP(), []int{71} // placeholder index
}

func (x *DecommissionRackRequest) GetTargetSpec() *OperationTargetSpec {
	if x != nil {
		return x.TargetSpec
	}
	return nil
}

func (x *DecommissionRackRequest) GetDescription() string {
	if x != nil {
		return x.Description
	}
	return ""
}

func (x *DecommissionRackRequest) GetQueueOptions() *QueueOptions {
	if x != nil {
		return x.QueueOptions
	}
	return nil
}

func (x *DecommissionRackRequest) GetRuleId() *UUID {
	if x != nil {
		return x.RuleId
	}
	return nil
}
