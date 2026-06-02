// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package util

import (
	"errors"
	"fmt"

	cwssaws "github.com/NVIDIA/infra-controller-rest/workflow-schema/schema/site-agent/workflows/v1"
	"gopkg.in/yaml.v3"
)

const (
	// configuration for phone home
	SitePhoneHomeName    = "phone_home"
	SitePhoneHomePost    = "POST"
	SitePhoneHomePostAll = "all"
	SitePhoneHomeUrl     = "url"
	SiteCloudConfig      = "#cloud-config"
)

// Walks through the yaml nodes looking for a cloud-init phone-home block
// If `url` is nil, then any phone-home block found will be removed.
// If `url` is non-nil, then the phone-home block will only be removed if
// if the URL matches the value of `url`
func RemovePhoneHomeFromUserData(documentRoot *yaml.Node, url *string) error {

	if documentRoot == nil || documentRoot.Kind != yaml.MappingNode {
		return fmt.Errorf("node must be non-nil MappingNode for user-data removal")
	}

	contentLen := len(documentRoot.Content)

	// If phone-home is being disabled, then delete
	// any phone-home data that might exist.
	// Go through the YAML nodes and look for our target.
	// We've previously determined that documentRoot is a
	// valid MappingNode, so the contents wil be pairs of nodes
	// representing key/value pairs of the map.
	//
	// Note there are no breaks or early returns because a user
	// could have submitted valid but nonsensical YAML with
	// multiple phone-home blocks.
	for i := 0; i < contentLen; i += 2 {
		mapKeyNode := documentRoot.Content[i]
		mapValueNode := documentRoot.Content[i+1]

		// No breaks or early-returns here because the user could have submitted
		// valid but nonsensical YAML that includes a phone-home block multiple times.
		if mapKeyNode.Kind == yaml.ScalarNode && mapKeyNode.Value == SitePhoneHomeName {
			// Check if the next node is a map, which will be the phone_home map itself.
			if mapValueNode.Kind == yaml.MappingNode {

				if url == nil {
					// Snip out the target while preserving the order of the nodes.
					// We have to snip out the key (phone_home) and the value
					// (the actual map node), so +2
					// We're working with pairs here, so the second slice-expression
					// won't violate bounds.
					documentRoot.Content = append(documentRoot.Content[:i], documentRoot.Content[i+2:]...)

					// Shift the "pointer" backwards since we
					// just modified documentRoot.Content "in-place"
					i -= 2

					// Reduce the loop limit since the
					// list being worked on is shorter now.
					contentLen = len(documentRoot.Content)
					continue
				}

				// Get the nodes in the map.
				phoneHomeMapSubNodes := mapValueNode.Content

				// Go through the map nodes and look for the URL key.
				// Again, MappingNode, so we can expect k/v node pairs.
				for j := 0; j < len(phoneHomeMapSubNodes); j += 2 {

					phoneHomeMapKeyNode := phoneHomeMapSubNodes[j]
					phoneHomeMapValueNode := phoneHomeMapSubNodes[j+1]
					if phoneHomeMapKeyNode.Kind == yaml.ScalarNode && phoneHomeMapKeyNode.Value == SitePhoneHomeUrl {
						if phoneHomeMapValueNode.Value == *url {
							documentRoot.Content = append(documentRoot.Content[:i], documentRoot.Content[i+2:]...)
							i -= 2
							contentLen = len(documentRoot.Content)
						}
					}
				}

			}
		}
	}

	return nil
}

func InsertPhoneHomeIntoUserData(documentRoot *yaml.Node, url string) error {
	if documentRoot == nil || documentRoot.Kind != yaml.MappingNode {
		return fmt.Errorf("node must be non-nil MappingNode for user-data insertion")
	}

	if documentRoot.Content == nil {
		documentRoot.Content = []*yaml.Node{}
	}

	// Remove any existing phone-home block found before we insert a new one.
	if err := RemovePhoneHomeFromUserData(documentRoot, nil); err != nil {
		return err
	}

	// Build the PhoneHome user-data section.
	phoneHomeConfigMap := map[string]string{}
	phoneHomeConfigMap[SitePhoneHomeUrl] = url
	phoneHomeConfigMap[SitePhoneHomePost] = SitePhoneHomePostAll

	// Encode it into a new YAML node so we can
	// add it to the root content later.
	phoneHomeValueNode := &yaml.Node{}
	if err := phoneHomeValueNode.Encode(phoneHomeConfigMap); err != nil {
		return errors.New("failed to insert phone-home into userData")
	}
	phoneHomeKeyNode := &yaml.Node{}
	phoneHomeKeyNode.SetString(SitePhoneHomeName)

	// Append the node that we can marshal it back out later.
	documentRoot.Content = append(documentRoot.Content, phoneHomeKeyNode, phoneHomeValueNode)

	// Ensure #cloud-config is present as a head comment
	foundCloudConfig := false
	for _, node := range documentRoot.Content {
		if node.HeadComment == SiteCloudConfig {
			foundCloudConfig = true
			break
		}
	}

	if !foundCloudConfig {
		if documentRoot.Kind == yaml.MappingNode {
			if documentRoot.HeadComment == "" {
				documentRoot.HeadComment = SiteCloudConfig
			}
		}
	}

	return nil
}

// ProtobufLabelsFromAPILabels converts API labels (map[string]string) to protobuf labels ([]*cwssaws.Label)
func ProtobufLabelsFromAPILabels(labels map[string]string) []*cwssaws.Label {
	if labels == nil {
		return nil
	}
	protoLabels := []*cwssaws.Label{}
	for k, v := range labels {
		protoLabels = append(protoLabels, &cwssaws.Label{
			Key:   k,
			Value: &v,
		})
	}
	return protoLabels
}
