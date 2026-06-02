// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"errors"
	"time"

	"github.com/NVIDIA/infra-controller-rest/api/pkg/api/model/util"
	cdb "github.com/NVIDIA/infra-controller-rest/db/pkg/db"
	cdbm "github.com/NVIDIA/infra-controller-rest/db/pkg/db/model"
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/go-ozzo/ozzo-validation/v4/is"
	"github.com/google/uuid"
	"gopkg.in/yaml.v3"
)

const (
	validationErrorInfrastructureProviderIDExpectNil = "Specifying InfrastructureProviderID is currently not supported"
	errMsgInvalidImageSHA                            = "not a valid SHA hash"
	errMsgInvalidImageDiskPath                       = "not a valid disk path"
	errMsgExactlyOneRootFsField                      = "exactly one of 'rootFsId' and 'rootFsLabel' must be specified"
	errMsgOnlyOneRootFsField                         = "only one of 'rootFsId' and 'rootFsLabel' may be specified"
	errMsgNotEmpty                                   = "cannot be empty"
)

// APIOperatingSystemCreateRequest is the data structure to capture user request to create a new OperatingSystem
type APIOperatingSystemCreateRequest struct {
	// Name is the name of the OperatingSystem
	Name string `json:"name"`
	// Description is the description of the OperatingSystem
	Description *string `json:"description"`
	// InfrastructureProviderID is the ID of the InfrastructureProvider creating the Operating System
	InfrastructureProviderID *string `json:"infrastructureProviderId"`
	// SiteIDs is a list of Site objects
	SiteIDs []string `json:"siteIds"`
	// TenantID is the ID of the Tenant creating the Operating System
	TenantID *string `json:"tenantId"`
	// IpxeScript is the iPXE script for the Operating System
	IpxeScript *string `json:"ipxeScript"`
	// ImageURL is the image path for the Operating System
	ImageURL *string `json:"imageUrl"`
	// ImageSHA is SHA for the Operating System image type
	ImageSHA *string `json:"imageSha"`
	// ImageAuthType is auth type for the Operating System type
	ImageAuthType *string `json:"imageAuthType"`
	// ImageAuthToken is auth token for for the Operating System image type
	ImageAuthToken *string `json:"imageAuthToken"`
	// ImageDisk is disk for the Operating System image type
	ImageDisk *string `json:"imageDisk"`
	// RootFsID is root fs id for the Operating System image type
	RootFsID *string `json:"rootFsId"`
	// RootFsLabel is root fs label for the Operating System image type
	RootFsLabel *string `json:"rootFsLabel"`
	// PhoneHomeEnabled is the flag to allow enable phone home
	PhoneHomeEnabled *bool `json:"phoneHomeEnabled"`
	// UserData is the user data for the Operating System
	UserData *string `json:"userData"`
	// IsCloudInit indicates if the Operating System needs cloud init
	IsCloudInit bool `json:"isCloudInit"`
	// AllowOverride indicates if overrides are allowed
	AllowOverride bool `json:"allowOverride"`
	// EnableBlockStorage indicates whether the Operating System image will be stored remotely via block storage
	EnableBlockStorage bool `json:"enableBlockStorage"`
}

// Validate ensure the values passed in request are acceptable
func (oscr APIOperatingSystemCreateRequest) Validate() error {
	var err error
	err = validation.ValidateStruct(&oscr,
		validation.Field(&oscr.Name,
			validation.Required.Error(validationErrorStringLength),
			validation.By(util.ValidateNameCharacters),
			validation.Length(2, 256).Error(validationErrorStringLength)),
		validation.Field(&oscr.InfrastructureProviderID,
			// infrastructure provider id must be nil
			validation.Nil.Error(validationErrorInfrastructureProviderIDExpectNil)),
	)
	if err != nil {
		return err
	}

	// Make sure siteIds only required in case of image is OS based
	if oscr.IpxeScript != nil && len(oscr.SiteIDs) > 0 {
		return validation.Errors{
			"siteIds": errors.New("cannot be specified for iPXE based Operating Systems"),
		}
	}

	if oscr.IpxeScript != nil && oscr.ImageURL != nil {
		return validation.Errors{
			"imageURL": errors.New("cannot be specified for iPXE based Operating Systems"),
		}
	} else if oscr.IpxeScript == nil && oscr.ImageURL == nil {
		return validation.Errors{
			validationCommonErrorField: errors.New("either imageURL or ipxeScript must be specified"),
		}
	}

	if oscr.EnableBlockStorage {
		return validation.Errors{
			"enableBlockStorage": errors.New("Enabling block storage is not supported at this time"),
		}
	}

	if oscr.ImageURL != nil {
		err = validation.ValidateStruct(&oscr,
			validation.Field(&oscr.ImageURL, is.URL),
			validation.Field(&oscr.ImageSHA,
				validation.Required.Error(validationErrorValueRequired),
				validation.When(oscr.ImageSHA != nil, validation.Match(util.ShaHashRegex).Error(errMsgInvalidImageSHA))),
			validation.Field(&oscr.ImageAuthType,
				validation.When(!(util.IsNilOrEmptyStrPtr(oscr.ImageAuthType)) && util.IsNilOrEmptyStrPtr(oscr.ImageAuthToken),
					validation.Required.Error("imageAuthType cannot be specified if imageAuthToken is not specified")),
				validation.When(!(util.IsNilOrEmptyStrPtr(oscr.ImageAuthType)),
					validation.In(cdbm.OperatingSystemAuthTypeBasic, cdbm.OperatingSystemAuthTypeBearer).Error("imageAuthType must be Basic or Bearer")),
			),
			validation.Field(&oscr.ImageAuthToken,
				validation.When(!(util.IsNilOrEmptyStrPtr(oscr.ImageAuthToken)) && util.IsNilOrEmptyStrPtr(oscr.ImageAuthType), validation.Required.Error("imageAuthType must be specified when imageAuthToken is specified"))),
			validation.Field(&oscr.ImageDisk,
				validation.When(!(util.IsNilOrEmptyStrPtr(oscr.ImageDisk)), validation.Match(util.DiskImagePathRegex).Error(errMsgInvalidImageDiskPath))),
			validation.Field(&oscr.RootFsID,
				validation.When(util.IsNilOrEmptyStrPtr(oscr.RootFsLabel), validation.Required.Error(errMsgExactlyOneRootFsField)),
				validation.When(!(util.IsNilOrEmptyStrPtr(oscr.RootFsLabel)), validation.Empty.Error(errMsgExactlyOneRootFsField))),
			validation.Field(&oscr.RootFsLabel,
				validation.When(util.IsNilOrEmptyStrPtr(oscr.RootFsID), validation.Required.Error(errMsgExactlyOneRootFsField)),
				validation.When(!(util.IsNilOrEmptyStrPtr(oscr.RootFsID)), validation.Empty.Error(errMsgExactlyOneRootFsField))),
		)
		if len(oscr.SiteIDs) == 0 {
			return validation.Errors{
				"siteIds": errors.New("must be specified for image based Operating Systems"),
			}
		} else if len(oscr.SiteIDs) > 1 {
			return validation.Errors{
				"siteIds": errors.New("must specify a single Site ID. Creating Image based Operating System on more than one Site is not supported"),
			}
		}
	} else {
		err = validation.ValidateStruct(&oscr,
			validation.Field(&oscr.SiteIDs,
				validation.Nil.Error("siteIds cannot be specified if imageURL is not specified")),
			validation.Field(&oscr.ImageSHA,
				validation.Nil.Error("imageSHA cannot be specified if imageURL is not specified")),
			validation.Field(&oscr.ImageAuthType,
				validation.Nil.Error("imageAuthType cannot be specified if imageURL is not specified")),
			validation.Field(&oscr.ImageAuthToken,
				validation.Nil.Error("imageAuthToken cannot be specified if imageURL is not specified")),
			validation.Field(&oscr.ImageDisk,
				validation.Nil.Error("imageDisk cannot be specified if imageURL is not specified")),
			validation.Field(&oscr.RootFsID,
				validation.Nil.Error("rootFsID cannot be specified if imageURL is not specified")),
			validation.Field(&oscr.RootFsLabel,
				validation.Nil.Error("rootFsLabel cannot be specified if imageURL is not specified")),
		)
	}

	if oscr.IpxeScript != nil {
		err = validation.ValidateStruct(&oscr,
			validation.Field(&oscr.IpxeScript,
				validation.Required.Error(validationErrorValueRequired)),
			validation.Field(&oscr.EnableBlockStorage,
				validation.Empty.Error("enableBlockStorage must be false if ipxeScript is specified")),
		)
	}

	return err
}

func (oscr *APIOperatingSystemCreateRequest) ValidateAndSetUserData(phonehomeUrl string) error {
	// This is a create.  If phone-home is unspecified or false,
	// then any user-data content is acceptable, so do nothing and return.
	if oscr.PhoneHomeEnabled == nil || !*oscr.PhoneHomeEnabled {
		return nil
	}

	// At this point, we know phone-home has been requested,
	// so default to empty user-data if nothing was passed in
	if oscr.UserData == nil || *oscr.UserData == "" {
		oscr.UserData = cdb.GetStrPtr("{}")
	}

	userDataMap := &yaml.Node{}

	var documentRoot *yaml.Node

	isUserDataValidYAML := false

	err := yaml.Unmarshal([]byte(*oscr.UserData), userDataMap)
	if err == nil {

		// We have a slightly more restrictive view of what
		// counts as valid YAML.
		if len(userDataMap.Content) > 0 {
			documentRoot = userDataMap.Content[0]
			if documentRoot.Kind == yaml.MappingNode {
				isUserDataValidYAML = true
			}
		}
	}

	if !isUserDataValidYAML {
		return validation.Errors{
			"userData": errors.New("userData specified in request must be valid cloud-init YAML to enable phone home"),
		}
	}

	if err := util.InsertPhoneHomeIntoUserData(documentRoot, phonehomeUrl); err != nil {
		return validation.Errors{
			"userData": errors.New("failed to update userData with phone home config"),
		}
	}

	byteUserData, err := yaml.Marshal(userDataMap)
	if err != nil {
		return validation.Errors{
			"userData": errors.New("failed to re-construct userData after processing phone home config"),
		}
	}

	// Render it back out.
	oscr.UserData = cdb.GetStrPtr(string(byteUserData))

	return nil
}

// APIOperatingSystemUpdateRequest is the data structure to capture user request to update an OperatingSystem
type APIOperatingSystemUpdateRequest struct {
	// Name is the name of the OperatingSystem
	Name *string `json:"name"`
	// Description is the description of the Operating System
	Description *string `json:"description"`
	// IpxeScript is the ipxe script for the Operating System
	IpxeScript *string `json:"ipxeScript"`
	// ImageURL is the image path for the Operating System
	ImageURL *string `json:"imageUrl"`
	// ImageSHA is SHA for the Operating System image type
	ImageSHA *string `json:"imageSha"`
	// ImageAuthType is auth type for the Operating System type
	ImageAuthType *string `json:"imageAuthType"`
	// ImageAuthToken is auth token for for the Operating System image type
	ImageAuthToken *string `json:"imageAuthToken"`
	// ImageDisk is disk for the Operating System image type
	ImageDisk *string `json:"imageDisk"`
	// RootFsID is root fs id for the Operating System image type
	RootFsID *string `json:"rootFsId"`
	// RootFsLabel is root fs label for the Operating System image type
	RootFsLabel *string `json:"rootFsLabel"`
	// PhoneHomeEnabled is the flag to allow enable phone home
	PhoneHomeEnabled *bool `json:"phoneHomeEnabled"`
	// UserData is the user data for the Operating System
	UserData *string `json:"userData"`
	// IsCloudInit indicates if the Operating System needs cloud init
	IsCloudInit *bool `json:"isCloudInit"`
	// AllowOverride indicates if overrides are allowed
	AllowOverride *bool `json:"allowOverride"`
	// IsActive indicates if the Operating System is active
	IsActive *bool `json:"isActive"`
	// DeactivationNote is the deactivation note if any
	DeactivationNote *string `json:"deactivationNote"`
}

// Validate ensure the values passed in request are acceptable
func (osur APIOperatingSystemUpdateRequest) Validate(existingOS *cdbm.OperatingSystem) error {
	err := validation.ValidateStruct(&osur,
		validation.Field(&osur.Name,
			validation.When(osur.Name != nil, validation.Required.Error(validationErrorStringLength)),
			validation.When(osur.Name != nil, validation.By(util.ValidateNameCharacters)),
			validation.When(osur.Name != nil, validation.Length(2, 256).Error(validationErrorStringLength))),
	)
	if err != nil {
		return err
	}

	// reject attempts to change active status if already in desired state:
	if osur.IsActive != nil {
		if *osur.IsActive && existingOS.IsActive {
			return validation.Errors{
				"isActive": errors.New("Operating System is already active"),
			}
		} else if !*osur.IsActive && !existingOS.IsActive {
			return validation.Errors{
				"isActive": errors.New("Operating System is already deactivated"),
			}
		} else if *osur.IsActive && osur.DeactivationNote != nil {
			return validation.Errors{
				"deactivationNote": errors.New("cannot provide Deactivation Note when activating Operating System"),
			}
		}
	} else if existingOS.IsActive && osur.DeactivationNote != nil {
		return validation.Errors{
			"deactivationNote": errors.New("cannot change Deactivation Note on an active Operating System"),
		}
	}

	if osur.IpxeScript != nil && osur.ImageURL != nil {
		return validation.Errors{
			"imageURL": errors.New("cannot be specified for iPXE based Operating Systems"),
		}
	}

	// verify if os created with ipxe script, if yes reject the update if imageURL provided
	if existingOS.Type == cdbm.OperatingSystemTypeIPXE && osur.ImageURL != nil {
		return validation.Errors{
			"imageURL": errors.New("unable to set image URL for iPXE based Operating System"),
		}
	} else if existingOS.Type == cdbm.OperatingSystemTypeImage && osur.IpxeScript != nil {
		return validation.Errors{
			"ipxeScript": errors.New("unable to set iPXE script for image based Operating System"),
		}
	}

	isImageBased := existingOS.Type == cdbm.OperatingSystemTypeImage

	if !util.IsNilOrEmptyStrPtr(osur.RootFsID) && osur.RootFsLabel == nil && !util.IsNilOrEmptyStrPtr(existingOS.RootFsLabel) {
		return validation.Errors{
			"rootFsId": errors.New("unable to set root filesystem id for Operating System with root filesystem label specified"),
		}
	} else if isImageBased && util.IsEmptyStrPtr(osur.RootFsID) && ((osur.RootFsLabel == nil && util.IsNilOrEmptyStrPtr(existingOS.RootFsLabel)) || util.IsEmptyStrPtr(osur.RootFsLabel)) {
		return validation.Errors{
			"rootFsId": errors.New("unable to clear root filesystem id for Operating System without specifying root filesystem label"),
		}
	} else if isImageBased && util.IsEmptyStrPtr(osur.RootFsLabel) && util.IsNilOrEmptyStrPtr(existingOS.RootFsID) && osur.RootFsID == nil {
		return validation.Errors{
			"rootFsLabel": errors.New("unable to clear root filesystem label for Operating System without specifying root filesystem id"),
		}
	} else if osur.RootFsID == nil && !util.IsNilOrEmptyStrPtr(osur.RootFsLabel) && !util.IsNilOrEmptyStrPtr(existingOS.RootFsID) {
		return validation.Errors{
			"rootFsLabel": errors.New("unable to set root filesystem label for Operating System with root filesystem id specified"),
		}
	}

	if osur.ImageURL != nil {
		err = validation.ValidateStruct(&osur,
			validation.Field(&osur.ImageURL, is.URL),
			validation.Field(&osur.ImageSHA,
				validation.Required.Error(validationErrorValueRequired),
				validation.When(osur.ImageSHA != nil, validation.Match(util.ShaHashRegex).Error(errMsgInvalidImageSHA))),
			validation.Field(&osur.ImageAuthType,
				validation.When(!(util.IsNilOrEmptyStrPtr(osur.ImageAuthType)) && util.IsNilOrEmptyStrPtr(osur.ImageAuthToken), validation.Required.Error("imageAuthType cannot be specified if imageAuthToken is not specified")),
				validation.When(!(util.IsNilOrEmptyStrPtr(osur.ImageAuthType)),
					validation.In(cdbm.OperatingSystemAuthTypeBasic, cdbm.OperatingSystemAuthTypeBearer).Error("imageAuthType must be Basic or Bearer")),
			),
			validation.Field(&osur.ImageAuthToken,
				validation.When(!(util.IsNilOrEmptyStrPtr(osur.ImageAuthToken)) && util.IsNilOrEmptyStrPtr(osur.ImageAuthType), validation.Required.Error("imageAuthType must be specified when imageAuthToken is specified"))),
			validation.Field(&osur.ImageDisk,
				validation.When(!(util.IsEmptyStrPtr(osur.ImageDisk)), validation.Match(util.DiskImagePathRegex).Error(errMsgInvalidImageDiskPath))),
			validation.Field(&osur.RootFsID,
				validation.When(!(util.IsNilOrEmptyStrPtr(osur.RootFsLabel)), validation.Empty.Error(errMsgOnlyOneRootFsField))),
			validation.Field(&osur.RootFsLabel,
				validation.When(!(util.IsNilOrEmptyStrPtr(osur.RootFsID)), validation.Empty.Error(errMsgOnlyOneRootFsField))),
		)
	} else {
		err = validation.ValidateStruct(&osur,
			validation.Field(&osur.ImageSHA,
				validation.Nil.Error("imageSHA cannot be specified if imageURL is not specified")),
			validation.Field(&osur.ImageAuthType,
				validation.Nil.Error("imageAuthType cannot be specified if imageURL is not specified")),
			validation.Field(&osur.ImageAuthToken,
				validation.Nil.Error("imageAuthToken cannot be specified if imageURL is not specified")),
			validation.Field(&osur.ImageDisk,
				validation.Nil.Error("imageDisk cannot be specified if imageURL is not specified")),
			validation.Field(&osur.RootFsID,
				validation.Nil.Error("rootFsID cannot be specified if imageURL is not specified")),
			validation.Field(&osur.RootFsLabel,
				validation.Nil.Error("rootFsLabel cannot be specified if imageURL is not specified")),
		)
	}

	if osur.IpxeScript != nil {
		err = validation.ValidateStruct(&osur,
			validation.Field(&osur.IpxeScript,
				validation.Required.Error(validationErrorValueRequired)),
		)
	}
	return err
}

func (osur *APIOperatingSystemUpdateRequest) ValidateAndSetUserData(phonehomeUrl string, existingOS *cdbm.OperatingSystem) error {

	mergedPhoneHomeEnabled := osur.PhoneHomeEnabled
	mergedUserData := osur.UserData

	if mergedUserData == nil {
		mergedUserData = existingOS.UserData
	}

	if mergedPhoneHomeEnabled == nil {
		mergedPhoneHomeEnabled = &existingOS.PhoneHomeEnabled

		// If phone-home has never been enabled, then
		// any user-data content was always acceptable,
		// so do nothing and return.
		if !*mergedPhoneHomeEnabled {
			return nil
		}
	}

	// If phone-home is being disabled, but there
	// isn't any user-data to begin with, there's nothing to do.
	if !*mergedPhoneHomeEnabled && (mergedUserData == nil || *mergedUserData == "") {
		return nil
	}

	if mergedUserData == nil || *mergedUserData == "" {
		// A request to disable that had no user-data would
		// have returned already; so, If we're here, then we
		// have a request to enable that is totally missing
		// user data, so default it.
		mergedUserData = cdb.GetStrPtr("{}")
	}

	userDataMap := &yaml.Node{}

	var documentRoot *yaml.Node

	isUserDataValidYAML := false

	err := yaml.Unmarshal([]byte(*mergedUserData), userDataMap)
	if err == nil {

		// We have a slightly more restrictive view of what
		// counts as valid YAML.
		if len(userDataMap.Content) > 0 {
			documentRoot = userDataMap.Content[0]
			if documentRoot.Kind == yaml.MappingNode {
				isUserDataValidYAML = true
			}
		}
	}

	if *mergedPhoneHomeEnabled {
		if !isUserDataValidYAML {
			return validation.Errors{
				"userData": errors.New("userData specified in request must be valid cloud-init YAML to enable phone home"),
			}
		}

		// If some user-data was sent in,
		// insert our phone-home block into the
		// existing data.
		if err := util.InsertPhoneHomeIntoUserData(documentRoot, phonehomeUrl); err != nil {
			return validation.Errors{
				"userData": errors.New("failed to update userData with phone home config"),
			}
		}
	} else if isUserDataValidYAML {
		// If phone-home is being disabled,
		// We still have to make sure we don't try to remove from invalid yaml,
		// but the UI will always send false if phone-home is unchecked,
		// so we want to do this check silently and not alert people who
		// are using non-YAML user-data.
		if err := util.RemovePhoneHomeFromUserData(documentRoot, &phonehomeUrl); err != nil {
			return validation.Errors{
				"userData": errors.New("failed to remove phone home config from userData"),
			}
		}
	} else {
		// If we've arrived here, then phone-home is being disabled,
		// and the user-data is NOT valid YAML,
		// but we don't care, so don't touch user-data and just return.
		return nil
	}

	if len(documentRoot.Content) == 0 {
		// If we've arrived here, then the original user-data
		// was valid, but phone-home has been disabled, and the
		// phone-home block was the only thing in the original YAML,
		// so just blank the DB field.
		osur.UserData = cdb.GetStrPtr("")
		return nil
	}

	// Render any data that still exists.
	byteUserData, err := yaml.Marshal(userDataMap)
	if err != nil {
		return validation.Errors{
			"userData": errors.New("failed to re-construct userData after processing phone home config"),
		}
	}

	// Set it in the request.
	osur.UserData = cdb.GetStrPtr(string(byteUserData))

	return nil
}

// APIOperatingSystem is the data structure to capture API representation of an OS
type APIOperatingSystem struct {
	// ID is the unique UUID v4 identifier for the Operating System
	ID string `json:"id"`
	// Name is the name of the Operating System
	Name string `json:"name"`
	// Description is the description of the Operating System
	Description *string `json:"description"`
	// InfrastructureProviderID is the ID of the InfrastructureProvider creating the OS
	InfrastructureProviderID *string `json:"infrastructureProviderId"`
	// InfrastructureProvider is the summary of the InfrastructureProvider
	InfrastructureProvider *APIInfrastructureProviderSummary `json:"infrastructureProvider,omitempty"`
	// TenantID is the ID of the tenant creating the Operating System
	TenantID *string `json:"tenantId"`
	// Tenant is the summary of the Tenant
	Tenant *APITenantSummary `json:"tenant,omitempty"`
	// Type is which type of Operating System
	Type *string `json:"type"`
	// ImageUrl is url path for the Operating System
	ImageURL *string `json:"imageUrl"`
	// ImageSHA is SHA for the Operating System image type
	ImageSHA *string `json:"imageSha"`
	// ImageAuthType is auth type for the Operating System type
	ImageAuthType *string `json:"imageAuthType"`
	// ImageAuthToken is auth token for for the Operating System image type
	ImageAuthToken *string `json:"imageAuthToken"`
	// ImageDisk is disk for the Operating System image type
	ImageDisk *string `json:"imageDisk"`
	// RootFsID is root fs id for the Operating System image type
	RootFsID *string `json:"rootFsId"`
	// RootFsLabel is root fs id for the Operating System image type
	RootFsLabel *string `json:"rootFsLabel"`
	// IpxeScript is the ipxe ocript for the Operating System
	IpxeScript *string `json:"ipxeScript"`
	// PhoneHomeEnabled is an attribute which is specified by user if Operating System needs to be enabled for phone home or not
	PhoneHomeEnabled bool `json:"phoneHomeEnabled"`
	// UserData is the user data for the Operating System
	UserData *string `json:"userData"`
	// IsCloudInit indicates if the Operating System needs cloud init
	IsCloudInit bool `json:"isCloudInit"`
	// AllowOverride indicates if overrides are allowed
	AllowOverride bool `json:"allowOverride"`
	// EnableBlockStorage indicates whether the Operating System image will be stored remotely via block storage
	EnableBlockStorage bool `json:"enableBlockStorage"`
	// IsActive indicates if the Operating System is active
	IsActive bool `json:"isActive"`
	// DeactivationNote is the deactivation note if any
	DeactivationNote *string `json:"deactivationNote"`
	// Status is the status of the Operating System
	Status string `json:"status"`
	// StatusHistory is the history of statuses for the Operating System
	StatusHistory []APIStatusDetail `json:"statusHistory"`
	// SiteAssociations is the list of Sites associated with the Operating System
	SiteAssociations []APIOperatingSystemSiteAssociation `json:"siteAssociations"`
	// CreatedAt indicates the ISO datetime string for when the entity was created
	Created time.Time `json:"created"`
	// UpdatedAt indicates the ISO datetime string for when the entity was last updated
	Updated time.Time `json:"updated"`
}

// NewAPIOperatingSystem accepts a DB layer objects and returns an API layer object
func NewAPIOperatingSystem(dbOS *cdbm.OperatingSystem, dbsds []cdbm.StatusDetail, ossas []cdbm.OperatingSystemSiteAssociation, sttsmap map[uuid.UUID]*cdbm.TenantSite) *APIOperatingSystem {
	apiOperatingSystem := APIOperatingSystem{
		ID:                 dbOS.ID.String(),
		Name:               dbOS.Name,
		Description:        dbOS.Description,
		Type:               &dbOS.Type,
		ImageURL:           dbOS.ImageURL,
		ImageSHA:           dbOS.ImageSHA,
		ImageAuthType:      dbOS.ImageAuthType,
		ImageAuthToken:     dbOS.ImageAuthToken,
		ImageDisk:          dbOS.ImageDisk,
		RootFsID:           dbOS.RootFsID,
		RootFsLabel:        dbOS.RootFsLabel,
		IpxeScript:         dbOS.IpxeScript,
		PhoneHomeEnabled:   dbOS.PhoneHomeEnabled,
		UserData:           dbOS.UserData,
		IsCloudInit:        dbOS.IsCloudInit,
		AllowOverride:      dbOS.AllowOverride,
		EnableBlockStorage: dbOS.EnableBlockStorage,
		IsActive:           dbOS.IsActive,
		DeactivationNote:   dbOS.DeactivationNote,
		Status:             dbOS.Status,
		Created:            dbOS.Created,
		Updated:            dbOS.Updated,
	}
	if dbOS.InfrastructureProviderID != nil {
		apiOperatingSystem.InfrastructureProviderID = cdb.GetStrPtr(dbOS.InfrastructureProviderID.String())
	}
	if dbOS.TenantID != nil {
		apiOperatingSystem.TenantID = cdb.GetStrPtr(dbOS.TenantID.String())
	}
	if dbOS.InfrastructureProvider != nil {
		apiOperatingSystem.InfrastructureProvider = NewAPIInfrastructureProviderSummary(dbOS.InfrastructureProvider)
	}
	if dbOS.Tenant != nil {
		apiOperatingSystem.Tenant = NewAPITenantSummary(dbOS.Tenant)
	}
	apiOperatingSystem.StatusHistory = []APIStatusDetail{}
	for _, dbsd := range dbsds {
		apiOperatingSystem.StatusHistory = append(apiOperatingSystem.StatusHistory, NewAPIStatusDetail(dbsd))
	}
	apiOperatingSystem.SiteAssociations = []APIOperatingSystemSiteAssociation{}
	for _, ossa := range ossas {
		ts := sttsmap[ossa.SiteID]
		curVal := ossa
		apiOperatingSystem.SiteAssociations = append(apiOperatingSystem.SiteAssociations, *NewAPIOperatingSystemSiteAssociation(&curVal, ts))
	}
	return &apiOperatingSystem
}

// APIOperatingSystemSummary is the data structure to capture API summary of an OperatingSystem
type APIOperatingSystemSummary struct {
	// ID of the OperatingSystem
	ID string `json:"id"`
	// Name of the OperatingSystem, only lowercase characters, digits, hyphens and cannot begin/end with hyphen
	Name string `json:"name"`
	// Type is which type of Operating System
	Type *string `json:"type"`
	// Status is the status of the Operating System
	Status string `json:"status"`
}

// NewAPIOperatingSystemSummary accepts a DB layer OperatingSystem object returns an API layer object
func NewAPIOperatingSystemSummary(dbos *cdbm.OperatingSystem) *APIOperatingSystemSummary {
	aos := APIOperatingSystemSummary{
		ID:     dbos.ID.String(),
		Name:   dbos.Name,
		Type:   &dbos.Type,
		Status: dbos.Status,
	}

	return &aos
}
