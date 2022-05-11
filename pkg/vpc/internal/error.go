package internal

import "fmt"

// UnknownResourceGroupError indicates a ResourceGroup does not exist, due to perhaps user misconfiguration.
type UnknownResourceGroupError struct {
	name string
}

func (e *UnknownResourceGroupError) Error() string {
	return fmt.Sprintf("Backend does not know resourceGroup %v", e.name)
}
func NewUnknownResourceGroupError(name string) error {
	return &UnknownResourceGroupError{name: name}
}

// BackendConfigurationInProgress indicates the backend is executing configuration requirement.
type BackendConfigurationInProgress struct {
	impl string
	kind string
	name string
}

func (e *BackendConfigurationInProgress) Error() string {
	return fmt.Sprintf("%s backend configuration in progress for %s: %s", e.impl, e.kind, e.name)
}

func NewBackendConfigurationInProgress(impl, kind, name string) error {
	return &BackendConfigurationInProgress{impl: impl, kind: kind, name: name}
}

type BackendConfigurationError struct {
	impl string
	kind string
	name string
	msg  string
}

func (e *BackendConfigurationError) Error() string {
	return fmt.Sprintf("%s backend apply configuration failed for %s: %s, %s", e.impl, e.kind, e.name, e.msg)
}

func NewBackendConfigurationError(impl, kind, name, msg string) error {
	return &BackendConfigurationError{impl: impl, kind: kind, name: name, msg: msg}
}

// AlreadyExistError indicates the configuration already exists.
type AlreadyExistError struct {
	name string
	kind string
}

func (e *AlreadyExistError) Error() string {
	return fmt.Sprintf("Backend already have configuration for %s:%s", e.kind, e.name)

}

func NewAlreadyExistError(kind, name string) *AlreadyExistError {
	return &AlreadyExistError{
		kind: kind,
		name: name,
	}
}

// NetworkDeviceNotAvailableError indicates a network device does not exist.
type NetworkDeviceNotAvailableError struct {
	kind string
	name string
}

func NewNetworkDeviceNotAvailableError(kind, name string) *NetworkDeviceNotAvailableError {
	return &NetworkDeviceNotAvailableError{
		kind: kind,
		name: name,
	}
}

func (e *NetworkDeviceNotAvailableError) Error() string {
	return fmt.Sprintf("Backend does not know network fabric device(s) %s:%s", e.kind, e.name)
}

// NetworkDeviceInMaintenanceError indicates a network device is in maintenance mode.
type NetworkDeviceInMaintenanceError struct {
	kind string
	name string
}

func NewNetworkDeviceInMaintenanceError(kind, name string) *NetworkDeviceInMaintenanceError {
	return &NetworkDeviceInMaintenanceError{
		kind: kind,
		name: name,
	}
}

func (e *NetworkDeviceInMaintenanceError) Error() string {
	return fmt.Sprintf("network fabric device %s:%s in maintenance", e.kind, e.name)
}

// NetworkDeviceNotReachableError indicates a network device is not reachable.
type NetworkDeviceNotReachableError struct {
	kind string
	name string
}

func NewNetworkDeviceNotReachableError(kind, name string) *NetworkDeviceNotReachableError {
	return &NetworkDeviceNotReachableError{
		kind: kind,
		name: name,
	}
}

func (e *NetworkDeviceNotReachableError) Error() string {
	return fmt.Sprintf("network fabric device %s:%s not reachable", e.kind, e.name)
}

// MissingSpecError indicates a configuration request missing some mandatory specs.
type MissingSpecError struct {
	what string
}

func (e *MissingSpecError) Error() string {
	return fmt.Sprintf("%s must be specified", e.what)
}

func NewMissingSpecError(what string) error {
	return &MissingSpecError{what: what}
}

// MissingResourcePoolError indicates a resource pool is not provided.
type MissingResourcePoolError struct {
	pool string
}

func (e *MissingResourcePoolError) Error() string {
	return fmt.Sprintf("%s is not configured or is exhausted", e.pool)
}

func NewMissingResourcePoolError(pool string) error {
	return &MissingResourcePoolError{pool: pool}
}
