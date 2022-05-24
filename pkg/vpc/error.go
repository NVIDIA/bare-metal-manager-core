package vpc

import (
	"time"

	"gitlab-master.nvidia.com/forge/vpc/pkg/vpc/internal"
)

var (
	NewNetworkDeviceNotAvailableError     = internal.NewNetworkDeviceNotAvailableError
	NewNewNetworkDeviceInMaintenanceError = internal.NewNetworkDeviceInMaintenanceError
)

func IsNetworkDeviceNotAvailableError(err error) bool {
	_, ok := err.(*internal.NetworkDeviceNotAvailableError)
	return ok
}

func IsNetworkDeviceInMaintenanceError(err error) bool {
	_, ok := err.(*internal.NetworkDeviceInMaintenanceError)
	return ok
}

func IsAlreadyExistError(err error) bool {
	_, ok := err.(*internal.AlreadyExistError)
	return ok
}

func IgnoreNetworkDeviceNotAvailableError(err error) error {
	if IsNetworkDeviceNotAvailableError(err) || IsNetworkDeviceInMaintenanceError(err) {
		return nil
	}
	return err
}

// GetErrorNextPollAfter returns next polling time after err.
func GetErrorNextPollAfter(err error) (*time.Duration, error) {
	switch err.(type) {
	case *internal.UnknownResourceGroupError:
		return nil, nil
	case *internal.AlreadyExistError:
		return nil, nil
	case *internal.NetworkDeviceNotAvailableError:
		return nil, nil
	case *internal.NetworkDeviceInMaintenanceError:
		return nil, nil
	case *internal.NetworkDeviceNotReachableError:
		return nil, nil
	case *internal.MissingSpecError:
		return nil, nil
	case *internal.BackendConfigurationInProgress:
		return nil, nil
	case *internal.MissingResourcePoolError:
		return nil, nil
	}
	return nil, err
}
