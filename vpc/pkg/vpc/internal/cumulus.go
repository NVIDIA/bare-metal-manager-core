package internal

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/go-logr/logr"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"gitlab-master.nvidia.com/forge/vpc/apis/networkfabric/v1alpha1"
	"gitlab-master.nvidia.com/forge/vpc/pkg/properties"
)

var (
	_                       NetworkDeviceTransport = &Cumulus{}
	_                       NetworkDevice          = &Cumulus{}
	CumulusLivenessInterval                        = time.Second * 30
	reconcileConfRev                               = "dummy"
)

type Cumulus struct {
	mutex           sync.Mutex
	executionLock   sync.Mutex
	maintenanceMode bool
	key             string
	hosts           map[string]string
	log             logr.Logger
	NetworkDeviceTransport
	desiredState                  map[string]ConfigurationRequest
	operationState                map[string]ConfigurationRequest
	desiredHostAdminState         map[string]ConfigurationRequest
	operationHostAdminState       map[string]ConfigurationRequest
	hostAdminIPsBackendState      ConfigurationBackendState
	hostAdminIPsBackendStateError error
	livenessCancel                context.CancelFunc
	manager                       *vpcManager
	hbn                           *HBN
	pendingChanges                uint
	configRev                     string
	unManaged                     bool
	unManagedDone                 bool
	inReconcile                   bool
	forcedConnect                 bool
	saveConfig                    bool
}

func NewCumulus(mgr *vpcManager, key string, maint bool, connectedHosts map[string]string,
	asn uint32, loopbackIP string, transport NetworkDeviceTransport) (*Cumulus, error) {
	var hbn *HBN
	log := logf.Log.WithName("Cumulus:" + key)
	if _, ok := transport.(*cumulusTransport); ok {
		transport.SetLogger(log.WithName("Transport"))
	}
	if HBNConfig.HBNDevice {
		hbn = &HBN{
			NetworkDeviceTransport: transport,
			loopbackIP:             loopbackIP,
			asn:                    asn,
			manager:                mgr,
			log:                    log.WithName("HBN"),
		}
	}
	return &Cumulus{
		key:                     key,
		hosts:                   connectedHosts,
		maintenanceMode:         maint,
		NetworkDeviceTransport:  transport,
		log:                     log,
		desiredState:            make(map[string]ConfigurationRequest),
		operationState:          make(map[string]ConfigurationRequest),
		desiredHostAdminState:   make(map[string]ConfigurationRequest),
		operationHostAdminState: make(map[string]ConfigurationRequest),
		manager:                 mgr,
		hbn:                     hbn,
	}, nil
}

type deltaType struct {
	old ConfigurationRequest
	new ConfigurationRequest
}

func (c *Cumulus) Key() string {
	// c.mutex.Lock()
	// defer c.mutex.Unlock()
	return c.key
}

// SetMaintenanceMode changes maintenance mode and if device comes out of maintenance,
// queue to re-sync device state.
func (c *Cumulus) SetMaintenanceMode(maint bool) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if c.maintenanceMode == maint {
		return
	}
	if maint {
		// if a config exists on both operational and desired state,
		// remove from operational to allow re-sync later.
		for k := range c.operationState {
			if _, ok := c.desiredState[k]; ok {
				delete(c.operationState, k)
			}
		}
		for k := range c.operationHostAdminState {
			if _, ok := c.desiredHostAdminState[k]; ok {
				delete(c.operationHostAdminState, k)
			}
		}

		if c.livenessCancel != nil {
			c.livenessCancel()
			c.livenessCancel = nil
		}
	}
	c.maintenanceMode = maint
	if !maint {
		c.forcedConnect = true
		c.liveness()
		c.queueDevice()
	}
	// Notify frontend, device is now in maintenance mod.
	c.manager.networkDevices.NotifyChange(c.key, c.getHostIdentifiers())
}

func (c *Cumulus) IsInMaintenanceMode() bool {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.maintenanceMode
}

func (c *Cumulus) SetNICIdentifiers(hosts map[string]string) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.hosts = hosts
}

func (c *Cumulus) getHostIdentifiers() []string {
	ret := make([]string, 0, len(c.hosts))
	for k := range c.hosts {
		ret = append(ret, k)
	}
	return ret
}

func (c *Cumulus) GetNICIdentifiers() []string {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.getHostIdentifiers()
}

func (c *Cumulus) getPortByNICIdentifier(identifier string) string {
	port, ok := c.hosts[identifier]
	if !ok {
		return ""
	}
	return port
}

func (c *Cumulus) GetPortByNICIdentifier(identifier string) string {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.getPortByNICIdentifier(identifier)
}

func (c *Cumulus) queueDevice() {
	if c.livenessCancel == nil && !c.unManaged {
		c.log.V(1).Info("Device has not started, ignore device queuing")
	}
	c.pendingChanges++
	// queue config to be sent. A delay allows multiple configurations be sent at the same time.
	if c.pendingChanges == 1 {
		go func() {
			<-time.After(time.Second * 1)
			c.manager.networkDevices.Add(c, false)
		}()
	}
}

// UpdateConfiguration updates desired state and returns true if device's desired and operation states
// are in sync with respect to the incoming request.
func (c *Cumulus) updateConfiguration(req ConfigurationRequest, hostAdmin, doReconcile, isDelete bool) (bool, error) {
	c.log.V(1).Info("UpdateConfiguration called", "Configuration", req.Key(),
		"hostAdmin", hostAdmin, "doReconcile", doReconcile,
		"IsDelete", isDelete)
	if doReconcile && c.inReconcile {
		c.log.Info("Update configuration, reconcile", "Configuration", req.Key())
		if hostAdmin {
			c.desiredHostAdminState[req.Key()] = req
			if len(c.desiredState) == 0 {
				c.operationHostAdminState[req.Key()] = req
			}
		} else {
			c.operationState[req.Key()] = req
			c.desiredState[req.Key()] = req
			c.operationHostAdminState = nil
		}
		_ = req.SetBackendState(c.manager, BackendStateComplete, nil, false)
		return true, nil
	}
	operationState := c.operationState
	desiredState := c.desiredState
	if hostAdmin {
		operationState = c.operationHostAdminState
		desiredState = c.desiredHostAdminState
	}
	operation := operationState[req.Key()]
	desired := desiredState[req.Key()]

	// Config does not exist.
	state, _ := req.GetBackendState(c.manager)
	if state == BackendStateUnknown {
		c.log.V(1).Info("Don't know how to update unknown configuration", "Configuration", req.Key())
		return true, nil
	}
	if isDelete {
		if operation == nil && desired == nil {
			if state == BackendStateInit && c.inReconcile {
				// Asked to remove some unknown config, it is possible processes restarted while
				// this config is removed.
				operation = req
			} else {
				return true, nil
			}
		}
		if c.unManaged {
			// Network device is not under VPC control anymore.
			return false, NewNetworkDeviceNotAvailableError(v1alpha1.LeafName, c.key)
		}
		delete(desiredState, req.Key())
		if operation == nil {
			return true, nil
		}
		return false, nil
	}

	// config is already in place.
	if operation != nil && operation.Equal(req) {
		return true, nil
	}

	if c.unManaged {
		return false, NewNetworkDeviceNotAvailableError(v1alpha1.LeafName, c.key)
	}

	c.log.V(1).Info("Update configuration", "Current", operation, "Desired", req)
	desiredState[req.Key()] = req
	return false, nil
}

func (c *Cumulus) UpdateConfigurations(reqs []ConfigurationRequest, hostAdmin, doReconcile, isDelete bool) (bool, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	insync := true
	for _, req := range reqs {
		syn, err := c.updateConfiguration(req, hostAdmin, doReconcile, isDelete)
		if err != nil {
			return syn, err
		}
		insync = insync && syn
	}
	if !insync {
		c.queueDevice()
	}
	return insync, nil
}

// ExecuteConfiguration compares operation and desired state and sync the state.
// It returns true if the execution requires retry.
func (c *Cumulus) ExecuteConfiguration() (retry bool, fErr error) {
	if c.IsInMaintenanceMode() {
		return false, nil
	}
	if c.IsUnmanagedDone() {
		return false, nil
	}
	// Ensure commits to cumulus is in sequence.
	c.executionLock.Lock()
	defer c.executionLock.Unlock()
	now := time.Now().Unix()
	defer func() {
		var opkeys, desirekeys, opadmkeys, desireadmkeys []string
		for k := range c.operationState {
			opkeys = append(opkeys, k)
		}
		for k := range c.desiredState {
			desirekeys = append(desirekeys, k)
		}
		for k := range c.operationHostAdminState {
			opadmkeys = append(opadmkeys, k)
		}
		for k := range c.desiredHostAdminState {
			desireadmkeys = append(desireadmkeys, k)
		}
		c.log.V(1).Info("ExecuteConfiguration completed in", "Second", time.Now().Unix()-now,
			"Error", fErr, "Retry", retry, "HBNState", c.hbn.GetHBNState(), "Operations", opkeys,
			"Desired", desirekeys, "HostAdminOperation", opadmkeys, "HostAdminDesired", desireadmkeys)
	}()
	defer func() {
		c.mutex.Lock()
		defer c.mutex.Unlock()
		// Handle unmanaged
		if fErr == nil {
			if c.unManaged && !c.hasConfigurations() && !c.hasHostAdminConfigurations() {
				if fErr = c.hbn.Stop(true); fErr != nil {
					retry = true
					return
				}
				c.unManagedDone = true
				c.manager.networkDevices.NotifyChange(c.key, nil)
			}
			if c.forcedConnect {
				c.queueDevice()
			}
		}
		if c.saveConfig {
			if c.hbn.Save() == nil {
				c.saveConfig = false
			}
		}
	}()
	delta := make(map[bool]map[string]deltaType)
	oldDesiredState := make(map[string]ConfigurationRequest)
	oldDesiredHostAdminState := make(map[string]ConfigurationRequest)

	if c.hbn.GetHBNState() == HBNStopping && c.hbn.GetError() != nil {
		// Stop HBN failed, retry.
		return false, nil
	}

	if err := c.hbn.Connect(c.forcedConnect); err != nil {
		c.log.Info("Failed to connect to device", "Error", err)
		return false, err
	}
	c.forcedConnect = false

	/*
	   Desired  Op   AdminDesired AdminOp  |   delta              retry
	     Y      N/A     N/A        Y       |   Admin,Resource      N      <- host just assigned
	     Y      N/A     N/A        N       |   Resource            N      <- host is assigned
	     N      Y       N/A        N/A     |   Resource            Y      <- host just unassigned
	     N      N       N/A        N/A     |   Admin               N      <- host is unassigned
	     N      N/A     N          N/A     |   Admin or Resource   N      <- host is unmanaged
	*/
	// Compute and store configuration changes to delta, and store current desiredState to oldDesired.
	computeDelta := func(oldDesired, operation, desired map[string]ConfigurationRequest) {
		for k, v := range desired {
			oldDesired[k] = v
			if vv, ok := operation[k]; !ok || !vv.Equal(v) {
				updates := delta[false]
				if updates == nil {
					updates = make(map[string]deltaType)
					delta[false] = updates
				}
				updates[k] = deltaType{
					old: vv,
					new: v,
				}
			}
		}
		for k, v := range operation {
			if _, ok := desired[k]; !ok {
				removes := delta[true]
				if removes == nil {
					removes = make(map[string]deltaType)
					delta[true] = removes
				}
				removes[k] = deltaType{old: v}
			}
		}
	}
	func() {
		c.mutex.Lock()
		defer c.mutex.Unlock()
		if c.unManaged {
			computeDelta(oldDesiredState, c.operationState, c.desiredState)
			computeDelta(oldDesiredHostAdminState, c.operationHostAdminState, c.desiredHostAdminState)
		} else {
			if c.hasConfigurations() {
				computeDelta(oldDesiredState, c.operationState, c.desiredState)
				// host is just unassigned, add hostAdmin in next iteration.
				c.forcedConnect = len(c.desiredState) == 0
			} else {
				computeDelta(oldDesiredHostAdminState, c.operationHostAdminState, c.desiredHostAdminState)
			}
			if len(c.desiredState) > 0 && len(c.operationHostAdminState) > 0 {
				// host is just assigned, remove hostAdmin config
				computeDelta(oldDesiredHostAdminState, c.operationHostAdminState, nil)
			}
		}
		c.pendingChanges = 0
	}()

	rev := ""
	if len(delta) == 0 {
		rev = emptyRevision
	}
	oldRev := c.configRev
	var err error
	c.configRev, err = c.getRevision(rev)
	if err != nil {
		c.log.V(1).Info("Failed to ping device", "Error", err)
		// Notify frontend, device becomes unreachable.
		if len(oldRev) > 0 {
			c.manager.networkDevices.NotifyChange(c.key, c.GetNICIdentifiers())
		}
		// Don't retry because ping is periodical.
		return false, err
	}

	// Notify frontend, device becomes reachable.
	if len(oldRev) == 0 || oldRev == reconcileConfRev {
		c.manager.networkDevices.NotifyChange(c.key, c.GetNICIdentifiers())
	}
	if len(delta) == 0 {
		return false, nil
	}

	for isDelete, updates := range delta {
		for _, change := range updates {
			var configv ConfigurationRequest
			if change.old != nil {
				configv = change.old
			} else {
				configv = change.new
			}
			switch configv.(type) {
			case *PortRequest:
				retry, err = c.updatePortConfig(change, &c.configRev, isDelete)
			case *NetworkPolicyRules:
				retry, err = c.updateNetworkPolicyConfig(change, &c.configRev, isDelete)
			case *HostAdminRequest:
				retry, err = c.updateHostInAdmin(change, &c.configRev, isDelete)
			default:
				c.log.Error(nil, "Unknown config request type")
			}

			if err != nil {
				_ = configv.SetBackendState(c.manager, BackendStateError, err, true)
				return retry, err
			}
			_ = configv.SetBackendState(c.manager, BackendStateModifying, err, false)
		}
	}
	// Commit config.
	err = c.applyRevision(c.configRev)

	// If no commit error, operation and desired states are in-sync.
	if err == nil {
		func() {
			c.mutex.Lock()
			defer c.mutex.Unlock()
			c.operationState = make(map[string]ConfigurationRequest)
			// Desired state may have changed during update, use old state.
			for k, v := range oldDesiredState {
				c.operationState[k] = v
			}
			c.operationHostAdminState = make(map[string]ConfigurationRequest)
			for k, v := range oldDesiredHostAdminState {
				c.operationHostAdminState[k] = v
			}
			c.saveConfig = true
		}()
	}

	// Commit successful or failed , update runtime state.
	state := BackendStateError
	for isDelete, updates := range delta {
		if err == nil {
			if isDelete {
				state = BackendStateDeleted
			} else {
				state = BackendStateComplete
			}
		}
		for _, change := range updates {
			var configv ConfigurationRequest
			if change.old != nil {
				configv = change.old
			} else {
				configv = change.new
			}
			_ = configv.SetBackendState(c.manager, state, err, true)
		}
	}
	return retry || err != nil, err
}

// updatePortConfig updates a single ManagedResource to the cumulus device.
func (c *Cumulus) updatePortConfig(change deltaType, rev *string, isDelete bool) (bool, error) {
	var config, old *PortRequest
	if isDelete {
		config = change.old.(*PortRequest)
	} else {
		config = change.new.(*PortRequest)
		old, _ = change.old.(*PortRequest)
	}
	c.log.V(1).Info("updatePortConfig", "PortConfig", config, "Old", old, "IsDelete", isDelete)
	if old != nil {
		if retry, err := c.updatePortConfig1(old, rev, true); err != nil {
			return retry, err
		}
	}
	return c.updatePortConfig1(config, rev, isDelete)
}

func (c *Cumulus) updatePortConfig1(config *PortRequest, rev *string, isDelete bool) (bool, error) {
	rt := c.manager.managedResources.Get(config.name)
	if rt == nil {
		// Cannot be true ??
		c.log.Error(nil, "ManagedResource runtime not found", "ManagedResource", config.name)
		return true, nil
	}
	if !isDelete {
		config.Update(rt)
		if config.NeedFabricIP {
			return false, fmt.Errorf("NATting not supported")
		}
	}
	hostRoute := ""
	if config.HostIP != nil {
		hostRoute = config.HostIP.String() + "/32"
	}
	networkImpl := rt.NetworkImpl.(*FabricOverlayNetworkImplementation)
	vni := networkImpl.vni
	vlanid := networkImpl.vlan
	gwIP := &net.IPNet{
		IP:   networkImpl.gateway.To4(),
		Mask: networkImpl.network.Mask,
	}
	if config.Isolated {
		// Hack, use the last IP in the range.
		ip := net.IP{0, 0, 0, 0}
		for i := range gwIP.IP {
			ip[i] = gwIP.IP[i] | ^gwIP.Mask[i]
		}
		ip[len(ip)-1] -= 1
		gwIP.IP = ip
		gwIP.Mask = net.CIDRMask(32, 32)
	}
	return c.updatePortConfig2(vlanid, vni, c.GetPortByNICIdentifier(config.Identifier), gwIP.String(), networkImpl.dhcpServer.String(), hostRoute,
		rev, config.Isolated, isDelete)
}

func (c *Cumulus) updateHostInAdmin(change deltaType, rev *string, isDelete bool) (bool, error) {
	var config, old *HostAdminRequest
	if isDelete {
		config = change.old.(*HostAdminRequest)
	} else {
		config = change.new.(*HostAdminRequest)
		old, _ = change.old.(*HostAdminRequest)
	}
	c.log.V(1).Info("updateHostInAdmin", "HostAdminRequest", config, "Old", old, "IsDelete", isDelete)
	cur := config
	if old != nil {
		cur = old
		isDelete = true
	}
	for {
		for port, ip := range cur.hostAdminIPs {
			gwIP, _ := c.manager.GetAdminNetworkGW()
			dhcpServer, _ := c.manager.GetAdminDHCPServer()
			hostRoute := ""
			if len(ip) > 0 {
				hostRoute = ip + "/32"
			}
			vlanid, err := c.manager.GetAdminNetworkVLan()
			if err != nil {
				return false, err
			}
			if retry, err := c.updatePortConfig2(vlanid, 0, port, gwIP, dhcpServer, hostRoute, rev, false, isDelete); err != nil {
				return retry, err
			}
		}
		if old != nil && old == cur {
			cur = config
			isDelete = false
		} else {
			break
		}
	}
	return false, nil
}

// updateNetworkPolicyConfig updates NetworkPolicy on a single ManagedResource or leaf to the cumulus device.
func (c *Cumulus) updateNetworkPolicyConfig(change deltaType, rev *string, isDelete bool) (bool, error) {
	var config, old *NetworkPolicyRules
	if isDelete {
		config = change.old.(*NetworkPolicyRules)
	} else {
		config = change.new.(*NetworkPolicyRules)
		old, _ = change.old.(*NetworkPolicyRules)
	}
	c.log.V(1).Info("updateNetworkPolicyConfig", "NetworkPolicy", config, "Old", old, "IsDelete", isDelete)
	if old != nil {
		if err := c.updateACL(old, rev, true); err != nil {
			return true, err
		}
	}
	if err := c.updateACL(config, rev, isDelete); err != nil {
		return true, err
	}
	return false, nil
}

func (c *Cumulus) updatePortConfig2(vlanid, vni uint32, port string, gwIP string, dhcpServer string,
	hostRoute string, rev *string, isIsolated, isDelete bool) (bool, error) {
	if retry, err := c.updateInterface(vlanid, vni, port, gwIP, rev, isDelete); err != nil {
		return retry, err
	}
	if err := c.updateDHCPRelayAgent(vlanid, port, dhcpServer, rev, isDelete); err != nil {
		return true, err
	}
	if len(hostRoute) == 0 {
		c.log.V(1).Info("Route filter configuration is no-op because there is no IP to advertise")
		return false, nil
	}
	if err := c.updateRouteFilter(vlanid, port, hostRoute, rev, isDelete || isIsolated); err != nil {
		return true, err
	}
	return false, nil
}

func (c *Cumulus) SetReconcile(reconcile bool) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.inReconcile = reconcile
	if c.inReconcile {
		c.log.Info("Reconcile with existing device")
		// Assume device is in good standing.
		c.hbn.SetHBNState(HBNConnected)
		c.configRev = reconcileConfRev
	}
}

func (c *Cumulus) liveness() {
	if c.maintenanceMode {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		c.log.V(1).Info("Liveness probe starts")
		tick := time.NewTicker(CumulusLivenessInterval)
		if !c.inReconcile {
			// Allow time to reconcile resources already created.
			c.manager.networkDevices.Add(c, false)
		}
		for {
			select {
			case <-ctx.Done():
				tick.Stop()
				c.log.V(1).Info("Exit liveness probe.")
				return
			case <-tick.C:
				c.inReconcile = false
				c.manager.networkDevices.Add(c, false)
			}
		}
	}()
	c.livenessCancel = cancel
}

// Liveness probes device liveness.
func (c *Cumulus) Liveness() {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if c.inReconcile {
		// Trigger front-end to add configurations to this device.
		c.manager.networkDevices.NotifyChange(c.key, c.getHostIdentifiers())
	}
	c.liveness()
}

// Unmanage removes any configurations on the device as the device becomes un-managed.
func (c *Cumulus) Unmanage() error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if c.unManagedDone {
		return nil
	}
	if c.maintenanceMode {
		return nil
	}
	if !c.isReachable() && c.unManaged {
		// Try to unmanaged device again, maybe now device is up.
		c.unManaged = false
	}

	c.desiredState = nil
	c.desiredHostAdminState = nil
	if c.livenessCancel != nil {
		c.livenessCancel()
		c.livenessCancel = nil
	}
	if !c.unManaged {
		c.unManaged = true
		c.queueDevice()
	}
	return NewBackendConfigurationInProgress("Fabric", v1alpha1.LeafName, c.key)
}

func (c *Cumulus) IsReachable() bool {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.isReachable()
}

func (c *Cumulus) isReachable() bool {
	hbnState := c.hbn.GetHBNState()
	return !c.maintenanceMode && (hbnState == HBNConnected || hbnState == HBNInvalid) && len(c.configRev) > 0
}

func (c *Cumulus) IsUnmanaged() bool {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.unManaged
}

// GetProperties returns networkDevice Properties
func (c *Cumulus) GetProperties() (*properties.NetworkDeviceProperties, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if c.hbn == nil {
		return &properties.NetworkDeviceProperties{
			Alive: c.isReachable(),
		}, nil
	}
	i := c.operationHostAdminState[(&HostAdminRequest{deviceName: c.key}).Key()]
	hostAdmin, _ := i.(*HostAdminRequest)
	state := BackendStateUnknown
	if hostAdmin != nil {
		state, _ = hostAdmin.GetBackendState(c.manager)
	}
	if state != BackendStateComplete {
		return &properties.NetworkDeviceProperties{
			LoopbackIP: c.hbn.loopbackIP,
			ASN:        c.hbn.asn,
			Alive:      c.isReachable(),
		}, nil
	}
	var adminIPs map[string]string
	dhcpServer := ""
	if len(hostAdmin.hostAdminIPs) > 0 {
		dhcpServer, _ = c.manager.GetAdminDHCPServer()
		adminIPs = make(map[string]string)
		for k, v := range hostAdmin.hostAdminIPs {
			adminIPs[k] = v
		}
	}
	return &properties.NetworkDeviceProperties{
		LoopbackIP:      c.hbn.loopbackIP,
		ASN:             c.hbn.asn,
		Alive:           c.isReachable(),
		AdminDHCPServer: dhcpServer,
		AdminHostIPs:    adminIPs,
	}, c.hbn.GetError()
}

func (c *Cumulus) IsUnmanagedDone() bool {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.unManagedDone
}

func (c *Cumulus) hasConfigurations() bool {
	return len(c.operationState) > 0 || len(c.desiredState) > 0
}

func (c *Cumulus) hasHostAdminConfigurations() bool {
	return len(c.operationHostAdminState) > 0 || len(c.desiredHostAdminState) > 0
}

func (c *Cumulus) getHostAdminIPsBackendState() (ConfigurationBackendState, error) {
	if c.hasConfigurations() {
		return BackendStateInit, nil
	}
	return c.hostAdminIPsBackendState, c.hostAdminIPsBackendStateError
}

func (c *Cumulus) sethostAdminIPsBackendState(s ConfigurationBackendState, err error) error {
	c.hostAdminIPsBackendState = s
	c.hostAdminIPsBackendStateError = err
	return nil
}

func (c *Cumulus) portInUseWithLock(port string) bool {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	var ll []ConfigurationRequest
	for _, i := range c.desiredState {
		ll = append(ll, i)
	}
	for _, i := range c.desiredHostAdminState {
		ll = append(ll, i)
	}
	for _, i := range ll {
		if portReq, ok := i.(*PortRequest); ok {
			if c.getPortByNICIdentifier(portReq.Identifier) == port {
				return true
			}
		} else if admIP, ok := i.(*HostAdminRequest); ok {
			for oport := range admIP.hostAdminIPs {
				if oport == port {
					return true
				}

			}
		}
	}
	return false
}

func (c *Cumulus) aclInUseWithLock(rules *NetworkPolicyRules) (aclInUse bool, samePort bool) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	var ll []ConfigurationRequest
	for _, i := range c.desiredState {
		ll = append(ll, i)
	}
	for _, i := range c.desiredHostAdminState {
		ll = append(ll, i)
	}
	for _, i := range ll {
		req, ok := i.(*NetworkPolicyRules)
		if !ok {
			continue
		}
		if req.ResourceName == rules.ResourceName && req.ResourceKind == rules.ResourceKind &&
			req.Key() == rules.Key() {
			// ignore self.
			continue
		}
		// multiple resources use the same NetworkPolicy.
		if req.Key() == rules.Key() {
			aclInUse = true
			if req.DevicePort == rules.DevicePort {
				samePort = true
				break
			}
		}
	}
	return aclInUse, samePort
}
