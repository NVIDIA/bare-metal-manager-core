package internal

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"golang.org/x/crypto/ssh"
	"k8s.io/apimachinery/pkg/util/json"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	"gitlab-master.nvidia.com/forge/vpc/apis/networkfabric/v1alpha1"
	"gitlab-master.nvidia.com/forge/vpc/pkg/properties"
)

const (
	cumulusConnTimeout     = time.Second * 30
	cumulusApplyTimeout    = time.Second * 300
	cumulusDefaultNVUEPort = "8765"
)

type cumulusTransport struct {
	mutex   sync.Mutex
	user    string
	pwd     string
	sshUser string
	sshPwd  string
	ip      string
	client  *http.Client
	log     logr.Logger
}

func NewCumulusTransport(ip, user, pwd, sshUser, sshPwd string) (NetworkDeviceTransport, error) {
	c := &cumulusTransport{
		user:    user,
		pwd:     pwd,
		sshUser: sshUser,
		sshPwd:  sshPwd,
		client: &http.Client{
			Timeout: cumulusConnTimeout,
		},
		log: logf.Log.WithName("CumulusTransport:"),
	}
	c.SetMgmtIP(ip)
	if strings.ToLower(os.Getenv("DISABLE_CUMULUS_CERT_VERIFY")) == "true" {
		c.log.V(1).Info("Disabling cumulus certificate verification")
		c.client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}
	return c, nil
}

func (t *cumulusTransport) Send(req *http.Request) ([]byte, error) {
	req.SetBasicAuth(t.user, t.pwd)
	var body []byte
	if req.GetBody != nil {
		b, _ := req.GetBody()
		body, _ = ioutil.ReadAll(b)
	}
	t.log.V(1).Info("Sending https to", "URL", req.URL.String(), "Method", req.Method, "Body", string(body))
	resp, err := t.client.Do(req)
	if err != nil {
		t.log.Error(err, "Https send failed")
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	return ioutil.ReadAll(resp.Body)
}

func (t *cumulusTransport) GetMgmtIP() string {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return t.ip
}

func (t *cumulusTransport) SetMgmtIP(ip string) {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	if len(strings.Split(ip, ":")) == 1 {
		ip += ":" + cumulusDefaultNVUEPort
	}
	if t.ip != ip {
		t.ip = ip
	}
}

var (
	_                       NetworkDeviceTransport = &Cumulus{}
	_                       NetworkDevice          = &Cumulus{}
	CumulusLivenessInterval                        = time.Second * 30
)

// Ssh sends command to network device via ssh.
func (t *cumulusTransport) Ssh(cmd string) (string, error) {
	config := &ssh.ClientConfig{
		User: t.sshUser,
		Auth: []ssh.AuthMethod{
			ssh.Password(t.sshPwd),
		},
		// TODO. populate all known leaf keys
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         cumulusConnTimeout,
	}
	port := os.Getenv("SSH_PORT")
	if len(port) == 0 {
		port = "22"
	}
	ip := strings.Split(t.ip, ":")[0] + ":" + port
	t.log.V(1).Info("SSH", "Cmd", cmd, "To", ip)
	sshConn, err := ssh.Dial("tcp", ip, config)
	if err != nil {
		return "", err
	}
	defer sshConn.Close()
	sess, err := sshConn.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()
	var outBuf, errBuf bytes.Buffer
	sess.Stderr = &errBuf
	sess.Stdout = &outBuf
	if err := sess.Run(cmd); err != nil {
		t.log.V(1).Info("Ssh failed", "Error", err, "ErrBuf", errBuf.String(), "OutBuf", outBuf.String())
		return errBuf.String(), err
	}
	return outBuf.String(), nil
}

func ParseContainerID(in []byte) (string, error) {
	v := make(map[string]interface{})
	var err error
	if err = json.Unmarshal(in, &v); err != nil {
		return "", err
	}
	vv, ok := v["containers"]
	if !ok {
		return "", nil
	}
	vvv, ok := vv.([]interface{})
	if !ok {
		return "", nil
	}
	if len(vvv) == 0 {
		return "", nil
	}
	cont, ok := vvv[0].(map[string]interface{})
	if !ok {
		return "", nil
	}
	vvvv, ok := cont["id"]
	if !ok {
		return "", nil
	}
	id, ok := vvvv.(string)
	if !(ok) {
		return "", nil
	}
	return id, nil
}

func (t *cumulusTransport) GetHBNContainerID() (string, error) {
	if output, err := t.Ssh("sudo systemctl start containerd.service"); err != nil {
		t.log.Info("Failed to start containerd", "Error", err, "Output", output)
		return "", err
	}
	out, err := t.Ssh("sudo crictl ps --name=doca-hbn -o=json")
	if err != nil {
		return out, err
	}
	return ParseContainerID([]byte(out))
}

// SshHBN sends command to HBN on DPU via ssh.
func (t *cumulusTransport) SshHBN(cmd string) (string, error) {
	id, err := t.GetHBNContainerID()
	if err != nil {
		return id, err
	}
	return t.Ssh(fmt.Sprintf("sudo crictl exec %s bash -c '%s'", id, cmd))
}

type Cumulus struct {
	mutex           sync.Mutex
	executionLock   sync.Mutex
	maintenanceMode bool
	key             string
	hosts           map[string]string
	log             logr.Logger
	NetworkDeviceTransport
	desiredState          map[string]*PortRequest
	operationState        map[string]*PortRequest
	operationHostAdminIPs map[string]string
	desiredHostAdminIPs   map[string]string
	livenessCancel        context.CancelFunc
	manager               *vpcManager
	hbn                   *HBN
	pendingChanges        uint
	configRev             string
	unManaged             bool
	unManagedDone         bool
	inReconcile           bool
}

func modifyRequest(req *http.Request, params map[string]string) {
	req.Header.Add("content-type", "application/json")
	q := req.URL.Query()
	for k, v := range params {
		q.Add(k, v)
	}
	req.URL.RawQuery = q.Encode()
}

func NewCumulus(mgr *vpcManager, key string, maint bool, connectedHosts map[string]string,
	asn uint32, loopbackIP string, transport NetworkDeviceTransport) (*Cumulus, error) {
	var hbn *HBN
	if HBNConfig.HBNDevice {
		hbn = &HBN{
			NetworkDeviceTransport: transport,
			loopbackIP:             loopbackIP,
			asn:                    asn,
			manager:                mgr,
			log:                    logf.Log.WithName("HBN:" + key),
		}
	}
	return &Cumulus{
		key:                    key,
		hosts:                  connectedHosts,
		maintenanceMode:        maint,
		NetworkDeviceTransport: transport,
		log:                    logf.Log.WithName("Cumulus:" + key),
		desiredState:           make(map[string]*PortRequest),
		operationState:         make(map[string]*PortRequest),
		manager:                mgr,
		hbn:                    hbn,
	}, nil
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
		if c.livenessCancel != nil {
			c.livenessCancel()
		}
	}
	c.maintenanceMode = maint
	if !maint {
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

func (c *Cumulus) SetHostIdentifiers(hosts map[string]string) {
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

func (c *Cumulus) GetHostIdentifiers() []string {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.getHostIdentifiers()
}

func (c *Cumulus) GetPortByHostIdentifier(identifier string) string {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	port, ok := c.hosts[identifier]
	if !ok {
		return ""
	}
	return port
}

func (c *Cumulus) SetHostAdminIPs(adminIPs map[string]string, doReconcile bool) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.desiredHostAdminIPs = adminIPs
	if reflect.DeepEqual(c.desiredHostAdminIPs, c.operationHostAdminIPs) {
		return
	}
	if doReconcile && len(c.operationState) == 0 && len(c.desiredState) == 0 {
		c.operationHostAdminIPs = make(map[string]string)
		for k, v := range adminIPs {
			c.operationHostAdminIPs[k] = v
		}
		return
	}
	c.queueDevice()
}

// getHostAdminIPsChangeLocked returns complete adminIPs state that need to be changed.
func (c *Cumulus) getHostAdminIPsChangeLocked(inAdminState bool) (ret map[string]string, isDelete bool) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	ret = make(map[string]string)
	var source map[string]string
	defer func() {
		c.log.V(1).Info("TODO, remove later xxxxx: getHostAdminIPsChangeLocked", "InAddmin", inAdminState,
			"Ret", ret, "Op", c.operationHostAdminIPs, "Desired", c.desiredHostAdminIPs)
	}()
	if inAdminState {
		// adminState and op and desired are the same, no change.
		if reflect.DeepEqual(c.operationHostAdminIPs, c.desiredHostAdminIPs) {
			return
		}
		if len(c.desiredHostAdminIPs) > 0 {
			source = c.desiredHostAdminIPs
			isDelete = false
		} else {
			source = c.operationHostAdminIPs
			isDelete = true
		}
	} else {
		// Not in adminState, remove op.
		source = c.operationHostAdminIPs
		isDelete = true
	}
	for k, v := range source {
		ret[k] = v
	}
	return
}

func (c *Cumulus) updateOperationHostAdminIPsLocked(adminIPs map[string]string, inAdminState bool) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	old := c.operationHostAdminIPs
	if inAdminState && len(adminIPs) > 0 {
		c.operationHostAdminIPs = adminIPs
	} else {
		c.operationHostAdminIPs = nil
	}
	if !c.unManaged && !reflect.DeepEqual(c.operationHostAdminIPs, old) {
		c.manager.networkDevices.NotifyChange(c.key, nil)
	}
}

func (c *Cumulus) queueDevice() {
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
func (c *Cumulus) updateConfiguration(req *PortRequest, doReconcile, isDelete bool) (bool, error) {
	if doReconcile && c.inReconcile {
		c.log.Info("Update configuration, reconcile", "ManagedResource", req.Key)
		c.operationState[req.Key.String()] = req
		c.desiredState[req.Key.String()] = req
		c.operationHostAdminIPs = nil
		return true, nil
	}
	operation := c.operationState[req.Key.String()]
	desired := c.desiredState[req.Key.String()]
	// Config does not exist.
	rt := c.manager.managedResources.Get(req.Key)
	if rt == nil {
		c.log.V(1).Info("Don't know how to update unknown resource", "ManagedResource", req.Key)
		return true, nil
	}
	if isDelete {
		if operation == nil && desired == nil {
			if rt.State == BackendStateComplete {
				return true, nil
			} else if rt.State == BackendStateInit {
				operation = req
			}
		}
		if c.unManaged {
			return false, NewNetworkDeviceNotAvailableError(v1alpha1.LeafName, c.key)
		}
		c.operationState[req.Key.String()] = req
		delete(c.desiredState, req.Key.String())
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
	c.desiredState[req.Key.String()] = req
	return false, nil
}

func (c *Cumulus) UpdateConfiguration(req *PortRequest, doReconcile, isDelete bool) (bool, error) {
	c.log.V(1).Info("UpdateConfiguration called", "ManagedResource", req.Key, "doReconcile", doReconcile,
		"IsDelete", isDelete)
	c.mutex.Lock()
	defer c.mutex.Unlock()
	insync, err := c.updateConfiguration(req, doReconcile, isDelete)
	if err != nil {
		return insync, err
	}
	if !insync {
		c.queueDevice()
	}
	return insync, nil
}

// ExecuteConfiguration compares operation and desired state and sync the state.
// It returns true if the execution requires retry.
func (c *Cumulus) ExecuteConfiguration() (retry bool, fErr error) {
	// Ensure commits to cumulus is in sequence.
	c.executionLock.Lock()
	defer c.executionLock.Unlock()
	now := time.Now().Unix()
	defer func() {
		c.log.V(1).Info("ExecuteConfiguration completed in", "Second", time.Now().Unix()-now,
			"Error", fErr, "Retry", retry, "HBNState", c.hbn.GetHBNState())
	}()
	if c.IsInMaintenanceMode() {
		return false, nil
	}
	if c.unmanagedDoneLocked() {
		return false, nil
	}

	var adminIPCallback func()
	delta := make(map[bool]map[string]*PortRequest)
	oldDesiredState := make(map[string]*PortRequest)

	defer func() {
		if fErr != nil {
			return
		}
		var call func() error
		unmanaged := false
		inAdmin := false
		unmanagedDone := false
		func() {
			c.mutex.Lock()
			defer c.mutex.Unlock()
			unmanaged = c.unManaged
			inAdmin = len(c.desiredState) == 0 && len(c.operationState) == 0
			unmanagedDone = unmanaged && len(c.desiredState) == 0 && len(c.operationState) == 0
			if inAdmin {
				if unmanaged {
					call = func() error { return c.hbn.Stop(true) }
				} else {
					// resync to startup when there is no more tenant configuration; and this
					// is not a liveness probe.
					if len(delta) != 0 {
						call = func() error { return c.hbn.Connect(true) }
					}
				}
			}
		}()
		if call != nil {
			fErr = call()
		}
		changes, _ := c.getHostAdminIPsChangeLocked(inAdmin)
		if inAdmin && !unmanaged && fErr == nil && len(changes) > 0 {
			change := false
			if c.configRev, fErr = c.getRevision(""); fErr == nil {
				change, adminIPCallback, fErr = c.updateHostInAdmin(inAdmin)
				if change {
					fErr = c.applyRevision(c.configRev)
				}
			}
		}
		if unmanaged {
			if fErr == nil {
				c.setUnmanagedDoneLocked(unmanagedDone)
			}
			c.manager.networkDevices.NotifyChange(c.key, nil)
		}
		if adminIPCallback != nil && fErr == nil {
			adminIPCallback()
		}
		retry = fErr != nil
	}()
	if err := c.hbn.Connect(false); err != nil {
		c.log.Info("Failed to connect to device", "Error", err)
		return false, err
	}
	func() {
		c.mutex.Lock()
		defer c.mutex.Unlock()
		for k, v := range c.desiredState {
			oldDesiredState[k] = v
			if vv, ok := c.operationState[k]; !ok || !vv.Equal(v) {
				updates := delta[false]
				if updates == nil {
					updates = make(map[string]*PortRequest)
					delta[false] = updates
				}
				updates[k] = v
			}
		}
		for k, v := range c.operationState {
			if _, ok := c.desiredState[k]; !ok {
				removes := delta[true]
				if removes == nil {
					removes = make(map[string]*PortRequest)
					delta[true] = removes
				}
				removes[k] = v
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
			c.manager.networkDevices.NotifyChange(c.key, c.GetHostIdentifiers())
		}
		// Don't retry because ping is periodical.
		return false, err
	}

	// Notify frontend, device becomes reachable.
	if len(oldRev) == 0 {
		c.manager.networkDevices.NotifyChange(c.key, c.GetHostIdentifiers())
	}
	if len(delta) == 0 {
		return false, nil
	}

	// Delete leaf host admin state configurations if host is assigned to a tenant.
	if _, ok := delta[false]; ok {
		_, adminIPCallback, err = c.updateHostInAdmin(false)
		if err != nil {
			return true, err
		}
	}
	for isDelete, updates := range delta {
		for _, v := range updates {
			rt := c.manager.managedResources.Get(v.Key)
			if rt == nil {
				// Cannot be true ??
				c.log.Error(nil, "ManagedResource runtime not found", "ManagedResource", v.Key)
				continue
			}
			v.Update(rt)
			retry, err = c.updateOne(rt, v, &c.configRev, isDelete)
			if err != nil {
				if rt.State != BackendStateError {
					rt.State = BackendStateError
					rt.Error = err
					_ = c.manager.managedResources.Update(rt)
					c.manager.managedResources.NotifyChange(rt.Key)
				}
				return retry, err
			}
			if BackendStateModifying != rt.State {
				rt.State = BackendStateModifying
				_ = c.manager.managedResources.Update(rt)
			}
		}
	}
	// Commit config.
	err = c.applyRevision(c.configRev)

	// If no commit error, operation and desired states are in-sync.
	if err == nil {
		func() {
			c.mutex.Lock()
			defer c.mutex.Unlock()
			c.operationState = make(map[string]*PortRequest)
			// Desired state may have changed during update, use old state.
			for k, v := range oldDesiredState {
				c.operationState[k] = v
			}
		}()
	}

	// Commit successful or failed , update runtime state.
	for _, updates := range delta {
		for _, v := range updates {
			rt := c.manager.managedResources.Get(v.Key)
			if rt == nil {
				// Cannot be true ??
				continue
			}
			if err != nil {
				rt.State = BackendStateError
				rt.Error = err
			} else {
				rt.State = BackendStateComplete
				rt.Error = nil
			}
			_ = c.manager.managedResources.Update(rt)
			c.manager.managedResources.NotifyChange(rt.Key)
		}
	}
	return err != nil, err
}

// updateOne updates a single ManagedResource to the cumulus device.
func (c *Cumulus) updateOne(rt *managedResourceRuntime, config *PortRequest, rev *string, isDelete bool) (bool, error) {
	if config.NeedFabricIP {
		return false, fmt.Errorf("NATting not supported")
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
	return c.updateOne2(vlanid, vni, c.GetPortByHostIdentifier(config.Identifier), gwIP.String(), networkImpl.dhcpServer.String(), hostRoute,
		rev, config.Isolated, isDelete)
}

func (c *Cumulus) updateOne2(vlanid, vni uint32, port string, gwIP string, dhcpServer string,
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

// updateHostInAdmin updates leaf when hosts are in admin state. It returns true if there is change on device.
func (c *Cumulus) updateHostInAdmin(adminState bool) (bool, func(), error) {
	adminIPs, isDelete := c.getHostAdminIPsChangeLocked(adminState)
	c.log.V(1).Info("updateHostInAdmin", "HostAdminIPs", adminIPs, "adminState", adminState)
	if len(adminIPs) == 0 {
		return false, nil, nil
	}
	var err error
	for port, ip := range adminIPs {
		gwIP, _ := c.manager.GetAdminNetworkGW()
		dhcpServer, _ := c.manager.GetAdminDHCPServer()
		hostRoute := ""
		if len(ip) > 0 {
			hostRoute = ip + "/32"
		}
		var vlanid uint32
		if vlanid, err = c.manager.GetAdminNetworkVLan(); err != nil {
			return false, nil, err
		}
		if _, err = c.updateOne2(vlanid, 0, port, gwIP, dhcpServer, hostRoute, &c.configRev, false, isDelete); err != nil {
			return false, nil, err
		}
		if len(ip) == 0 && !isDelete {
			// Adding is nil hostRoute means deleting hostRoute in op.
			c.mutex.Lock()
			ip = c.operationHostAdminIPs[port]
			c.mutex.Unlock()
			if len(ip) > 0 {
				hostRoute = ip + "/32"
				if err = c.updateRouteFilter(0, port, hostRoute, &c.configRev, true); err != nil {
					return false, nil, err
				}
			}
		}
	}
	// Delay update admin operation state until configuring device is successful.
	return true, func() { c.updateOperationHostAdminIPsLocked(adminIPs, adminState) }, nil
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
func (c *Cumulus) Liveness(doReconcile bool) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.inReconcile = doReconcile
	if c.inReconcile {
		c.log.Info("Reconcile existing device")
		c.manager.networkDevices.NotifyChange(c.key, c.getHostIdentifiers())
	}
	c.liveness()
}

// Unmanage removes any configurations on the device as the device becomes un-managed.
func (c *Cumulus) Unmanage() error {
	if c.IsInMaintenanceMode() {
		// backdoor, allow NetworkDevice to be removed without reaching to the device.
		return nil
	}
	if c.unmanagedDoneLocked() {
		return nil
	}
	c.mutex.Lock()
	defer c.mutex.Unlock()
	hbnState := c.hbn.GetHBNState()
	if len(c.operationState) == 0 && (hbnState == HBNInvalid || hbnState == HBNInit) {
		return nil
	}

	if !c.isReachable() {
		return NewNetworkDeviceNotReachableError(v1alpha1.LeafName, c.key)
	}

	if c.livenessCancel != nil {
		c.livenessCancel()
		c.livenessCancel = nil
	}
	alreadyUnmanaged := c.unManaged
	c.desiredState = nil
	c.unManaged = true
	if !alreadyUnmanaged {
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
	if c.inReconcile {
		return true
	}
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
	dhcpServer := ""
	var adminIPs map[string]string
	if len(c.operationHostAdminIPs) > 0 {
		dhcpServer, _ = c.manager.GetAdminDHCPServer()
		adminIPs = make(map[string]string)
		for k, v := range c.operationHostAdminIPs {
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

func (c *Cumulus) setUnmanagedDoneLocked(val bool) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.unManagedDone = val
}

func (c *Cumulus) unmanagedDoneLocked() bool {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	return c.unManagedDone
}

func (c *Cumulus) handleResponse(resp []byte) (map[string]interface{}, error) {
	ret := make(map[string]interface{})
	if err := json.Unmarshal(resp, &ret); err != nil {
		c.log.Error(err, "Failed to unmarshal response", "Out", string(resp))
		return nil, err
	}
	if status, ok := ret["status"]; ok {
		if status.(int64) != 200 {
			c.log.Error(nil, "Response not OK", "Response", ret)
			return nil, fmt.Errorf("response not OK")
		}
	}
	c.log.V(1).Info("Response is ", "Response", ret)
	return ret, nil
}

func (c *Cumulus) sendAndGetResponse(method, uri string, body []byte, rev *string) (map[string]interface{}, []byte, error) {
	var buf io.Reader = nil
	if body != nil {
		buf = bytes.NewReader(body)
	}
	req, _ := http.NewRequest(method, uri, buf)
	if rev != nil {
		modifyRequest(req, map[string]string{"rev": *rev})
	} else {
		modifyRequest(req, map[string]string{})
	}
	out, err := c.Send(req)
	if err != nil {
		return nil, nil, err
	}
	resp, err := c.handleResponse(out)
	if err != nil {
		c.log.Error(err, "Send receives errored response")
		return nil, nil, err
	}
	return resp, out, nil
}

func (c *Cumulus) sendContentAndGetResponse(method, uri string, body interface{}, rev *string) (map[string]interface{}, []byte, error) {
	in, err := json.Marshal(body)
	if err != nil {
		return nil, nil, err
	}
	return c.sendAndGetResponse(method, uri, in, rev)
}
