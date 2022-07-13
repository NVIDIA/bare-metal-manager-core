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
	defer func() { _ = sshConn.Close() }()
	sess, err := sshConn.NewSession()
	if err != nil {
		return "", err
	}
	defer func() { _ = sess.Close() }()
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
	desiredState            map[string]ConfigurationRequest
	operationState          map[string]ConfigurationRequest
	desiredHostAdminState   map[string]ConfigurationRequest
	operationHostAdminState map[string]ConfigurationRequest
	// TODO consolidate to xxHostAdminState
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
		key:                     key,
		hosts:                   connectedHosts,
		maintenanceMode:         maint,
		NetworkDeviceTransport:  transport,
		log:                     logf.Log.WithName("Cumulus:" + key),
		desiredState:            make(map[string]ConfigurationRequest),
		operationState:          make(map[string]ConfigurationRequest),
		desiredHostAdminState:   make(map[string]ConfigurationRequest),
		operationHostAdminState: make(map[string]ConfigurationRequest),
		manager:                 mgr,
		hbn:                     hbn,
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

func (c *Cumulus) GetPortByNICIdentifier(identifier string) string {
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
	if doReconcile && !c.hasConfigurations() {
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
			c.operationHostAdminIPs = nil
			c.operationHostAdminState = nil
		}
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
		operationState[req.Key()] = req
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
		sync, err := c.updateConfiguration(req, hostAdmin, doReconcile, isDelete)
		if err != nil {
			return sync, err
		}
		insync = insync && sync
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
		c.mutex.Lock()
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
		c.mutex.Unlock()

		c.log.V(1).Info("ExecuteConfiguration completed in", "Second", time.Now().Unix()-now,
			"Error", fErr, "Retry", retry, "HBNState", c.hbn.GetHBNState(), "Operations", opkeys,
			"Desired", desirekeys, "HostAdminOperation", opadmkeys, "HostAdminDesired", desireadmkeys)
	}()
	if c.IsInMaintenanceMode() {
		return false, nil
	}
	if c.unmanagedDoneLocked() {
		return false, nil
	}

	var adminIPCallback func()
	delta := make(map[bool]map[string]ConfigurationRequest)
	oldDesiredState := make(map[string]ConfigurationRequest)
	oldDesiredHostAdminState := make(map[string]ConfigurationRequest)

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
			inAdmin = !c.hasConfigurations()
			unmanagedDone = unmanaged && !c.hasConfigurations() && !c.hasHostAdminConfigurations()
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
		if inAdmin && !unmanaged && fErr == nil {
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

	// Compute and store configuration changes to delta, and store current desiredState to oldDesired.
	computeDelta := func(oldDesired, operation, desired map[string]ConfigurationRequest) {
		for k, v := range desired {
			oldDesired[k] = v
			if vv, ok := operation[k]; !ok || !vv.Equal(v) {
				updates := delta[false]
				if updates == nil {
					updates = make(map[string]ConfigurationRequest)
					delta[false] = updates
				}
				updates[k] = v
			}
		}
		for k, v := range operation {
			if _, ok := desired[k]; !ok {
				removes := delta[true]
				if removes == nil {
					removes = make(map[string]ConfigurationRequest)
					delta[true] = removes
				}
				removes[k] = v
			}
		}
	}
	func() {
		c.mutex.Lock()
		defer c.mutex.Unlock()
		computeDelta(oldDesiredState, c.operationState, c.desiredState)
		if len(c.desiredState) == 0 {
			// add hostAdmin configurations
			computeDelta(oldDesiredHostAdminState, c.operationHostAdminState, c.desiredHostAdminState)
		} else {
			// remove hostAdmin configurations
			computeDelta(oldDesiredHostAdminState, c.operationHostAdminState, nil)
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
	if len(oldRev) == 0 {
		c.manager.networkDevices.NotifyChange(c.key, c.GetNICIdentifiers())
	}
	if len(delta) == 0 {
		return false, nil
	}

	// Delete leaf host admin state configurations if host is assigned to a tenant.
	_, adminIPCallback, err = c.updateHostInAdmin(!c.hasConfigurations())
	if err != nil {
		return true, err
	}
	for isDelete, updates := range delta {
		for _, v := range updates {
			switch vv := v.(type) {
			case *PortRequest:
				retry, err = c.updatePortConfig(vv, &c.configRev, isDelete)
			case *NetworkPolicyRules:
				retry, err = c.updateNetworkPolicyConfig(vv, &c.configRev, isDelete)
			default:
				c.log.Error(nil, "Unknown config request type")
			}
			if err != nil {
				v.SetBackendState(c.manager, BackendStateError, err, true)
				return retry, err
			}
			v.SetBackendState(c.manager, BackendStateModifying, err, false)
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
		for _, v := range updates {
			v.SetBackendState(c.manager, state, err, true)
		}
	}
	return err != nil, err
}

// updatePortConfig updates a single ManagedResource to the cumulus device.
func (c *Cumulus) updatePortConfig(config *PortRequest, rev *string, isDelete bool) (bool, error) {
	rt := c.manager.managedResources.Get(config.name)
	if rt == nil {
		// Cannot be true ??
		c.log.Error(nil, "ManagedResource runtime not found", "ManagedResource", config.name)
		return true, nil
	}
	config.Update(rt)

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
	return c.updatePortConfig2(vlanid, vni, c.GetPortByNICIdentifier(config.Identifier), gwIP.String(), networkImpl.dhcpServer.String(), hostRoute,
		rev, config.Isolated, isDelete)
}

// updateNetworkPolicyConfig updates NetworkPolicy on a single ManagedResource or leaf to the cumulus device.
func (c *Cumulus) updateNetworkPolicyConfig(config *NetworkPolicyRules, rev *string, isDelete bool) (bool, error) {
	c.log.V(1).Info("updateNetworkPolicyConfig", "NetworkPolicy", config, "IsDelete", isDelete)
	// TODO test only
	method := http.MethodPost
	if isDelete {
		method = http.MethodDelete
	}
	url := c.getBaseURI() + "network-policy/" + config.ResourceKind + "/" + config.ResourceName
	if _, _, err := c.sendContentAndGetResponse(method, url, config, rev); err != nil {
		return false, err
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
		if _, err = c.updatePortConfig2(vlanid, 0, port, gwIP, dhcpServer, hostRoute, &c.configRev, false, isDelete); err != nil {
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
		c.log.Info("Reconcile with existing device")
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
	if !c.hasConfigurations() && !c.hasHostAdminConfigurations() && (hbnState == HBNInvalid || hbnState == HBNInit) {
		return nil
	}

	if !c.isReachable() {
		return NewNetworkDeviceNotReachableError(v1alpha1.LeafName, c.key)
	}

	if c.livenessCancel != nil {
		c.livenessCancel()
		c.livenessCancel = nil
	}
	c.desiredState = nil
	c.desiredHostAdminState = nil
	if !c.unManaged {
		c.queueDevice()
	}
	c.unManaged = true

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

func (c *Cumulus) hasConfigurations() bool {
	return len(c.operationState) > 0 || len(c.desiredState) > 0
}

func (c *Cumulus) hasHostAdminConfigurations() bool {
	return len(c.operationHostAdminState) > 0 || len(c.desiredHostAdminState) > 0
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
