/*
Copyright 2022 NVIDIA CORPORATION & AFFILIATES.
*/

package internal

import (
	"bytes"
	"fmt"
	"html/template"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/util/wait"

	"gitlab-master.nvidia.com/forge/vpc/apis/networkfabric/v1alpha1"
)

type HBNState int

/*
   Collected parameters:
   LoopbackIP, ASN    // allocated and stored in leaf.Status
   device.startup.yaml, // startup.yaml current on device.
   controller.startup.yaml // computed startup.yaml by the controller.

   State      |Parameters                              |NextState      | Action
   ----------------------------------------------------|---------------|--------------
   Init       |                                        |Connecting     | None
              |                                        |Connected      | None
   -----------|----------------------------------------|---------------|--------------
   Connecting | no loopbackIP/ASN or                   |Connected      | Connect (OK)
              | no device.startup or                   |Connecting     | Connect (NOK)
              | device.startup.yaml !=                 |               |
              |    controller.startup.yaml             |               |
   -----------|----------------------------------------|---------------|--------------
   Connected  | loopback/ASN and                       |Connected      | Connect
              | device.startup ==                      |Init           | Stop
              |     controller.startup                 |               |
  -------------------------------------------------------------------------------------
*/

const (
	HBNInit HBNState = iota
	HBNConnecting
	HBNConnected
	HBNInvalid
)

type HBN struct {
	// no locks because DPU/HBN transactions are serialized in upper tier.
	NetworkDeviceTransport
	state      HBNState
	loopbackIP string
	asn        uint32
	manager    *vpcManager
	log        logr.Logger
	err        error
}

// getHBNOperationStartup retrieves startup.yaml from the HBN device.
func (h *HBN) getHBNOperationStartup() (string, error) {
	output, err := h.Ssh("sudo ls /var/lib/hbn/etc/nvue.d/")
	if err != nil {
		return "", err
	}
	if !strings.Contains(output, "startup.yaml") {
		return "", nil
	}
	return h.Ssh("sudo cat /var/lib/hbn/etc/nvue.d/startup.yaml")
}

// getHBNDhcRealyConf retrieves startu from the HBN device.
func (h *HBN) getHBNDhcRealyConf() (string, error) {
	output, err := h.Ssh("sudo ls /var/lib/hbn/etc/supervisor/conf.d/")
	if err != nil {
		return "", err
	}
	if !strings.Contains(output, "supervisor-isc-dhcp-relay.conf") {
		return "", nil
	}
	return h.Ssh("sudo cat /var/lib/hbn/etc/supervisor/conf.d/supervisor-isc-dhcp-relay.conf")
}

// getHBNDesiredStartup returns desired NVUE startup.yaml that may or may not
// exists on the HBN device.
func (h *HBN) getHBNDesiredStartup() (string, error) {
	t := template.Must(template.New("").Parse(string(HBNConfig.NVUEConfig)))
	nvueConfig := &bytes.Buffer{}
	nparam := &struct {
		LoopbackIP         string
		ASN                uint32
		FromUnderlayFilter string
		ToUnderlayFilter   string
		UplinkGroup        string
	}{
		LoopbackIP:         h.loopbackIP,
		ASN:                h.asn,
		FromUnderlayFilter: ForgeFromUnderlayFilter,
		ToUnderlayFilter:   ForgeToUnderlayFilter,
		UplinkGroup:        ForgeUplink,
	}
	if err := t.Execute(nvueConfig, nparam); err != nil {
		return "", err
	}
	return nvueConfig.String(), nil
}

// GetHBNState returns current HBN state.
func (h *HBN) GetHBNState() HBNState {
	if h == nil {
		return HBNInvalid
	}
	return h.state
}

// computeHBNState returns next HBN state.
func (h *HBN) computeHBNState(isConnect bool) (HBNState, error) {
	if !isConnect {
		return HBNInit, nil
	}
	if h.state > HBNInit {
		return h.state, nil
	}
	if h.asn == 0 || len(h.loopbackIP) == 0 {
		return HBNConnecting, nil
	}
	cStartup, err := h.getHBNOperationStartup()
	if err != nil {
		return HBNInit, err
	}
	r := strings.NewReplacer("\n", "", " ", "", "'", "", "\"", "")
	cStartup = r.Replace(cStartup)
	dStartup, err := h.getHBNDesiredStartup()
	if err != nil {
		return HBNInit, err
	}
	dStartup = r.Replace(dStartup)
	if cStartup != dStartup {
		h.log.V(1).Info("Different startup", "Current", cStartup, "Desired", dStartup)
		return HBNConnecting, nil
	}
	return HBNConnected, nil
}

// Connect HBN to network fabric without overlay. It is no-op if HBN is
// already connect
func (h *HBN) Connect(forced bool) (err error) {
	if h == nil {
		return nil
	}
	defer func() {
		h.err = err
	}()
	h.log.V(1).Info("Connect", "LoopbackIP", h.loopbackIP, "ASN", h.asn, "Forced", forced)
	h.state, err = h.computeHBNState(true)
	if err != nil {
		return err
	}
	if h.state >= HBNConnected && !forced {
		return nil
	}
	if h.asn == 0 {
		pool := h.manager.resourceMgr.GetIntegerPool(string(v1alpha1.ASNResourcePool))
		if pool == nil {
			h.asn = HBNConfig.DefaultASN
		} else {
			asn, err := pool.Get()
			if err != nil {
				return NewMissingResourcePoolError(string(v1alpha1.ASNResourcePool))
			}
			h.asn = uint32(asn)
		}
	}
	if len(h.loopbackIP) == 0 {
		pool := h.manager.resourceMgr.GetIPv4Pool(string(v1alpha1.LoopbackIPResourcePool))
		if pool == nil {
			return NewMissingResourcePoolError(string(v1alpha1.LoopbackIPResourcePool))
		}
		var err error
		if h.loopbackIP, err = pool.Get(); err != nil {
			return NewMissingResourcePoolError(string(v1alpha1.LoopbackIPResourcePool))
		}
	}
	nvueConfig, err := h.getHBNDesiredStartup()
	if err != nil {
		return err
	}
	if _, err = h.Ssh(fmt.Sprintf("echo -e '%s' | sudo tee /var/lib/hbn/etc/nvue.d/startup.yaml", nvueConfig)); err != nil {
		return err
	}

	if err = h.start(); err != nil {
		return err
	}
	h.state = HBNConnected
	return nil
}

// Stop HBN.
func (h *HBN) Stop(forced bool) (err error) {
	if h == nil {
		return nil
	}
	defer func() {
		h.err = err
	}()
	if h.state == HBNInit && !forced {
		return nil
	}
	nextState, _ := h.computeHBNState(false)
	if _, err = h.Ssh("sudo systemctl stop kubelet.service"); err != nil {
		return err
	}
	if _, err = h.Ssh("sudo systemctl disable kubelet.service"); err != nil {
		return err
	}
	id, err := h.GetHBNContainerID()
	if err != nil {
		return err
	}
	if len(id) == 0 {
		return nil
	}
	if _, err = h.Ssh("sudo crictl rm -f " + id); err != nil {
		return err
	}
	if _, err = h.Ssh("sudo rm -f /var/lib/hbn/etc/supervisor/conf.d/supervisor-isc-dhcp-relay.conf"); err != nil {
		return err
	}
	h.state = nextState
	return nil
}

func (h *HBN) GetASN() uint32 {
	if h == nil || h.state < HBNConnected {
		return 0
	}
	return h.asn
}

func (h *HBN) GetLoopbackIP() string {
	if h == nil || h.state < HBNConnected {
		return ""
	}
	return h.loopbackIP
}

func (h *HBN) GetError() error {
	if h == nil {
		return nil
	}
	return h.err
}

// start HBN.
func (h *HBN) start() error {
	now := time.Now().Unix()
	defer func() {
		h.log.Info("Start HBN finished in", "Second", time.Now().Unix()-now)
	}()
	curContainer, _ := h.GetHBNContainerID()
	if len(curContainer) > 0 {
		if _, err := h.SshHBN("nv config apply startup --assume-yes"); err != nil {
			return err
		}
		return nil
	}
	if _, err := h.Ssh("sudo systemctl start containerd.service"); err != nil {
		return err
	}
	if _, err := h.Ssh("sudo systemctl enable containerd.service"); err != nil {
		return err
	}
	if _, err := h.Ssh("sudo systemctl start kubelet.service"); err != nil {
		return err
	}
	if _, err := h.Ssh("sudo systemctl enable kubelet.service"); err != nil {
		return err
	}
	if err := wait.Poll(time.Second, cumulusConnTimeout, func() (bool, error) {
		id, err := h.GetHBNContainerID()
		if err != nil {
			return false, err
		}
		return len(id) > 0, nil
	}); err != nil {
		h.log.Info("Error waiting for HBN to come up", "Error", err)
		return err
	}
	if err := wait.Poll(time.Second, cumulusConnTimeout, func() (bool, error) {
		out, err := h.SshHBN("supervisorctl status nvued")
		if err != nil {
			return false, err
		}
		return strings.Contains(out, "RUNNING"), nil
	}); err != nil {
		return err
	}
	if _, err := h.SshHBN("nv config apply startup --assume-yes"); err != nil {
		return err
	}
	return nil
}
