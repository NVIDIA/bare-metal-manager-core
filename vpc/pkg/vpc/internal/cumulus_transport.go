/*
Copyright 2022 NVIDIA CORPORATION & AFFILIATES.
*/

package internal

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"golang.org/x/crypto/ssh"
	"k8s.io/apimachinery/pkg/util/json"
)

const (
	cumulusConnTimeout     = time.Second * 30
	cumulusApplyTimeout    = time.Second * 300
	cumulusDefaultNVUEPort = "8765"
)

func modifyRequest(req *http.Request, params map[string]string) {
	req.Header.Add("content-type", "application/json")
	q := req.URL.Query()
	for k, v := range params {
		q.Add(k, v)
	}
	req.URL.RawQuery = q.Encode()
}

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

func NewCumulusTransport(ip, user, pwd string) (NetworkDeviceTransport, error) {
	t := &cumulusTransport{
		user:    user,
		pwd:     pwd,
		sshUser: user,
		sshPwd:  pwd,
		client: &http.Client{
			Timeout: cumulusConnTimeout,
		},
	}
	t.SetMgmtIP(ip)
	if strings.ToLower(os.Getenv("DISABLE_CUMULUS_CERT_VERIFY")) == "true" {
		t.client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}
	return t, nil
}

func (t *cumulusTransport) Send(req *http.Request) ([]byte, error) {
	req.SetBasicAuth(t.user, t.pwd)
	/*
		var body []byte
		if req.GetBody != nil {
			b, _ := req.GetBody()
			body, _ = ioutil.ReadAll(b)
		}
		t.log.V(1).Info("Sending https to", "URL", req.URL.String(), "Method", req.Method, "Body", string(body))
	*/
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
	if err != nil || len(out) == 0 {
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

func (t *cumulusTransport) SetLogger(logger logr.Logger) {
	t.log = logger
}
