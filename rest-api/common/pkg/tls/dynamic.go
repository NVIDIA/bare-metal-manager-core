// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package tls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

var (
	refreshPeriod = 30 * time.Second
)

// DynTLSCfg implements a periodically refreshed tls config that can be
// used by servers and clients
type DynTLSCfg struct {
	sync.Mutex
	keyPath    string
	certPath   string
	cacertPath string
	tlsCfg     *tls.Config

	cachedCert   *tls.Certificate
	cachedCa     []byte
	caCertPool   *x509.CertPool
	cachedCfg    *tls.Config
	cacheUpdated bool

	isClient bool
	err      error
	ticker   *time.Ticker
	stop     chan bool
	logger   *logrus.Logger
}

// NewDynTLSCfg returns a DynTLSCfg
func NewDynTLSCfg(keyPath, certPath, cacertPath string) (*DynTLSCfg, error) {
	d := &DynTLSCfg{
		keyPath:    keyPath,
		certPath:   certPath,
		cacertPath: cacertPath,
	}

	caCert, err := os.ReadFile(cacertPath)
	if err != nil {
		return nil, err
	}
	d.caCertPool = x509.NewCertPool()
	d.caCertPool.AppendCertsFromPEM(caCert)
	d.cachedCa = caCert
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	d.cachedCert = &cert
	d.tlsCfg = &tls.Config{MinVersion: tls.VersionTLS12}

	d.ticker = time.NewTicker(refreshPeriod)
	d.stop = make(chan bool)
	d.logger = logrus.New()
	d.logger.SetFormatter(&logrus.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: "2006-01-02T15:04:05.999Z07:00",
		CallerPrettyfier: func(f *runtime.Frame) (string, string) {
			return "", fmt.Sprintf("%s:%d", filepath.Base(f.File), f.Line)
		},
	})
	d.logger.SetReportCaller(true)
	go d.pollCerts()
	return d, nil
}

// Close stops the poller go routine
func (d *DynTLSCfg) Close() {
	close(d.stop)
}

// WithTLSCfg allows a tls config to be passed in
func (d *DynTLSCfg) WithTLSCfg(cfg *tls.Config) *DynTLSCfg {
	d.Lock()
	defer d.Unlock()
	d.tlsCfg = cfg
	return d
}

// ClientCfg returns tls config that can be used for a tls client
// CA cannot be refreshed for clients. Instead a warning is logged.
func (d *DynTLSCfg) ClientCfg() *tls.Config {
	d.Lock()
	defer d.Unlock()
	d.isClient = true

	d.tlsCfg.RootCAs = d.caCertPool
	d.tlsCfg.Certificates = []tls.Certificate(nil)
	d.tlsCfg.GetClientCertificate = func(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
		d.Lock()
		defer d.Unlock()
		if d.err != nil {
			d.logger.Errorf("GetClientCertificate: %v", d.err)
			return nil, d.err
		}

		return d.cachedCert, nil
	}
	return d.tlsCfg
}

// ServerCfg returns a tls config that can be used by tls servers. The
// config including CA is synced with the source files.
func (d *DynTLSCfg) ServerCfg() *tls.Config {
	d.tlsCfg.Certificates = nil

	// getter for the server config for any given client
	d.tlsCfg.GetConfigForClient = func(_ *tls.ClientHelloInfo) (*tls.Config, error) {
		d.Lock()
		defer d.Unlock()
		if d.err != nil {
			return nil, d.err
		}

		if d.cachedCfg == nil || d.cacheUpdated {
			d.cachedCfg = d.tlsCfg.Clone()
			d.cachedCfg.Certificates = []tls.Certificate{*d.cachedCert}
			d.cachedCfg.RootCAs = d.caCertPool
			d.cacheUpdated = false
		}

		return d.cachedCfg, nil
	}

	return d.tlsCfg
}

func (d *DynTLSCfg) pollCerts() {
	for {
		select {
		case <-d.stop:
			return
		case <-d.ticker.C:
			d.refresh()
		}
	}
}

func (d *DynTLSCfg) refresh() {
	d.Lock()
	defer d.Unlock()

	// read ca
	caCert, err := os.ReadFile(d.cacertPath)
	if err != nil {
		d.err = err
		d.logger.Errorf("Failed to read CA certificate from %s - %v", d.cacertPath, err)
		return
	}

	if !reflect.DeepEqual(caCert, d.cachedCa) {
		if d.isClient {
			// for client config, we don't have a way to update CA
			// just log a warning
			d.logger.Warn("CA has changed, clients will likely not work without restart")
		} else {
			caCertPool := x509.NewCertPool()
			caCertPool.AppendCertsFromPEM(caCert)
			d.caCertPool = caCertPool
			d.cachedCa = caCert
			d.cacheUpdated = true
			d.logger.Info("Updated server CA certificate")
		}
	}

	// read cert and key
	cert, err := tls.LoadX509KeyPair(d.certPath, d.keyPath)
	if err != nil {
		d.err = err
		d.logger.Errorf("Failed to read certificate and key from %s, %s - %v", d.certPath, d.keyPath, err)
		return
	}

	if !reflect.DeepEqual(&cert, d.cachedCert) {
		d.logger.Info("Updated certificate")
		d.cachedCert = &cert
		d.cacheUpdated = true
	}

	// A complete refresh succeeded — clear any sticky error from a prior
	// failed attempt. Without this, a single transient mismatch (e.g. when
	// cert and key files are updated non-atomically by a k8s secret remount)
	// would poison the config until the process restarted, even after files
	// settle into a consistent state.
	d.err = nil
}
