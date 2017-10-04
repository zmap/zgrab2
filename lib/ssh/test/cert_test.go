// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build darwin dragonfly freebsd linux netbsd openbsd

package test

import (
	"crypto/rand"
	"testing"

	"github.com/zmap/zgrab/ztools/xssh"
)

func DISABLED_TestCertLogin(t *testing.T) {
	s := newServer(t)
	defer s.Shutdown()

	// Use a key different from the default.
	clientKey := testSigners["dsa"]
	caAuthKey := testSigners["ecdsa"]
	cert := &xssh.Certificate{
		Key:             clientKey.PublicKey(),
		ValidPrincipals: []string{username()},
		CertType:        xssh.UserCert,
		ValidBefore:     xssh.CertTimeInfinity,
	}
	if err := cert.SignCert(rand.Reader, caAuthKey); err != nil {
		t.Fatalf("SetSignature: %v", err)
	}

	certSigner, err := xssh.NewCertSigner(cert, clientKey)
	if err != nil {
		t.Fatalf("NewCertSigner: %v", err)
	}

	conf := &xssh.ClientConfig{
		User: username(),
	}
	conf.Auth = append(conf.Auth, xssh.PublicKeys(certSigner))
	client, err := s.TryDial(conf)
	if err != nil {
		t.Fatalf("TryDial: %v", err)
	}
	client.Close()
}
