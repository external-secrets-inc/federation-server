// /*
// Copyright © 2025 ESO Maintainer Team
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// */

// Package server implements the federation server.
// Copyright External Secrets Inc.
// All Rights Reserved.
package server

import (
	"crypto/tls"
	"crypto/x509"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

func makeCertWithSPIFFEURI(uri string) (*x509.Certificate, error) {
	parsedURI, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}
	return &x509.Certificate{
		URIs: []*url.URL{parsedURI},
	}, nil
}

func TestVerifyConnection_NoCertificates(t *testing.T) {
	cs := tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{},
	}
	err := verifyConnection(cs)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no certificates found")
}

func TestVerifyConnection_InvalidCertificate(t *testing.T) {
	// Certificate with no URI SAN → x509svid.IDFromCert returns an error.
	leaf := &x509.Certificate{}
	cs := tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{leaf},
	}
	err := verifyConnection(cs)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "error extracting spiffe id")
}

func TestVerifyConnection_NotAllowedSPIFFE(t *testing.T) {
	uri := "spiffe://example.org/app/ns/test-ns/sa/uid/service-account/pod/pid/podname"
	leaf, err := makeCertWithSPIFFEURI(uri)
	assert.NoError(t, err)

	cs := tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{leaf},
	}

	RemoveTLSAllowedID(uri)

	err = verifyConnection(cs)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not authorized spiffe id: "+uri)
}

func TestVerifyConnection_Success(t *testing.T) {
	uri := "spiffe://example.org/app/ns/prod-ns/sa/uid/my-sa/pod/pid/my-pod"
	leaf, err := makeCertWithSPIFFEURI(uri)
	assert.NoError(t, err)

	cs := tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{leaf},
	}

	AddTLSAllowedID(uri)
	defer RemoveTLSAllowedID(uri)

	err = verifyConnection(cs)
	assert.NoError(t, err)
}
