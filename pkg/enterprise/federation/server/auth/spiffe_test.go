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

// Package auth implements the federation server authorization.
// Copyright External Secrets Inc.
// All Rights Reserved.
package auth

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Helper to create a dummy x509.Certificate with a single URI SAN.
func makeCertWithSPIFFEURI(uri string) (*x509.Certificate, error) {
	parsedURI, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}
	return &x509.Certificate{
		URIs: []*url.URL{parsedURI},
	}, nil
}

func TestBuildKubeAttributes_ValidPath(t *testing.T) {
	a := NewSpiffeAuthenticator()

	path := "/my-app/ns/test-namespace/sa/uid123/service-account-name/pod/pod456/pod-name"
	attrs, err := a.buildKubeAttributes(path)
	assert.NoError(t, err)
	assert.NotNil(t, attrs)

	assert.Equal(t, "test-namespace", attrs.Namespace)
	assert.Equal(t, "uid123", attrs.ServiceAccount.UID)
	assert.Equal(t, "service-account-name", attrs.ServiceAccount.Name)
	assert.Equal(t, "pod456", attrs.Pod.UID)
	assert.Equal(t, "pod-name", attrs.Pod.Name)
}

func TestBuildKubeAttributes_InvalidPath(t *testing.T) {
	a := NewSpiffeAuthenticator()

	invalidPaths := []string{
		"",                                    // empty
		"/wrong/format/with/missing/segments", // too few segments
		"/app/ns//sa/id/name/pod/id",          // missing namespace
		"/app/ns/ns1/sa/uidOnly/pod/podID/podName", // missing service account name
	}

	for _, path := range invalidPaths {
		_, err := a.buildKubeAttributes(path)
		assert.Error(t, err, "expected error for invalid path %q", path)
	}
}

func TestAuthenticate_NoTLS(t *testing.T) {
	a := NewSpiffeAuthenticator()
	req := &http.Request{} // TLS is nil

	_, err := a.Authenticate(req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no certificates in request")
}

func TestAuthenticate_EmptyPeerCertificates(t *testing.T) {
	a := NewSpiffeAuthenticator()
	req := &http.Request{
		TLS: &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{},
		},
	}

	_, err := a.Authenticate(req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no certificates in request")
}

func TestAuthenticate_InvalidCertificate(t *testing.T) {
	a := NewSpiffeAuthenticator()

	// Certificate with no URI SAN: x509svid.IDFromCert should fail.
	cert := &x509.Certificate{}
	req := &http.Request{
		TLS: &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{cert},
		},
	}

	_, err := a.Authenticate(req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "error extracting spiffe id")
}

func TestAuthenticate_InvalidSPIFFEPath(t *testing.T) {
	a := NewSpiffeAuthenticator()

	// Create a certificate whose URI SAN is a valid SPIFFE URI syntax but with wrong path format.
	badPath := "spiffe://example.org/invalid/path/without/required/segments"
	cert, err := makeCertWithSPIFFEURI(badPath)
	assert.NoError(t, err)

	req := &http.Request{
		TLS: &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{cert},
		},
	}

	_, err = a.Authenticate(req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid spiffe path")
}

func TestAuthenticate_Success(t *testing.T) {
	a := NewSpiffeAuthenticator()

	uri := "spiffe://example.org/my-app/ns/prod-namespace/sa/sa-uid/my-sa/pod/pod-uid/my-pod"
	cert, err := makeCertWithSPIFFEURI(uri)
	assert.NoError(t, err)

	req := &http.Request{
		TLS: &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{cert},
		},
	}

	info, err := a.Authenticate(req)
	assert.NoError(t, err)
	assert.NotNil(t, info)

	assert.Equal(t, "spiffe", info.Method)
	assert.Equal(t, "example.org", info.Provider)
	assert.Equal(t, uri, info.Subject)

	ka := info.KubeAttributes
	assert.NotNil(t, ka)
	assert.Equal(t, "prod-namespace", ka.Namespace)
	assert.Equal(t, "sa-uid", ka.ServiceAccount.UID)
	assert.Equal(t, "my-sa", ka.ServiceAccount.Name)
	assert.Equal(t, "pod-uid", ka.Pod.UID)
	assert.Equal(t, "my-pod", ka.Pod.Name)
}
