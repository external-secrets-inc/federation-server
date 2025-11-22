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
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sync"

	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

// SpiffeAuthenticator implements Authenticator.
type SpiffeAuthenticator struct {
	mu sync.RWMutex
}

// NewSpiffeAuthenticator creates a new SpiffeAuthenticator.
func NewSpiffeAuthenticator() *SpiffeAuthenticator {
	return &SpiffeAuthenticator{
		mu: sync.RWMutex{},
	}
}

// Authenticate implements Authenticator.
func (a *SpiffeAuthenticator) Authenticate(r *http.Request) (*Info, error) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no certificates in request")
	}

	cert := r.TLS.PeerCertificates[0]
	id, err := x509svid.IDFromCert(cert)
	if err != nil {
		return nil, fmt.Errorf("error extracting spiffe id: %w", err)
	}
	kubeAttributes, err := a.buildKubeAttributes(id.Path())
	if err != nil {
		return nil, err
	}

	authInfo := &Info{
		Method:         "spiffe",
		Provider:       id.TrustDomain().Name(),
		Subject:        id.String(),
		KubeAttributes: kubeAttributes,
	}
	return authInfo, nil
}

func (a *SpiffeAuthenticator) buildKubeAttributes(path string) (*KubeAttributes, error) {
	// path should follow the pattern /{app-name}/ns/{namespace}/sa/{saID}/{saName}/pod/{podID}/{podName}
	// match 0: full path
	// match 1: namespace
	// match 2: saID
	// match 3: saName
	// match 4: podID
	// match 5: podName
	pattern := `^/[^/]+/ns/([^/]+)/sa/([^/]+)/([^/]+)/pod/([^/]+)/([^/]+)$`
	re := regexp.MustCompile(pattern)

	matches := re.FindStringSubmatch(path)
	if matches == nil {
		return nil, errors.New(
			"invalid spiffe path; should follow the pattern /{app-name}/ns/{namespace}/sa/{saID}/{saName}/pod/{podID}/{podName}",
		)
	}
	return &KubeAttributes{
		Namespace:      matches[1],
		ServiceAccount: &ServiceAccount{Name: matches[3], UID: matches[2]},
		Pod:            &PodInfo{Name: matches[5], UID: matches[4]},
	}, nil
}

func init() {
	Register("spiffe", NewSpiffeAuthenticator())
}
