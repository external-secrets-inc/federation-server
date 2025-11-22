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

// Package provider implements the federation provider.
// Copyright External Secrets Inc.
// All Rights Reserved.
package provider

import (
	"context"
)

// SpiffeProvider implements the SPIFFE provider for federation.
type SpiffeProvider struct {
	TrustDomain string
}

// NewSpiffeProvider creates a new SPIFFE provider.
func NewSpiffeProvider(trustDomain string) *SpiffeProvider {
	return &SpiffeProvider{
		TrustDomain: trustDomain,
	}
}

// GetJWKS returns the JWKS for the SPIFFE provider.
func (k *SpiffeProvider) GetJWKS(_ context.Context, _, _ string, _ []byte) (map[string]map[string]string, error) {
	return nil, nil
}

// CheckIdentityExists checks if a SPIFFE identity still exists.
// For SPIFFE federation, identity lifecycle is managed through WorkloadBinding and mTLS certificate validation,
// so this always returns true (identity check happens via workload lifecycle).
func (k *SpiffeProvider) CheckIdentityExists(_ context.Context, _ string) (bool, error) {
	// SPIFFE federation uses WorkloadBinding and certificate validation for lifecycle management
	// This method is not used for SPIFFE identities
	return true, nil
}
