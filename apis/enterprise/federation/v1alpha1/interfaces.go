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

// /*
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// */

// Package v1alpha1 contains federation API types.
package v1alpha1

import "context"

// +kubebuilder:object:root=false
// +kubebuilder:object:generate:false
// +k8s:deepcopy-gen:interfaces=nil
// +k8s:deepcopy-gen=nil

// FederationProvider defines the interface for federation providers.
type FederationProvider interface {
	GetJWKS(ctx context.Context, token, issuer string, caCrt []byte) (map[string]map[string]string, error)
	// CheckIdentityExists checks if the identity (client/app/workload) still exists in the identity provider.
	// Returns true if exists, false if deleted/doesn't exist, or error if check failed.
	CheckIdentityExists(ctx context.Context, subject string) (bool, error)
}

// +kubebuilder:object:root=false
// +kubebuilder:object:generate:false
// +k8s:deepcopy-gen:interfaces=nil
// +k8s:deepcopy-gen=nil

// ValidationResult represents the result of a validation operation.
type ValidationResult string

const (
	// ValidationResultValid indicates the validation was successful.
	ValidationResultValid ValidationResult = "Valid"
	// ValidationResultInvalid indicates the validation failed.
	ValidationResultInvalid ValidationResult = "Invalid"
	// ValidationResultUnknown indicates the validation result is unknown.
	ValidationResultUnknown ValidationResult = "Unknown"
	// ValidationResultError indicates the validation failed with an error.
	ValidationResultError ValidationResult = "Error"
)
