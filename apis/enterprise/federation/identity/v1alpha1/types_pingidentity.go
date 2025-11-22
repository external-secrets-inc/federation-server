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

/*
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// PingIdentityFederationSpec defines the specification for PingIdentity federation.
type PingIdentityFederationSpec struct {
	// Region is the PingOne region (e.g., "com", "eu", "asia", "ca")
	// +required
	// +kubebuilder:validation:Enum=com;eu;asia;ca
	Region string `json:"region"`

	// EnvironmentID is the PingOne environment ID (UUID)
	// +required
	EnvironmentID string `json:"environmentId"`

	// ManagementAPI credentials for checking if PingOne applications still exist
	// This is optional - if not provided, identity existence checking will be skipped
	// Requires a Worker application with appropriate permissions
	// +optional
	ManagementAPI *PingIdentityManagementAPI `json:"managementAPI,omitempty"`
}

// PingIdentityManagementAPI contains credentials for calling PingOne Management API.
// Use a Worker application type for machine-to-machine authentication.
type PingIdentityManagementAPI struct {
	// ClientIDSecretRef references a secret containing the Worker app client ID
	// +required
	ClientIDSecretRef SecretKeySelector `json:"clientIdSecretRef"`

	// ClientSecretRef references a secret containing the Worker app client secret
	// +required
	ClientSecretRef SecretKeySelector `json:"clientSecretRef"`
}

// PingIdentityFederation represents a PingIdentity federation configuration.
// +kubebuilder:object:root=true
// +kubebuilder:storageversion
// +kubebuilder:subresource:status
// +kubebuilder:metadata:labels="external-secrets.io/component=controller"
// +kubebuilder:resource:scope=Cluster,categories={external-secrets, external-secrets-federation}
type PingIdentityFederation struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              PingIdentityFederationSpec `json:"spec"`
}

// +kubebuilder:object:root=true

// PingIdentityFederationList contains a list of PingIdentityFederation resources.
type PingIdentityFederationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []PingIdentityFederation `json:"items"`
}
