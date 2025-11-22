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

// OktaFederationSpec defines the specification for Okta federation.
type OktaFederationSpec struct {
	// Domain is the Okta organization domain (e.g., "https://dev-12345.okta.com" or custom domain)
	// +required
	Domain string `json:"domain"`

	// AuthorizationServerID is the OAuth2 Authorization Server ID (e.g., "default" or custom auth server ID)
	// Defaults to "default" if not specified
	// +optional
	// +kubebuilder:default="default"
	AuthorizationServerID string `json:"authorizationServerId,omitempty"`

	// ManagementAPI credentials for checking if Okta applications still exist
	// This is optional - if not provided, identity existence checking will be skipped
	// +optional
	ManagementAPI *OktaManagementAPI `json:"managementAPI,omitempty"`
}

// OktaManagementAPI contains credentials for calling Okta Management API.
type OktaManagementAPI struct {
	// APITokenSecretRef references a secret containing the Okta API token
	// +required
	APITokenSecretRef SecretKeySelector `json:"apiTokenSecretRef"`
}

// SecretKeySelector selects a key from a Secret.
type SecretKeySelector struct {
	// Name of the secret
	// +required
	Name string `json:"name"`

	// Namespace of the secret
	// +optional
	Namespace string `json:"namespace,omitempty"`

	// Key in the secret
	// +required
	Key string `json:"key"`
}

// OktaFederation represents an Okta federation configuration.
// +kubebuilder:object:root=true
// +kubebuilder:storageversion
// +kubebuilder:subresource:status
// +kubebuilder:metadata:labels="external-secrets.io/component=controller"
// +kubebuilder:resource:scope=Cluster,categories={external-secrets, external-secrets-federation}
type OktaFederation struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              OktaFederationSpec `json:"spec"`
}

// +kubebuilder:object:root=true

// OktaFederationList contains a list of OktaFederation resources.
type OktaFederationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OktaFederation `json:"items"`
}
