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
Copyright External Secrets Inc.
All Rights Reserved.
*/

// Package v1alpha1 contains federation API types.
package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// AuthorizedIdentitySpec defines the specification for an authorized identity.
type AuthorizedIdentitySpec struct {
	IdentitySpec      IdentitySpec       `json:"identitySpec"`
	IssuedCredentials []IssuedCredential `json:"issuedCredentials"`
}

// IdentitySpec defines the specification for an identity.
type IdentitySpec struct {
	FederationRef FederationRef `json:"federationRef"`

	// +kubebuilder:validation:Required
	Subject *FederationSubject `json:"subject,omitempty"`
}

// IssuedCredential maps the credential that was issued to a given identity.
type IssuedCredential struct {
	SourceRef SourceRef `json:"sourceRef"`
	// +kubebuilder:validation:Optional
	RemoteRef *RemoteRef `json:"remoteRef,omitempty"`
	// +kubebuilder:validation:Optional
	StateRef *StateRef `json:"stateRef,omitempty"`
	// +kubebuilder:validation:Optional
	WorkloadBinding *WorkloadBinding `json:"workloadBinding,omitempty"`
	// +kubebuilder:validation:Optional
	LastIssuedAt metav1.Time `json:"lastIssuedAt,omitempty"`
}

// WorkloadBinding describes which workload the credential was bound to.
type WorkloadBinding struct {
	// Kind is the kind of workload, e.g., "Pod" or "ServiceAccount".
	Kind string `json:"kind"`
	// Name is the name of the workload.
	Name string `json:"name"`
	// UID is the UID of the workload.
	UID string `json:"uid"`
	// Namespace is the namespace of the workload.
	Namespace string `json:"namespace"`
}

// RemoteRef is a reference within the source Ref, if any, to which key was obtained.
type RemoteRef struct {
	RemoteKey string `json:"remoteKey"`
	Property  string `json:"property"`
}

// StateRef is a reference to any object containing a state.
// Typically this is a GeneratorState.
type StateRef struct {
	Kind       string `json:"kind"`
	APIVersion string `json:"apiVersion"`
	Name       string `json:"name"`
	// +kubebuilder:validation:Optional
	Namespace *string `json:"namespace"`
}

// SourceRef is a reference to any object that can output a credential.
// This can be a SecretStore or a Generator.
type SourceRef struct {
	Kind       string `json:"kind"`
	APIVersion string `json:"apiVersion"`
	Name       string `json:"name"`
	// +kubebuilder:validation:Optional
	Namespace *string `json:"namespace"`
}

// AuthorizedIdentity is the schema to control which identities were able to get which credentials
// +kubebuilder:object:root=true
// +kubebuilder:storageversion
// +kubebuilder:subresource:status
// +kubebuilder:metadata:labels="external-secrets.io/component=controller"
// +kubebuilder:resource:scope=Cluster,categories={external-secrets, external-secrets-federation}
type AuthorizedIdentity struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              AuthorizedIdentitySpec `json:"spec,omitempty"`
}

// +kubebuilder:object:root=true

// AuthorizedIdentityList contains a list of AuthorizedIdentity resources.
type AuthorizedIdentityList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AuthorizedIdentity `json:"items"`
}
