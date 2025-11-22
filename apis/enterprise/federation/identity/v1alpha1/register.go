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
	"reflect"

	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

// Package type metadata.
const (
	Group   = "identity.federation.external-secrets.io"
	Version = "v1alpha1"
)

var (
	// SchemeGroupVersion is group version used to register these objects.
	SchemeGroupVersion = schema.GroupVersion{Group: Group, Version: Version}

	// SchemeBuilder is used to add go types to the GroupVersionKind scheme.
	SchemeBuilder = &scheme.Builder{GroupVersion: SchemeGroupVersion}
	// AddToScheme adds all types to the scheme.
	AddToScheme   = SchemeBuilder.AddToScheme
)

// KubernetesFederation type metadata.
var (
	KubernetesFederationKind             = reflect.TypeOf(KubernetesFederation{}).Name()
	KubernetesFederationGroupKind        = schema.GroupKind{Group: Group, Kind: KubernetesFederationKind}.String()
	KubernetesFederationKindAPIVersion   = KubernetesFederationKind + "." + SchemeGroupVersion.String()
	KubernetesFederationGroupVersionKind = SchemeGroupVersion.WithKind(KubernetesFederationKind)
)

// SpiffeFederation type metadata.
var (
	SpiffeFederationKind             = reflect.TypeOf(SpiffeFederation{}).Name()
	SpiffeFederationGroupKind        = schema.GroupKind{Group: Group, Kind: SpiffeFederationKind}.String()
	SpiffeFederationKindAPIVersion   = SpiffeFederationKind + "." + SchemeGroupVersion.String()
	SpiffeFederationGroupVersionKind = SchemeGroupVersion.WithKind(SpiffeFederationKind)
)

// OktaFederation type metadata.
var (
	OktaFederationKind             = reflect.TypeOf(OktaFederation{}).Name()
	OktaFederationGroupKind        = schema.GroupKind{Group: Group, Kind: OktaFederationKind}.String()
	OktaFederationKindAPIVersion   = OktaFederationKind + "." + SchemeGroupVersion.String()
	OktaFederationGroupVersionKind = SchemeGroupVersion.WithKind(OktaFederationKind)
)

// PingIdentityFederation type metadata.
var (
	PingIdentityFederationKind             = reflect.TypeOf(PingIdentityFederation{}).Name()
	PingIdentityFederationGroupKind        = schema.GroupKind{Group: Group, Kind: PingIdentityFederationKind}.String()
	PingIdentityFederationKindAPIVersion   = PingIdentityFederationKind + "." + SchemeGroupVersion.String()
	PingIdentityFederationGroupVersionKind = SchemeGroupVersion.WithKind(PingIdentityFederationKind)
)

func init() {
	SchemeBuilder.Register(&KubernetesFederation{}, &KubernetesFederationList{})
	SchemeBuilder.Register(&SpiffeFederation{}, &SpiffeFederationList{})
	SchemeBuilder.Register(&OktaFederation{}, &OktaFederationList{})
	SchemeBuilder.Register(&PingIdentityFederation{}, &PingIdentityFederationList{})
}
