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

package federation

import (
	"context"
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	fedv1alpha1 "github.com/external-secrets/external-secrets-federation/apis/enterprise/federation/v1alpha1"
	genv1alpha1 "github.com/external-secrets/external-secrets/apis/generators/v1alpha1"
)

func TestShouldKeepCredential(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = fedv1alpha1.AddToScheme(scheme)
	_ = genv1alpha1.AddToScheme(scheme)
	_ = v1.AddToScheme(scheme)

	namespace := "test-namespace"

	tests := []struct {
		name       string
		credential *fedv1alpha1.IssuedCredential
		objects    []client.Object
		want       bool
	}{
		{
			name: "credential without StateRef or WorkloadBinding should be kept",
			credential: &fedv1alpha1.IssuedCredential{
				SourceRef: fedv1alpha1.SourceRef{
					Kind: "ClusterSecretStore",
					Name: "test-store",
				},
			},
			objects: []client.Object{},
			want:    true,
		},
		{
			name: "credential with existing GeneratorState should be kept",
			credential: &fedv1alpha1.IssuedCredential{
				SourceRef: fedv1alpha1.SourceRef{
					Kind: "Generator",
					Name: "test-gen",
				},
				StateRef: &fedv1alpha1.StateRef{
					Kind:       "GeneratorState",
					APIVersion: "generators.external-secrets.io/v1alpha1",
					Name:       "test-state",
					Namespace:  &namespace,
				},
			},
			objects: []client.Object{
				&genv1alpha1.GeneratorState{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-state",
						Namespace: namespace,
					},
				},
			},
			want: true,
		},
		{
			name: "credential with non-existing GeneratorState should be removed",
			credential: &fedv1alpha1.IssuedCredential{
				SourceRef: fedv1alpha1.SourceRef{
					Kind: "Generator",
					Name: "test-gen",
				},
				StateRef: &fedv1alpha1.StateRef{
					Kind:       "GeneratorState",
					APIVersion: "generators.external-secrets.io/v1alpha1",
					Name:       "missing-state",
					Namespace:  &namespace,
				},
			},
			objects: []client.Object{},
			want:    false,
		},
		{
			name: "credential with existing Pod should be kept",
			credential: &fedv1alpha1.IssuedCredential{
				SourceRef: fedv1alpha1.SourceRef{
					Kind: "Generator",
					Name: "test-gen",
				},
				WorkloadBinding: &fedv1alpha1.WorkloadBinding{
					Kind:      "Pod",
					Name:      "test-pod",
					UID:       "pod-uid-123",
					Namespace: namespace,
				},
			},
			objects: []client.Object{
				&v1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-pod",
						Namespace: namespace,
						UID:       "pod-uid-123",
					},
				},
			},
			want: true,
		},
		{
			name: "credential with non-existing Pod should be removed",
			credential: &fedv1alpha1.IssuedCredential{
				SourceRef: fedv1alpha1.SourceRef{
					Kind: "Generator",
					Name: "test-gen",
				},
				WorkloadBinding: &fedv1alpha1.WorkloadBinding{
					Kind:      "Pod",
					Name:      "missing-pod",
					UID:       "pod-uid-456",
					Namespace: namespace,
				},
			},
			objects: []client.Object{},
			want:    false,
		},
		{
			name: "credential with Pod UID mismatch should be removed",
			credential: &fedv1alpha1.IssuedCredential{
				SourceRef: fedv1alpha1.SourceRef{
					Kind: "Generator",
					Name: "test-gen",
				},
				WorkloadBinding: &fedv1alpha1.WorkloadBinding{
					Kind:      "Pod",
					Name:      "test-pod",
					UID:       "old-pod-uid",
					Namespace: namespace,
				},
			},
			objects: []client.Object{
				&v1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-pod",
						Namespace: namespace,
						UID:       "new-pod-uid",
					},
				},
			},
			want: false,
		},
		{
			name: "credential with existing ServiceAccount should be kept",
			credential: &fedv1alpha1.IssuedCredential{
				SourceRef: fedv1alpha1.SourceRef{
					Kind: "Generator",
					Name: "test-gen",
				},
				WorkloadBinding: &fedv1alpha1.WorkloadBinding{
					Kind:      "ServiceAccount",
					Name:      "test-sa",
					UID:       "sa-uid-123",
					Namespace: namespace,
				},
			},
			objects: []client.Object{
				&v1.ServiceAccount{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-sa",
						Namespace: namespace,
						UID:       "sa-uid-123",
					},
				},
			},
			want: true,
		},
		{
			name: "credential with both StateRef and WorkloadBinding existing should be kept",
			credential: &fedv1alpha1.IssuedCredential{
				SourceRef: fedv1alpha1.SourceRef{
					Kind: "Generator",
					Name: "test-gen",
				},
				StateRef: &fedv1alpha1.StateRef{
					Kind:       "GeneratorState",
					APIVersion: "generators.external-secrets.io/v1alpha1",
					Name:       "test-state",
					Namespace:  &namespace,
				},
				WorkloadBinding: &fedv1alpha1.WorkloadBinding{
					Kind:      "Pod",
					Name:      "test-pod",
					UID:       "pod-uid-123",
					Namespace: namespace,
				},
			},
			objects: []client.Object{
				&genv1alpha1.GeneratorState{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-state",
						Namespace: namespace,
					},
				},
				&v1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-pod",
						Namespace: namespace,
						UID:       "pod-uid-123",
					},
				},
			},
			want: true,
		},
		{
			name: "credential with StateRef existing but WorkloadBinding missing should be removed",
			credential: &fedv1alpha1.IssuedCredential{
				SourceRef: fedv1alpha1.SourceRef{
					Kind: "Generator",
					Name: "test-gen",
				},
				StateRef: &fedv1alpha1.StateRef{
					Kind:       "GeneratorState",
					APIVersion: "generators.external-secrets.io/v1alpha1",
					Name:       "test-state",
					Namespace:  &namespace,
				},
				WorkloadBinding: &fedv1alpha1.WorkloadBinding{
					Kind:      "Pod",
					Name:      "missing-pod",
					UID:       "pod-uid-789",
					Namespace: namespace,
				},
			},
			objects: []client.Object{
				&genv1alpha1.GeneratorState{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test-state",
						Namespace: namespace,
					},
				},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(tt.objects...).
				Build()

			reconciler := &AuthorizedIdentityReconciler{
				Client: fakeClient,
				Log:    logr.Discard(),
				Scheme: scheme,
			}

			// Create a dummy IdentitySpec for the test
			identitySpec := &fedv1alpha1.IdentitySpec{
				FederationRef: fedv1alpha1.FederationRef{
					Kind: "KubernetesFederation",
					Name: "test-fed",
				},
			}

			got := reconciler.shouldKeepCredential(context.Background(), reconciler.Log, tt.credential, identitySpec)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestReconcile(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = fedv1alpha1.AddToScheme(scheme)
	_ = genv1alpha1.AddToScheme(scheme)
	_ = v1.AddToScheme(scheme)

	namespace := "test-namespace"

	tests := []struct {
		name                    string
		identity                *fedv1alpha1.AuthorizedIdentity
		objects                 []client.Object
		expectedCredentialsLeft int
	}{
		{
			name: "removes credentials with missing GeneratorState",
			identity: &fedv1alpha1.AuthorizedIdentity{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-identity",
				},
				Spec: fedv1alpha1.AuthorizedIdentitySpec{
					IdentitySpec: fedv1alpha1.IdentitySpec{
						FederationRef: fedv1alpha1.FederationRef{
							Kind: "Kubernetes",
							Name: "test-federation",
						},
					},
					IssuedCredentials: []fedv1alpha1.IssuedCredential{
						{
							SourceRef: fedv1alpha1.SourceRef{
								Kind: "Generator",
								Name: "test-gen",
							},
							StateRef: &fedv1alpha1.StateRef{
								Kind:       "GeneratorState",
								APIVersion: "generators.external-secrets.io/v1alpha1",
								Name:       "existing-state",
								Namespace:  &namespace,
							},
						},
						{
							SourceRef: fedv1alpha1.SourceRef{
								Kind: "Generator",
								Name: "test-gen",
							},
							StateRef: &fedv1alpha1.StateRef{
								Kind:       "GeneratorState",
								APIVersion: "generators.external-secrets.io/v1alpha1",
								Name:       "missing-state",
								Namespace:  &namespace,
							},
						},
					},
				},
			},
			objects: []client.Object{
				&genv1alpha1.GeneratorState{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "existing-state",
						Namespace: namespace,
					},
				},
			},
			expectedCredentialsLeft: 1,
		},
		{
			name: "keeps credentials without StateRef or WorkloadBinding",
			identity: &fedv1alpha1.AuthorizedIdentity{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-identity",
				},
				Spec: fedv1alpha1.AuthorizedIdentitySpec{
					IdentitySpec: fedv1alpha1.IdentitySpec{
						FederationRef: fedv1alpha1.FederationRef{
							Kind: "Kubernetes",
							Name: "test-federation",
						},
					},
					IssuedCredentials: []fedv1alpha1.IssuedCredential{
						{
							SourceRef: fedv1alpha1.SourceRef{
								Kind: "ClusterSecretStore",
								Name: "test-store",
							},
						},
					},
				},
			},
			objects:                 []client.Object{},
			expectedCredentialsLeft: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.objects = append(tt.objects, tt.identity)
			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(tt.objects...).
				Build()

			reconciler := &AuthorizedIdentityReconciler{
				Client: fakeClient,
				Log:    logr.Discard(),
				Scheme: scheme,
			}

			_, err := reconciler.Reconcile(context.Background(), ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name: tt.identity.Name,
				},
			})
			assert.NoError(t, err)

			// Verify the identity was updated
			updatedIdentity := &fedv1alpha1.AuthorizedIdentity{}
			err = fakeClient.Get(context.Background(), types.NamespacedName{
				Name: tt.identity.Name,
			}, updatedIdentity)
			assert.NoError(t, err)
			assert.Len(t, updatedIdentity.Spec.IssuedCredentials, tt.expectedCredentialsLeft)
		})
	}
}
