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
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	idfedv1alpha1 "github.com/external-secrets/external-secrets-federation/apis/enterprise/federation/identity/v1alpha1"
	fedv1alpha1 "github.com/external-secrets/external-secrets-federation/apis/enterprise/federation/v1alpha1"
	"github.com/external-secrets/external-secrets-federation/pkg/enterprise/federation/store"
)

func TestPingIdentityFederationController_Reconcile(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = idfedv1alpha1.AddToScheme(scheme)
	_ = fedv1alpha1.AddToScheme(scheme)

	tests := []struct {
		name                 string
		pingidentityFederation *idfedv1alpha1.PingIdentityFederation
		expectedRegion       string
		expectedEnvironmentID string
		expectError          bool
	}{
		{
			name: "reconcile with region com",
			pingidentityFederation: &idfedv1alpha1.PingIdentityFederation{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-pingidentity",
				},
				Spec: idfedv1alpha1.PingIdentityFederationSpec{
					Region:        "com",
					EnvironmentID: "12345678-1234-1234-1234-123456789abc",
				},
			},
			expectedRegion:       "com",
			expectedEnvironmentID: "12345678-1234-1234-1234-123456789abc",
			expectError:          false,
		},
		{
			name: "reconcile with region eu",
			pingidentityFederation: &idfedv1alpha1.PingIdentityFederation{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-pingidentity-eu",
				},
				Spec: idfedv1alpha1.PingIdentityFederationSpec{
					Region:        "eu",
					EnvironmentID: "87654321-4321-4321-4321-cba987654321",
				},
			},
			expectedRegion:       "eu",
			expectedEnvironmentID: "87654321-4321-4321-4321-cba987654321",
			expectError:          false,
		},
		{
			name: "reconcile with region asia",
			pingidentityFederation: &idfedv1alpha1.PingIdentityFederation{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-pingidentity-asia",
				},
				Spec: idfedv1alpha1.PingIdentityFederationSpec{
					Region:        "asia",
					EnvironmentID: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
				},
			},
			expectedRegion:       "asia",
			expectedEnvironmentID: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
			expectError:          false,
		},
		{
			name: "reconcile with region ca",
			pingidentityFederation: &idfedv1alpha1.PingIdentityFederation{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-pingidentity-ca",
				},
				Spec: idfedv1alpha1.PingIdentityFederationSpec{
					Region:        "ca",
					EnvironmentID: "cccccccc-cccc-cccc-cccc-cccccccccccc",
				},
			},
			expectedRegion:       "ca",
			expectedEnvironmentID: "cccccccc-cccc-cccc-cccc-cccccccccccc",
			expectError:          false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(tt.pingidentityFederation).
				Build()

			controller := &PingIdentityFederationController{
				Client: fakeClient,
				Log:    logr.Discard(),
				Scheme: scheme,
			}

			req := ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name: tt.pingidentityFederation.Name,
				},
			}

			ctx := context.Background()
			result, err := controller.Reconcile(ctx, req)

			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, ctrl.Result{}, result)

				// Verify provider was registered in store
				ref := fedv1alpha1.FederationRef{
					Name: tt.pingidentityFederation.Name,
					Kind: "PingIdentityFederation",
				}

				provider := store.GetStore(ref)
				require.NotNil(t, provider, "provider should be registered in store")
			}
		})
	}
}

func TestPingIdentityFederationController_Reconcile_NotFound(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = idfedv1alpha1.AddToScheme(scheme)

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	controller := &PingIdentityFederationController{
		Client: fakeClient,
		Log:    logr.Discard(),
		Scheme: scheme,
	}

	req := ctrl.Request{
		NamespacedName: types.NamespacedName{
			Name: "non-existent",
		},
	}

	ctx := context.Background()
	result, err := controller.Reconcile(ctx, req)

	// Should not error on NotFound - controller-runtime ignores it
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)
}
