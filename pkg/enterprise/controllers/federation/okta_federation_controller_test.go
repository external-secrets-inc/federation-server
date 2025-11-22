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

func TestOktaFederationController_Reconcile(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = idfedv1alpha1.AddToScheme(scheme)
	_ = fedv1alpha1.AddToScheme(scheme)

	tests := []struct {
		name                  string
		oktaFederation        *idfedv1alpha1.OktaFederation
		expectedDomain        string
		expectedAuthServerID  string
		expectError           bool
	}{
		{
			name: "reconcile with default auth server",
			oktaFederation: &idfedv1alpha1.OktaFederation{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-okta",
				},
				Spec: idfedv1alpha1.OktaFederationSpec{
					Domain:                "https://dev-12345.okta.com",
					AuthorizationServerID: "default",
				},
			},
			expectedDomain:       "https://dev-12345.okta.com",
			expectedAuthServerID: "default",
			expectError:          false,
		},
		{
			name: "reconcile with custom auth server",
			oktaFederation: &idfedv1alpha1.OktaFederation{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-okta-custom",
				},
				Spec: idfedv1alpha1.OktaFederationSpec{
					Domain:                "https://custom.okta.com",
					AuthorizationServerID: "custom-server",
				},
			},
			expectedDomain:       "https://custom.okta.com",
			expectedAuthServerID: "custom-server",
			expectError:          false,
		},
		{
			name: "reconcile with empty auth server ID (defaults to default)",
			oktaFederation: &idfedv1alpha1.OktaFederation{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-okta-empty",
				},
				Spec: idfedv1alpha1.OktaFederationSpec{
					Domain: "https://dev-67890.okta.com",
				},
			},
			expectedDomain:       "https://dev-67890.okta.com",
			expectedAuthServerID: "default",
			expectError:          false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(tt.oktaFederation).
				Build()

			controller := &OktaFederationController{
				Client: fakeClient,
				Log:    logr.Discard(),
				Scheme: scheme,
			}

			req := ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name: tt.oktaFederation.Name,
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
					Name: tt.oktaFederation.Name,
					Kind: "OktaFederation",
				}

				provider := store.GetStore(ref)
				require.NotNil(t, provider, "provider should be registered in store")
			}
		})
	}
}

func TestOktaFederationController_Reconcile_NotFound(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = idfedv1alpha1.AddToScheme(scheme)

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	controller := &OktaFederationController{
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
