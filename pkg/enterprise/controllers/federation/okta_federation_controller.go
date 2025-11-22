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

// Package federation implements federation controllers.
package federation

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"

	idfedv1alpha1 "github.com/external-secrets/external-secrets-federation/apis/enterprise/federation/identity/v1alpha1"
	fedv1alpha1 "github.com/external-secrets/external-secrets-federation/apis/enterprise/federation/v1alpha1"
	"github.com/external-secrets/external-secrets-federation/pkg/enterprise/federation/provider"
	"github.com/external-secrets/external-secrets-federation/pkg/enterprise/federation/store"
)

// OktaFederationController reconciles OktaFederation resources.
type OktaFederationController struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
}

// Reconcile reconciles an OktaFederation resource.
func (c *OktaFederationController) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, err error) {
	okta := &idfedv1alpha1.OktaFederation{}
	if err := c.Get(ctx, req.NamespacedName, okta); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Create FederationRef for this Okta federation
	ref := fedv1alpha1.FederationRef{
		Name: okta.Name,
		Kind: "OktaFederation",
	}

	// Create Okta provider with configuration from Spec
	prov := provider.NewOktaProvider(okta.Spec.Domain, okta.Spec.AuthorizationServerID)

	// If ManagementAPI is configured, fetch the API token from Secret
	if okta.Spec.ManagementAPI != nil {
		apiToken, err := c.getAPITokenFromSecret(ctx, okta.Spec.ManagementAPI.APITokenSecretRef)
		if err != nil {
			c.Log.Error(err, "Failed to get Okta API token from secret",
				"name", okta.Name,
				"secretName", okta.Spec.ManagementAPI.APITokenSecretRef.Name)
			// Continue without API token - CheckIdentityExists will be skipped
		} else {
			prov.ManagementAPIToken = apiToken
			c.Log.Info("Configured Okta Management API token",
				"name", okta.Name)
		}
	}

	// Register provider in the federation store
	store.AddStore(ref, prov)

	c.Log.Info("Registered Okta federation provider",
		"name", okta.Name,
		"domain", okta.Spec.Domain,
		"authServerId", okta.Spec.AuthorizationServerID)

	return ctrl.Result{}, nil
}

// getAPITokenFromSecret retrieves the API token from a Kubernetes Secret.
func (c *OktaFederationController) getAPITokenFromSecret(ctx context.Context, selector idfedv1alpha1.SecretKeySelector) (string, error) {
	secret := &v1.Secret{}
	namespace := selector.Namespace
	if namespace == "" {
		// Default to controller's namespace if not specified
		namespace = "external-secrets"
	}

	err := c.Get(ctx, types.NamespacedName{
		Name:      selector.Name,
		Namespace: namespace,
	}, secret)
	if err != nil {
		return "", err
	}

	tokenBytes, ok := secret.Data[selector.Key]
	if !ok {
		return "", fmt.Errorf("secret %s does not contain key %s", client.ObjectKeyFromObject(secret).String(), selector.Key)
	}

	return string(tokenBytes), nil
}

// SetupWithManager returns a new controller builder that will be started by the provided Manager.
func (c *OktaFederationController) SetupWithManager(mgr ctrl.Manager, opts controller.Options) error {
	return ctrl.NewControllerManagedBy(mgr).
		WithOptions(opts).
		For(&idfedv1alpha1.OktaFederation{}).
		Complete(c)
}
