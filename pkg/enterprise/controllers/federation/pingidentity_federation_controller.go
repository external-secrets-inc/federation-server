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

// PingIdentityFederationController reconciles PingIdentityFederation resources.
type PingIdentityFederationController struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
}

// Reconcile reconciles a PingIdentityFederation resource.
func (c *PingIdentityFederationController) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, err error) {
	pingidentity := &idfedv1alpha1.PingIdentityFederation{}
	if err := c.Get(ctx, req.NamespacedName, pingidentity); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Create FederationRef for this PingIdentity federation
	ref := fedv1alpha1.FederationRef{
		Name: pingidentity.Name,
		Kind: "PingIdentityFederation",
	}

	// Create PingIdentity provider with configuration from Spec
	prov := provider.NewPingIdentityProvider(pingidentity.Spec.Region, pingidentity.Spec.EnvironmentID)

	// If ManagementAPI is configured, fetch credentials from Secrets
	if pingidentity.Spec.ManagementAPI != nil {
		clientID, err := c.getSecretValue(ctx, pingidentity.Spec.ManagementAPI.ClientIDSecretRef)
		if err != nil {
			c.Log.Error(err, "Failed to get PingOne client ID from secret",
				"name", pingidentity.Name,
				"secretName", pingidentity.Spec.ManagementAPI.ClientIDSecretRef.Name)
			// Continue without management API - CheckIdentityExists will be skipped
		} else {
			clientSecret, err := c.getSecretValue(ctx, pingidentity.Spec.ManagementAPI.ClientSecretRef)
			if err != nil {
				c.Log.Error(err, "Failed to get PingOne client secret from secret",
					"name", pingidentity.Name,
					"secretName", pingidentity.Spec.ManagementAPI.ClientSecretRef.Name)
				// Continue without management API - CheckIdentityExists will be skipped
			} else {
				prov.ManagementClientID = clientID
				prov.ManagementClientSecret = clientSecret
				c.Log.Info("Configured PingOne Management API credentials",
					"name", pingidentity.Name)
			}
		}
	}

	// Register provider in the federation store
	store.AddStore(ref, prov)

	c.Log.Info("Registered PingIdentity federation provider",
		"name", pingidentity.Name,
		"region", pingidentity.Spec.Region,
		"environmentId", pingidentity.Spec.EnvironmentID)

	return ctrl.Result{}, nil
}

// getSecretValue retrieves a value from a Kubernetes Secret.
func (c *PingIdentityFederationController) getSecretValue(ctx context.Context, selector idfedv1alpha1.SecretKeySelector) (string, error) {
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

	valueBytes, ok := secret.Data[selector.Key]
	if !ok {
		return "", fmt.Errorf("secret %s does not contain key %s", client.ObjectKeyFromObject(secret).String(), selector.Key)
	}

	return string(valueBytes), nil
}

// SetupWithManager returns a new controller builder that will be started by the provided Manager.
func (c *PingIdentityFederationController) SetupWithManager(mgr ctrl.Manager, opts controller.Options) error {
	return ctrl.NewControllerManagedBy(mgr).
		WithOptions(opts).
		For(&idfedv1alpha1.PingIdentityFederation{}).
		Complete(c)
}
