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

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"

	idfedv1alpha1 "github.com/external-secrets/external-secrets-federation/apis/enterprise/federation/identity/v1alpha1"
	fedv1alpha1 "github.com/external-secrets/external-secrets-federation/apis/enterprise/federation/v1alpha1"
	"github.com/external-secrets/external-secrets-federation/pkg/enterprise/federation/provider"
	"github.com/external-secrets/external-secrets-federation/pkg/enterprise/federation/store"
)

// KubernetesFederationController reconciles KubernetesFederation resources.
// TODO - make this operate over all *.federation.external-secrets.io resources.
type KubernetesFederationController struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
}

// Reconcile reconciles a KubernetesFederation resource.
func (c *KubernetesFederationController) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, err error) {
	// Get the Authorization.fedetarion.external-secrets.io object
	authorization := &idfedv1alpha1.KubernetesFederation{}
	if err := c.Get(ctx, req.NamespacedName, authorization); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	ref := fedv1alpha1.FederationRef{
		Name: authorization.Name,
		Kind: "KubernetesFederation",
	}
	prov := provider.NewProvider(authorization.Spec.URL)
	// Get the Spec and add it to the federation store
	store.AddStore(ref, prov)
	return ctrl.Result{}, nil
}

// SetupWithManager returns a new controller builder that will be started by the provided Manager.
// SetupWithManager returns a new controller builder that will be started by the provided Manager.
func (c *KubernetesFederationController) SetupWithManager(mgr ctrl.Manager, _ controller.Options) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&idfedv1alpha1.KubernetesFederation{}).
		Complete(c)
}
