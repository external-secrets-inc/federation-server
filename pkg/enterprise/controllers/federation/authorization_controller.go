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
	"log"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"

	"github.com/external-secrets/external-secrets-federation/apis/enterprise/federation/v1alpha1"
	"github.com/external-secrets/external-secrets-federation/pkg/enterprise/federation/server"
	"github.com/external-secrets/external-secrets-federation/pkg/enterprise/federation/store"
)

const authorizationFinalizer = "authorization.federation.external-secrets.io/finalizer"

// AuthorizationController reconciles Authorization resources.
type AuthorizationController struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
}

// Reconcile reconciles an Authorization resource.
func (c *AuthorizationController) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, err error) {
	// Get the Authorization.fedetarion.external-secrets.io object
	authorization := &v1alpha1.Authorization{}
	if err := c.Get(ctx, req.NamespacedName, authorization); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	principal, err := authorization.Spec.Principal()
	if err != nil {
		return ctrl.Result{}, err
	}

	if authorization.GetDeletionTimestamp() != nil {
		return c.cleanup(ctx, authorization, principal)
	}

	if err := c.setFinalizer(ctx, authorization); err != nil {
		return ctrl.Result{Requeue: true}, err
	}

	authority, err := authorization.Spec.Authority()
	if err != nil {
		if errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	if authorization.Spec.RequiresTLS() {
		server.AddTLSAllowedID(principal)
	}

	// Get the Spec and add it to the federation store
	store.Add(authority, &authorization.Spec)

	return ctrl.Result{}, nil
}

func (c *AuthorizationController) cleanup(ctx context.Context, authorization *v1alpha1.Authorization, principal string) (result ctrl.Result, err error) {
	if authorization.Spec.RequiresTLS() {
		server.RemoveTLSAllowedID(principal)
	}

	for i, f := range authorization.GetFinalizers() {
		if f == authorizationFinalizer {
			authorization.SetFinalizers(append(authorization.GetFinalizers()[:i], authorization.GetFinalizers()[i+1:]...))
			break
		}
	}
	if err := c.Update(ctx, authorization); err != nil {
		log.Printf("failed to remove finalizer: %v", err)
		return ctrl.Result{Requeue: true}, err
	}

	return ctrl.Result{}, nil
}

func (c *AuthorizationController) setFinalizer(ctx context.Context, authorization *v1alpha1.Authorization) error {
	hasFinalizer := false
	for _, f := range authorization.GetFinalizers() {
		if f == authorizationFinalizer {
			hasFinalizer = true
			break
		}
	}
	if !hasFinalizer {
		authorization.SetFinalizers(append(authorization.GetFinalizers(), authorizationFinalizer))
		if err := c.Update(ctx, authorization); err != nil {
			log.Printf("failed to add finalizer: %v", err)
			return err
		}
	}
	return nil
}

// SetupWithManager returns a new controller builder that will be started by the provided Manager.
func (c *AuthorizationController) SetupWithManager(mgr ctrl.Manager, opts controller.Options) error {
	return ctrl.NewControllerManagedBy(mgr).
		WithOptions(opts).
		For(&v1alpha1.Authorization{}).
		Complete(c)
}
