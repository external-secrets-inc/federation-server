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
	"time"

	"github.com/go-logr/logr"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"

	fedv1alpha1 "github.com/external-secrets/external-secrets-federation/apis/enterprise/federation/v1alpha1"
	genv1alpha1 "github.com/external-secrets/external-secrets/apis/generators/v1alpha1"
	"github.com/external-secrets/external-secrets-federation/pkg/enterprise/federation/store"
)

// AuthorizedIdentityReconciler reconciles AuthorizedIdentity objects.
type AuthorizedIdentityReconciler struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
}

// Reconcile cleans up stale issuedCredentials from AuthorizedIdentity objects.
func (r *AuthorizedIdentityReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.WithValues("authorizedidentity", req.NamespacedName)

	// Get the AuthorizedIdentity object
	identity := &fedv1alpha1.AuthorizedIdentity{}
	if err := r.Get(ctx, req.NamespacedName, identity); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Track if we need to update
	needsUpdate := false
	validCredentials := []fedv1alpha1.IssuedCredential{}

	// Check each issued credential
	for _, credential := range identity.Spec.IssuedCredentials {
		if r.shouldKeepCredential(ctx, log, &credential, &identity.Spec.IdentitySpec) {
			validCredentials = append(validCredentials, credential)
		} else {
			needsUpdate = true
			log.Info("Removing stale credential",
				"sourceRef", credential.SourceRef.Name,
				"sourceKind", credential.SourceRef.Kind)

			// Delete associated GeneratorState if it exists
			if credential.StateRef != nil {
				if err := r.deleteGeneratorState(ctx, log, credential.StateRef); err != nil {
					log.Error(err, "Failed to delete GeneratorState, will retry",
						"name", credential.StateRef.Name,
						"namespace", credential.StateRef.Namespace)
					// Don't fail the reconciliation, we'll retry on next reconcile
				}
			}
		}
	}

	// Update if we removed any credentials
	if needsUpdate {
		identity.Spec.IssuedCredentials = validCredentials
		if err := r.Update(ctx, identity); err != nil {
			log.Error(err, "Failed to update AuthorizedIdentity")
			return ctrl.Result{}, err
		}
		log.Info("Updated AuthorizedIdentity", "remainingCredentials", len(validCredentials))
	}

	return ctrl.Result{RequeueAfter: time.Minute}, nil
}

// shouldKeepCredential determines if a credential should be kept or cleaned up.
func (r *AuthorizedIdentityReconciler) shouldKeepCredential(ctx context.Context, log logr.Logger, credential *fedv1alpha1.IssuedCredential, identitySpec *fedv1alpha1.IdentitySpec) bool {
	// Check if GeneratorState exists (if StateRef is present)
	if credential.StateRef != nil {
		stateExists := r.checkGeneratorStateExists(ctx, log, credential.StateRef)
		if !stateExists {
			log.V(1).Info("GeneratorState no longer exists",
				"name", credential.StateRef.Name,
				"namespace", credential.StateRef.Namespace)
			return false
		}
	}

	// Check if WorkloadBinding exists (if present)
	if credential.WorkloadBinding != nil {
		workloadExists := r.checkWorkloadExists(ctx, log, credential.WorkloadBinding)
		if !workloadExists {
			log.V(1).Info("Workload no longer exists",
				"kind", credential.WorkloadBinding.Kind,
				"name", credential.WorkloadBinding.Name,
				"namespace", credential.WorkloadBinding.Namespace)
			return false
		}
	}
	// check external identity provider (Okta, OIDC, etc.)
	identityExists := r.checkExternalIdentityExists(ctx, log, identitySpec)
	if !identityExists {
		return false
	}

	return true
}

// checkGeneratorStateExists checks if the referenced GeneratorState still exists.
func (r *AuthorizedIdentityReconciler) checkGeneratorStateExists(ctx context.Context, log logr.Logger, stateRef *fedv1alpha1.StateRef) bool {
	if stateRef == nil {
		return true
	}

	state := &genv1alpha1.GeneratorState{}
	namespace := ""
	if stateRef.Namespace != nil {
		namespace = *stateRef.Namespace
	}

	err := r.Get(ctx, types.NamespacedName{
		Name:      stateRef.Name,
		Namespace: namespace,
	}, state)

	if errors.IsNotFound(err) {
		return false
	}

	if err != nil {
		log.Error(err, "Error checking GeneratorState existence",
			"name", stateRef.Name,
			"namespace", namespace)
		// In case of error, keep the credential to avoid accidental deletion
		return true
	}

	return true
}

// deleteGeneratorState deletes the referenced GeneratorState resource.
func (r *AuthorizedIdentityReconciler) deleteGeneratorState(ctx context.Context, log logr.Logger, stateRef *fedv1alpha1.StateRef) error {
	if stateRef == nil {
		return nil
	}

	state := &genv1alpha1.GeneratorState{}
	namespace := ""
	if stateRef.Namespace != nil {
		namespace = *stateRef.Namespace
	}

	err := r.Get(ctx, types.NamespacedName{
		Name:      stateRef.Name,
		Namespace: namespace,
	}, state)

	if errors.IsNotFound(err) {
		// Already deleted, nothing to do
		return nil
	}

	if err != nil {
		return err
	}

	// Delete the GeneratorState
	if err := r.Delete(ctx, state); err != nil && !errors.IsNotFound(err) {
		return err
	}

	log.Info("Deleted GeneratorState",
		"name", stateRef.Name,
		"namespace", namespace)

	return nil
}

// checkWorkloadExists checks if the referenced workload (Pod or ServiceAccount) still exists.
func (r *AuthorizedIdentityReconciler) checkWorkloadExists(ctx context.Context, log logr.Logger, workload *fedv1alpha1.WorkloadBinding) bool {
	if workload == nil {
		return true
	}

	switch workload.Kind {
	case "Pod":
		pod := &v1.Pod{}
		err := r.Get(ctx, types.NamespacedName{
			Name:      workload.Name,
			Namespace: workload.Namespace,
		}, pod)

		if errors.IsNotFound(err) {
			return false
		}

		if err != nil {
			log.Error(err, "Error checking Pod existence",
				"name", workload.Name,
				"namespace", workload.Namespace)
			// In case of error, keep the credential to avoid accidental deletion
			return true
		}

		// Verify UID matches to ensure it's the same pod
		if string(pod.UID) != workload.UID {
			log.V(1).Info("Pod UID mismatch, treating as non-existent",
				"expected", workload.UID,
				"actual", pod.UID)
			return false
		}

		return true

	case "ServiceAccount":
		sa := &v1.ServiceAccount{}
		err := r.Get(ctx, types.NamespacedName{
			Name:      workload.Name,
			Namespace: workload.Namespace,
		}, sa)

		if errors.IsNotFound(err) {
			return false
		}

		if err != nil {
			log.Error(err, "Error checking ServiceAccount existence",
				"name", workload.Name,
				"namespace", workload.Namespace)
			// In case of error, keep the credential to avoid accidental deletion
			return true
		}

		// Verify UID matches
		if string(sa.UID) != workload.UID {
			log.V(1).Info("ServiceAccount UID mismatch, treating as non-existent",
				"expected", workload.UID,
				"actual", sa.UID)
			return false
		}

		return true

	default:
		log.Info("Unknown workload kind, keeping credential", "kind", workload.Kind)
		return true
	}
}

// checkExternalIdentityExists checks if an external identity (Okta app, OIDC client, etc.) still exists.
// This is used for OAuth2-based auth methods that don't have WorkloadBinding.
func (r *AuthorizedIdentityReconciler) checkExternalIdentityExists(ctx context.Context, log logr.Logger, identitySpec *fedv1alpha1.IdentitySpec) bool {
	// If no Subject is defined, we can't check - keep the credential
	if identitySpec.Subject == nil {
		log.V(1).Info("No subject defined in identity spec, keeping credential")
		return true
	}

	// Create a temporary AuthorizationSpec to use its Principal() helper method
	tempSpec := &fedv1alpha1.AuthorizationSpec{
		FederationRef: identitySpec.FederationRef,
		Subject:       identitySpec.Subject,
	}

	// Get the subject (client ID, etc.)
	subject, err := tempSpec.Principal()
	if err != nil {
		log.Error(err, "Failed to get principal from identity spec")
		return true // Keep credential on error to avoid accidental deletion
	}

	// Call store.CheckIfExists to check with the identity provider
	exists, err := store.CheckIfExists(ctx, identitySpec.FederationRef, subject)
	if err != nil {
		log.Error(err, "Ran identity check against provider and it failed",
			"federationRef", identitySpec.FederationRef,
			"subject", subject)
		return true // Keep credential on error to avoid accidental deletion
	}

	if !exists {
		log.Info("Ran identity check against provider - identity no longer exists",
			"federationRef", identitySpec.FederationRef,
			"subject", subject)
	} else {
		log.Info("Ran identity check against provider and it worked - identity is active",
			"federationRef", identitySpec.FederationRef,
			"subject", subject)
	}

	return exists
}

// SetupWithManager sets up the controller with the Manager.
func (r *AuthorizedIdentityReconciler) SetupWithManager(mgr ctrl.Manager, opts controller.Options) error {
	return ctrl.NewControllerManagedBy(mgr).
		WithOptions(opts).
		For(&fedv1alpha1.AuthorizedIdentity{}).
		Complete(r)
}
