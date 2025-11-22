// Copyright External Secrets Inc.
// SPDX-License-Identifier: Apache-2.0

package deps

import (
	"context"

	apiextensions "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	genv1alpha1 "github.com/external-secrets/external-secrets/apis/generators/v1alpha1"
)

// SecretStoreManager exposes the minimal surface needed by federation code to
// resolve a SecretStore/ClusterSecretStore into a provider client.
type SecretStoreManager interface {
	Get(ctx context.Context, storeRef esv1.SecretStoreRef, namespace string, sourceRef *esv1.StoreGeneratorSourceRef) (esv1.SecretsClient, error)
}

// SecretStoreManagerFactory creates a SecretStoreManager bound to a client and
// controller-class configuration. Using a factory lets federation code avoid a
// direct dependency on the concrete manager implementation.
type SecretStoreManagerFactory interface {
	New(client.Client, string, bool) SecretStoreManager
}

// GeneratorResolver resolves a generator reference to the generator
// implementation plus the serialized generator object.
type GeneratorResolver interface {
	Resolve(ctx context.Context, cl client.Client, scheme *runtime.Scheme, namespace string, ref *esv1.GeneratorRef) (genv1alpha1.Generator, *apiextensions.JSON, error)
}

// Dependencies wires the optional federation seams. Callers can override these
// to swap in fakes during tests or alternate implementations during the repo
// split.
type Dependencies struct {
	SecretStoreFactory SecretStoreManagerFactory
	GeneratorResolver  GeneratorResolver
}
