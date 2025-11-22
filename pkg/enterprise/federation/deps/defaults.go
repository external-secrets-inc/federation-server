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
	"github.com/external-secrets/external-secrets/pkg/controllers/secretstore"
	"github.com/external-secrets/external-secrets/runtime/esutils/resolvers"
)

type defaultSecretStoreFactory struct{}

func (defaultSecretStoreFactory) New(cl client.Client, controllerClass string, enableFloodGate bool) SecretStoreManager {
	return secretstore.NewManager(cl, controllerClass, enableFloodGate)
}

type defaultGeneratorResolver struct{}

func (defaultGeneratorResolver) Resolve(ctx context.Context, cl client.Client, scheme *runtime.Scheme, namespace string, ref *esv1.GeneratorRef) (genv1alpha1.Generator, *apiextensions.JSON, error) {
	return resolvers.GeneratorRef(ctx, cl, scheme, namespace, ref)
}

// DefaultDependencies returns the in-tree implementations that federation
// relies on today.
func DefaultDependencies() Dependencies {
	return Dependencies{
		SecretStoreFactory: defaultSecretStoreFactory{},
		GeneratorResolver:  defaultGeneratorResolver{},
	}
}
