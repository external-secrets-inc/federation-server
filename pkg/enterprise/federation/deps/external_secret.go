// Copyright External Secrets Inc.
// SPDX-License-Identifier: Apache-2.0

package deps

import (
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// ExternalSecretAccessor exposes the minimal interactions the federation
// server requires from the core ExternalSecret reconciler. This allows the
// federation packages to depend on a narrow contract instead of the full
// controller implementation, which simplifies extracting the federation
// code into a standalone repository later on.
type ExternalSecretAccessor interface {
	// RuntimeClient returns a controller-runtime client scoped to the same
	// cache configuration as the ExternalSecret reconciler.
	RuntimeClient() client.Client
	// RuntimeScheme returns the runtime scheme associated with the reconciler.
	RuntimeScheme() *runtime.Scheme
	// ControllerClassName identifies the controller-class label used to scope
	// reconcilers and managers.
	ControllerClassName() string
	// FloodGateEnabled indicates whether the floodgate feature is active.
	FloodGateEnabled() bool
}
