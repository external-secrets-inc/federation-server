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

// Package server implements the federation server.
// Copyright External Secrets Inc.
// All Rights Reserved.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	fedv1alpha1 "github.com/external-secrets/external-secrets-federation/apis/enterprise/federation/v1alpha1"
	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	genv1alpha1 "github.com/external-secrets/external-secrets/apis/generators/v1alpha1"
	"github.com/external-secrets/external-secrets-federation/pkg/enterprise/federation/deps"
	"github.com/external-secrets/external-secrets-federation/pkg/enterprise/federation/server/auth"
	store "github.com/external-secrets/external-secrets-federation/pkg/enterprise/federation/store"
	"github.com/go-logr/logr"
	"github.com/labstack/echo/v4"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	v1 "k8s.io/api/core/v1"
	apiextensions "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

// Handler implements the federation server.
type Handler struct {
	client                 client.Client
	scheme                 *runtime.Scheme
	controllerClass        string
	floodGateEnabled       bool
	dependencies           deps.Dependencies
	mu                     sync.RWMutex
	log                    logr.Logger
	port                   string
	tlsPort                string
	tlsEnabled             bool
	spireAgentSocketPath   string
	generateSecretFn       func(ctx context.Context, generatorName string, generatorKind string, namespace string, resource *Resource) (map[string]string, string, string, error)
	getSecretFn            func(ctx context.Context, storeName string, name string) ([]byte, error)
	deleteGeneratorStateFn func(ctx context.Context, namespace string, labels labels.Selector) error
}

type Option func(*Handler)

// WithDependencies allows overriding the in-tree federation dependencies such
// as the secretstore manager factory and the generator resolver. This enables
// fakes in tests and custom implementations during the repo split.
func WithDependencies(dep deps.Dependencies) Option {
	return func(s *Handler) {
		if dep.SecretStoreFactory == nil || dep.GeneratorResolver == nil {
			defaults := deps.DefaultDependencies()
			if dep.SecretStoreFactory == nil {
				dep.SecretStoreFactory = defaults.SecretStoreFactory
			}
			if dep.GeneratorResolver == nil {
				dep.GeneratorResolver = defaults.GeneratorResolver
			}
		}
		s.dependencies = dep
	}
}

// NewHandler creates a new Handler.
func NewHandler(accessor deps.ExternalSecretAccessor, port, tlsPort, socketPath string, tlsEnabled bool, options ...Option) *Handler {
	log := ctrl.Log.WithName("federationserver")
	s := &Handler{
		client:           accessor.RuntimeClient(),
		scheme:           accessor.RuntimeScheme(),
		controllerClass:  accessor.ControllerClassName(),
		floodGateEnabled: accessor.FloodGateEnabled(),
		dependencies:     deps.DefaultDependencies(),
		log:              log,
		mu:               sync.RWMutex{},
		port:             port,
		tlsPort:          tlsPort,
		tlsEnabled:       tlsEnabled,
	}
	s.spireAgentSocketPath = socketPath
	s.generateSecretFn = s.generateSecret
	s.getSecretFn = s.getSecret
	s.deleteGeneratorStateFn = s.deleteGeneratorState
	for _, opt := range options {
		opt(s)
	}
	return s
}

// SetupEcho sets up the echo server.
func (s *Handler) SetupEcho(ctx context.Context) *echo.Echo {
	e := echo.New()
	e.Server.BaseContext = func(_ net.Listener) context.Context {
		return ctx
	}
	e.Use(s.authMiddleware)

	e.POST("/secretstore/:secretStoreName/secrets/:secretName", s.postSecrets)
	e.POST("/generators/:generatorNamespace/:generatorKind/:generatorName", s.generateSecrets)
	e.DELETE("/generators/:generatorNamespace/:generatorKind/:generatorName", s.revokeSelf)
	e.POST("/generators/:generatorNamespace/revoke", s.revokeCredentialsOf)

	s.startHTTPServer(ctx, e)
	if s.tlsEnabled {
		s.startMTLSServer(ctx, e)
	}

	return e
}

func (s *Handler) startHTTPServer(ctx context.Context, e *echo.Echo) {
	srv := &http.Server{
		Addr:              s.port,
		Handler:           e,
		ReadHeaderTimeout: 10 * time.Second,
		BaseContext: func(_ net.Listener) context.Context {
			return ctx
		},
	}

	go func() {
		s.log.Info("Starting federation HTTP server")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.log.Error(err, "failed to start federation http server")
		}
	}()
}

func (s *Handler) startMTLSServer(ctx context.Context, e *echo.Echo) {
	source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(s.spireAgentSocketPath)))
	if err != nil {
		s.log.Error(err, "failed to create x509 source")
	}
	tlsConfig := tlsconfig.MTLSServerConfig(source, source, tlsconfig.AuthorizeAny())
	tlsConfig.VerifyConnection = verifyConnection

	tlsSrv := &http.Server{
		Addr:              s.tlsPort,
		Handler:           e,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 10 * time.Second,
		BaseContext: func(_ net.Listener) context.Context {
			return ctx
		},
	}

	go func() {
		s.log.Info("Starting federation TLS server")
		if err := tlsSrv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			s.log.Error(err, "failed to start federation tls server")
		}
	}()
}

func (s *Handler) authMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		var lastErr error
		for _, authenticator := range auth.Registry {
			info, err := authenticator.Authenticate(c.Request())
			if err != nil {
				lastErr = err
				continue
			}
			c.Set("authInfo", info)

			// Parse optional x-workload-token header
			workloadInfo, err := auth.ParseWorkloadToken(c.Request())
			if err != nil {
				// If token is malformed, return error
				return c.JSON(http.StatusBadRequest, fmt.Sprintf("invalid x-workload-token: %s", err.Error()))
			}

			// Merge with existing KubeAttributes if present
			if workloadInfo == nil && info.KubeAttributes != nil {
				// Use KubeAttributes from authInfo (e.g., from SPIFFE)
				workloadInfo = &auth.WorkloadInfo{
					Namespace:      info.KubeAttributes.Namespace,
					ServiceAccount: info.KubeAttributes.ServiceAccount,
					Pod:            info.KubeAttributes.Pod,
				}
			}

			// Set workloadInfo in context (may be nil)
			c.Set("workloadInfo", workloadInfo)

			return next(c)
		}
		return c.JSON(http.StatusUnauthorized, lastErr.Error())
	}
}

func (s *Handler) generateSecrets(c echo.Context) error {
	authInfo := c.Get("authInfo").(*auth.Info)
	workloadInfo, _ := c.Get("workloadInfo").(*auth.WorkloadInfo)

	AuthorizationSpecs := store.Get(authInfo.Provider)
	generatorName := c.Param("generatorName")
	generatorKind := c.Param("generatorKind")
	generatorNamespace := c.Param("generatorNamespace")
	d := fedv1alpha1.AllowedGenerator{
		Name:      generatorName,
		Kind:      generatorKind,
		Namespace: generatorNamespace,
	}

	// Build resource based on workload context
	var resource *Resource
	if workloadInfo != nil {
		// Has workload context (from x-workload-token or KubeAttributes)
		if workloadInfo.ServiceAccount == nil {
			return c.JSON(http.StatusBadRequest, "missing kubernetes service account")
		}

		owner := workloadInfo.ServiceAccount.Name
		if workloadInfo.Pod != nil {
			owner = workloadInfo.Pod.Name
		}

		resource = &Resource{
			Name:       generatorName,
			AuthMethod: "KubernetesServiceAccount",
			Owner:      owner,
			OwnerAttributes: map[string]string{
				"namespace":            workloadInfo.Namespace,
				"issuer":               authInfo.Provider,
				"serviceaccount-uid":   workloadInfo.ServiceAccount.UID,
				"service-account-name": workloadInfo.ServiceAccount.Name,
			},
		}
		if workloadInfo.Pod != nil {
			resource.OwnerAttributes["pod-uid"] = workloadInfo.Pod.UID
		}
	} else {
		// OAuth2-based authentication (Okta, OIDC, etc. - no workload context)
		resource = &Resource{
			Name:       generatorName,
			AuthMethod: authInfo.Method, // "okta", "oidc", etc.
			Owner:      authInfo.Subject,
			OwnerAttributes: map[string]string{
				"issuer":  authInfo.Provider,
				"subject": authInfo.Subject,
				"method":  authInfo.Method,
			},
		}
	}
	for _, spec := range AuthorizationSpecs {
		principal, err := spec.Principal()
		if err != nil {
			return c.JSON(http.StatusBadRequest, err.Error())
		}
		if contains(spec.AllowedGenerators, d) && principal == authInfo.Subject {
			secret, stateName, stateNamespace, err := s.generateSecretFn(c.Request().Context(), generatorName, generatorKind, generatorNamespace, resource)
			if err != nil {
				return c.JSON(http.StatusBadRequest, err.Error())
			}

			// Create or update AuthorizedIdentity
			stateRef := buildStateRef(stateName, stateNamespace)
			if err := s.upsertIdentity(c.Request().Context(), authInfo, workloadInfo, &spec.FederationRef, generatorName, "", generatorKind, generatorNamespace, stateRef); err != nil {
				s.log.Error(err, "failed to upsert identity for generator access")
			}

			return c.JSON(http.StatusOK, secret)
		}
	}
	return c.JSON(http.StatusNotFound, "Not Found")
}

func contains[T fedv1alpha1.AllowedGenerator | fedv1alpha1.AllowedGeneratorState](slice []T, item T) bool {
	switch any(item).(type) {
	case fedv1alpha1.AllowedGenerator:
		for _, v := range slice {
			sliceGen := any(v).(fedv1alpha1.AllowedGenerator)
			itemGen := any(item).(fedv1alpha1.AllowedGenerator)

			if sliceGen.Name == itemGen.Name && sliceGen.Kind == itemGen.Kind && sliceGen.Namespace == itemGen.Namespace {
				return true
			}
		}
	case fedv1alpha1.AllowedGeneratorState:
		for _, v := range slice {
			sliceState := any(v).(fedv1alpha1.AllowedGeneratorState)
			itemState := any(item).(fedv1alpha1.AllowedGeneratorState)
			if sliceState.Namespace == itemState.Namespace {
				return true
			}
		}
	}
	return false
}

func (s *Handler) postSecrets(c echo.Context) error {
	authInfo := c.Get("authInfo").(*auth.Info)
	workloadInfo, _ := c.Get("workloadInfo").(*auth.WorkloadInfo)

	AuthorizationSpecs := store.Get(authInfo.Provider)
	storeName := c.Param("secretStoreName")
	name := c.Param("secretName")
	for _, spec := range AuthorizationSpecs {
		principal, err := spec.Principal()
		if err != nil {
			return c.JSON(http.StatusBadRequest, err.Error())
		}
		if slices.Contains(spec.AllowedClusterSecretStores, storeName) && principal == authInfo.Subject {
			secret, err := s.getSecretFn(c.Request().Context(), storeName, name)
			if err != nil {
				return c.JSON(http.StatusBadRequest, err.Error())
			}

			// Create or update AuthorizedIdentity
			if err := s.upsertIdentity(c.Request().Context(), authInfo, workloadInfo, &spec.FederationRef, storeName, name, "", "", nil); err != nil {
				s.log.Error(err, "failed to upsert identity for secret store access")
			}

			return c.JSON(http.StatusOK, string(secret))
		}
	}
	return c.JSON(http.StatusNotFound, "Not Found")
}

func (s *Handler) revokeSelf(c echo.Context) error {
	authInfo := c.Get("authInfo").(*auth.Info)
	workloadInfo, _ := c.Get("workloadInfo").(*auth.WorkloadInfo)

	AuthorizationSpecs := store.Get(authInfo.Provider)
	generatorNamespace := c.Param("generatorNamespace")
	generatorName := c.Param("generatorName")
	generatorKind := c.Param("generatorKind")

	if workloadInfo == nil {
		return c.JSON(http.StatusBadRequest, "missing workload context")
	}

	if workloadInfo.ServiceAccount == nil {
		return c.JSON(http.StatusBadRequest, "missing kubernetes service account")
	}

	for _, spec := range AuthorizationSpecs {
		principal, err := spec.Principal()
		if err != nil {
			return c.JSON(http.StatusBadRequest, err.Error())
		}
		if !contains(spec.AllowedGenerators, fedv1alpha1.AllowedGenerator{
			Name:      generatorName,
			Kind:      generatorKind,
			Namespace: generatorNamespace,
		}) || principal != authInfo.Subject {
			continue
		}
		owner := workloadInfo.ServiceAccount.Name
		if workloadInfo.Pod != nil {
			owner = workloadInfo.Pod.Name
		}
		labels := labels.SelectorFromSet(labels.Set{
			"federation.externalsecrets.com/owner":          owner,
			"federation.externalsecrets.com/generator":      generatorName,
			"federation.externalsecrets.com/generator-kind": generatorKind,
		})
		err = s.deleteGeneratorStateFn(c.Request().Context(), generatorNamespace, labels)
		if err != nil {
			return c.JSON(http.StatusBadRequest, err.Error())
		}
		return c.JSON(http.StatusOK, nil)
	}
	return c.JSON(http.StatusNotFound, "Not Found")
}

type deleteRequest struct {
	Owner     string `json:"owner"`
	Namespace string `json:"namespace"`
}

func (s *Handler) revokeCredentialsOf(c echo.Context) error {
	var req deleteRequest
	err := c.Bind(&req)
	if err != nil {
		return c.JSON(http.StatusBadRequest, err.Error())
	}

	authInfo := c.Get("authInfo").(*auth.Info)

	AuthorizationSpecs := store.Get(authInfo.Provider)
	generatorNamespace := c.Param("generatorNamespace")
	for _, spec := range AuthorizationSpecs {
		principal, err := spec.Principal()
		if err != nil {
			return c.JSON(http.StatusBadRequest, err.Error())
		}

		if contains(spec.AllowedGeneratorStates, fedv1alpha1.AllowedGeneratorState{
			Namespace: generatorNamespace,
		}) && principal == authInfo.Subject {
			labels := labels.SelectorFromSet(labels.Set{
				"federation.externalsecrets.com/owner": req.Owner,
			})
			err = s.deleteGeneratorStateFn(c.Request().Context(), req.Namespace, labels)
			if err != nil {
				return c.JSON(http.StatusBadRequest, err.Error())
			}
			return c.JSON(http.StatusOK, "GeneratorState deleted")
		}
	}
	return c.JSON(http.StatusNotFound, "Not Found")
}

func (s *Handler) deleteGeneratorState(ctx context.Context, namespace string, labels labels.Selector) error {
	generators := &genv1alpha1.GeneratorStateList{}
	err := s.client.List(ctx, generators, &client.ListOptions{
		Namespace:     namespace,
		LabelSelector: labels,
	})
	if err != nil {
		return err
	}
	for _, generator := range generators.Items {
		err := s.client.Delete(ctx, &generator)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Handler) getSecret(ctx context.Context, storeName, name string) ([]byte, error) {
	storeRef := esv1.SecretStoreRef{
		Name: storeName,
		Kind: esv1.ClusterSecretStoreKind,
	}
	mgr := s.dependencies.SecretStoreFactory.New(s.client, s.controllerClass, s.floodGateEnabled)
	client, err := mgr.Get(ctx, storeRef, "", nil)
	if err != nil {
		return nil, err
	}
	ref := esv1.ExternalSecretDataRemoteRef{
		Key: name,
	}
	return client.GetSecret(ctx, ref)
}

func (s *Handler) generateSecret(ctx context.Context, generatorName, generatorKind, namespace string, resource *Resource) (map[string]string, string, string, error) {
	if resource == nil {
		return nil, "", "", errors.New("resource not found")
	}
	generatorRef := esv1.GeneratorRef{
		Name:       generatorName,
		Kind:       generatorKind,
		APIVersion: "generators.external-secrets.io/v1alpha1",
	}
	generator, obj, err := s.dependencies.GeneratorResolver.Resolve(ctx, s.client, s.scheme, namespace, &generatorRef)
	if err != nil {
		return nil, "", "", err
	}
	if generator == nil {
		return nil, "", "", errors.New("generator not found")
	}
	data, stateJSON, err := generator.Generate(ctx, obj, s.client, namespace)
	if err != nil {
		return nil, "", "", err
	}
	attributes, err := json.Marshal(resource.OwnerAttributes)
	if err != nil {
		return nil, "", "", err
	}
	if stateJSON == nil {
		stateJSON = &apiextensions.JSON{Raw: []byte("{}")}
	}
	generatorState := genv1alpha1.GeneratorState{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: fmt.Sprintf("%s-%s-%s-", strings.ToLower(generatorKind), strings.ToLower(generatorName), strings.ToLower(resource.Owner)),
			Namespace:    namespace,
			Labels: map[string]string{
				"federation.externalsecrets.com/owner":          resource.Owner,
				"federation.externalsecrets.com/generator":      generatorName,
				"federation.externalsecrets.com/generator-kind": generatorKind,
			},
			Annotations: map[string]string{
				"federation.externalsecrets.com/owner-attributes": string(attributes),
			},
		},
		Spec: genv1alpha1.GeneratorStateSpec{
			Resource: obj,
			State:    stateJSON,
		},
	}
	// We can bind the Generator State to a GC-linked object
	if resource.AuthMethod == "KubernetesServiceAccount" {
		var cobj client.Object
		if _, ok := resource.OwnerAttributes["pod-uid"]; ok {
			pod := &v1.Pod{}
			err := s.client.Get(ctx, client.ObjectKey{Name: resource.Owner, Namespace: resource.OwnerAttributes["namespace"]}, pod)
			if err != nil {
				return nil, "", "", err
			}
			cobj = pod
		} else {
			sa := &v1.ServiceAccount{}
			err := s.client.Get(ctx, client.ObjectKey{Name: resource.Owner, Namespace: resource.OwnerAttributes["namespace"]}, sa)
			if err != nil {
				return nil, "", "", err
			}
			cobj = sa
		}
		if err := controllerutil.SetOwnerReference(cobj, &generatorState, s.scheme); err != nil {
			return nil, "", "", err
		}
	}
	// Any other types, cleanup is done via the `authorized_identity` controller.
	// TODO - bind workloads to these other type of credentials as well.
	err = s.client.Create(ctx, &generatorState)
	if err != nil {
		return nil, "", "", err
	}
	stringData := map[string]string{}
	for k, v := range data {
		stringData[k] = string(v)
	}
	return stringData, generatorState.Name, generatorState.Namespace, nil
}

// Resource represents a resource to be generated.
type Resource struct {
	Name            string            `json:"name"`
	Owner           string            `json:"owner"`
	OwnerAttributes map[string]string `json:"ownerAttributes"`
	AuthMethod      string            `json:"authMethod"`
}

// buildIdentitySpec constructs an IdentitySpec from authInfo and federationRef.
func buildIdentitySpec(authInfo *auth.Info, federationRef *fedv1alpha1.FederationRef) fedv1alpha1.IdentitySpec {
	identitySpec := fedv1alpha1.IdentitySpec{
		FederationRef: *federationRef,
	}

	if authInfo.Method == "spiffe" {
		identitySpec.Subject = &fedv1alpha1.FederationSubject{
			Spiffe: &fedv1alpha1.FederationSpiffe{
				SpiffeID: authInfo.Subject,
			},
		}
	} else {
		identitySpec.Subject = &fedv1alpha1.FederationSubject{
			OIDC: &fedv1alpha1.FederationOIDC{
				Issuer:  authInfo.Provider,
				Subject: authInfo.Subject,
			},
		}
	}

	return identitySpec
}

// buildSourceRef constructs a SourceRef for a SecretStore or Generator.
func buildSourceRef(name, kind, namespace string) fedv1alpha1.SourceRef {
	sourceRef := fedv1alpha1.SourceRef{
		Kind: kind,
		Name: name,
	}

	if kind == "ClusterSecretStore" {
		sourceRef.APIVersion = "external-secrets.io/v1"
	} else {
		// Generator kinds
		sourceRef.APIVersion = "generators.external-secrets.io/v1alpha1"
		if namespace != "" {
			sourceRef.Namespace = &namespace
		}
	}

	return sourceRef
}

// buildRemoteRef constructs a RemoteRef for a secret key.
func buildRemoteRef(remoteKey, property string) *fedv1alpha1.RemoteRef {
	if remoteKey == "" {
		return nil
	}
	return &fedv1alpha1.RemoteRef{
		RemoteKey: remoteKey,
		Property:  property,
	}
}

// buildStateRef constructs a StateRef for a GeneratorState.
func buildStateRef(name, namespace string) *fedv1alpha1.StateRef {
	if name == "" {
		return nil
	}
	return &fedv1alpha1.StateRef{
		Kind:       "GeneratorState",
		APIVersion: "generators.external-secrets.io/v1alpha1",
		Name:       name,
		Namespace:  &namespace,
	}
}

// buildWorkloadBindingFromWorkloadInfo constructs a WorkloadBinding from workloadInfo.
func buildWorkloadBindingFromWorkloadInfo(workloadInfo *auth.WorkloadInfo) *fedv1alpha1.WorkloadBinding {
	if workloadInfo == nil {
		return nil
	}

	// If we have pod information, bind to the pod
	if workloadInfo.Pod != nil {
		return &fedv1alpha1.WorkloadBinding{
			Kind:      "Pod",
			Name:      workloadInfo.Pod.Name,
			UID:       workloadInfo.Pod.UID,
			Namespace: workloadInfo.Namespace,
		}
	}

	// Otherwise, bind to the service account
	if workloadInfo.ServiceAccount != nil {
		return &fedv1alpha1.WorkloadBinding{
			Kind:      "ServiceAccount",
			Name:      workloadInfo.ServiceAccount.Name,
			UID:       workloadInfo.ServiceAccount.UID,
			Namespace: workloadInfo.Namespace,
		}
	}

	return nil
}

// upsertIdentity creates or updates an AuthorizedIdentity object.
func (s *Handler) upsertIdentity(
	ctx context.Context,
	authInfo *auth.Info,
	workloadInfo *auth.WorkloadInfo,
	federationRef *fedv1alpha1.FederationRef,
	resourceName string,
	remoteKey string,
	resourceKind string,
	resourceNamespace string,
	stateRef *fedv1alpha1.StateRef,
) error {
	// Skip if dependencies are not available (e.g., in tests)
	if s.client == nil {
		return nil
	}

	// Build the identity spec
	identitySpec := buildIdentitySpec(authInfo, federationRef)

	// Determine the source ref kind
	kind := resourceKind
	if kind == "" {
		kind = "ClusterSecretStore"
	}

	// Build the source ref
	sourceRef := buildSourceRef(resourceName, kind, resourceNamespace)

	// Build the remote ref (optional)
	remoteRef := buildRemoteRef(remoteKey, "")

	// Build the workload binding from workloadInfo
	workloadBinding := buildWorkloadBindingFromWorkloadInfo(workloadInfo)

	// Build the issued credential
	issuedCredential := fedv1alpha1.IssuedCredential{
		SourceRef:       sourceRef,
		RemoteRef:       remoteRef,
		StateRef:        stateRef,
		WorkloadBinding: workloadBinding,
		LastIssuedAt:    metav1.Now(),
	}

	// Generate a deterministic name for the AuthorizedIdentity
	identityName := fmt.Sprintf("%s-%s", authInfo.Method, sanitizeName(authInfo.Subject))

	// Try to get existing AuthorizedIdentity
	identity := &fedv1alpha1.AuthorizedIdentity{}
	err := s.client.Get(ctx, client.ObjectKey{Name: identityName}, identity)

	if err != nil {
		// If error is not NotFound, return early (e.g., connection errors)
		if !apierrors.IsNotFound(err) {
			return fmt.Errorf("failed to get AuthorizedIdentity: %w", err)
		}

		// Create new AuthorizedIdentity
		identity = &fedv1alpha1.AuthorizedIdentity{
			ObjectMeta: metav1.ObjectMeta{
				Name: identityName,
			},
			Spec: fedv1alpha1.AuthorizedIdentitySpec{
				IdentitySpec:      identitySpec,
				IssuedCredentials: []fedv1alpha1.IssuedCredential{issuedCredential},
			},
		}
		return s.client.Create(ctx, identity)
	}

	// Update existing AuthorizedIdentity
	// Check if this credential already exists
	credentialExists := false
	for i, cred := range identity.Spec.IssuedCredentials {
		if credentialsMatch(cred, issuedCredential) {
			// Update the existing credential
			identity.Spec.IssuedCredentials[i] = issuedCredential
			credentialExists = true
			break
		}
	}

	if !credentialExists {
		// Append new credential
		identity.Spec.IssuedCredentials = append(identity.Spec.IssuedCredentials, issuedCredential)
	}
	// Add an automatic retry condition for colliding updates
	return s.client.Update(ctx, identity)

}

// credentialsMatch checks if two credentials reference the same source.
func credentialsMatch(a, b fedv1alpha1.IssuedCredential) bool {
	// Compare SourceRef
	if a.SourceRef.Kind != b.SourceRef.Kind ||
		a.SourceRef.APIVersion != b.SourceRef.APIVersion ||
		a.SourceRef.Name != b.SourceRef.Name {
		return false
	}

	// Compare SourceRef namespaces (handle nil cases)
	if (a.SourceRef.Namespace == nil) != (b.SourceRef.Namespace == nil) {
		return false
	}
	if a.SourceRef.Namespace != nil && b.SourceRef.Namespace != nil {
		if *a.SourceRef.Namespace != *b.SourceRef.Namespace {
			return false
		}
	}

	// Compare RemoteRef
	if (a.RemoteRef == nil) != (b.RemoteRef == nil) {
		return false
	}
	if a.RemoteRef != nil && b.RemoteRef != nil {
		if a.RemoteRef.RemoteKey != b.RemoteRef.RemoteKey {
			return false
		}
	}

	// Compare StateRef
	if (a.StateRef == nil) != (b.StateRef == nil) {
		return false
	}
	if a.StateRef != nil && b.StateRef != nil {
		if a.StateRef.Kind != b.StateRef.Kind ||
			a.StateRef.APIVersion != b.StateRef.APIVersion ||
			a.StateRef.Name != b.StateRef.Name {
			return false
		}
		// Compare StateRef namespace
		if (a.StateRef.Namespace == nil) != (b.StateRef.Namespace == nil) {
			return false
		}
		if a.StateRef.Namespace != nil && b.StateRef.Namespace != nil {
			if *a.StateRef.Namespace != *b.StateRef.Namespace {
				return false
			}
		}
	}

	// Compare WorkloadBinding
	if (a.WorkloadBinding == nil) != (b.WorkloadBinding == nil) {
		return false
	}
	if a.WorkloadBinding != nil && b.WorkloadBinding != nil {
		if a.WorkloadBinding.Kind != b.WorkloadBinding.Kind ||
			a.WorkloadBinding.Name != b.WorkloadBinding.Name ||
			a.WorkloadBinding.UID != b.WorkloadBinding.UID ||
			a.WorkloadBinding.Namespace != b.WorkloadBinding.Namespace {
			return false
		}
	}

	return true
}

// sanitizeName converts a subject/spiffeID to a valid Kubernetes resource name.
func sanitizeName(subject string) string {
	// Replace invalid characters with dashes
	sanitized := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			return r
		}
		return '-'
	}, strings.ToLower(subject))

	// Ensure it doesn't start or end with a dash
	sanitized = strings.Trim(sanitized, "-")

	// Limit length to 253 characters (k8s limit)
	if len(sanitized) > 253 {
		sanitized = sanitized[:253]
	}

	return sanitized
}
