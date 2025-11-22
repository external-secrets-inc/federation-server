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

// Package auth implements the federation server authorization.
// Copyright External Secrets Inc.
// All Rights Reserved.
package auth

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
)

// Info contains information about the authenticated user.
type Info struct {
	// Method is the authentication method used, either "oidc" or "spiffe".
	Method string `json:"method"`
	// Provider is the provider of the authentication, either an OIDC issuer URL or a SPIFFE trust domain.
	Provider string `json:"provider"`
	// Subject is the subject of the authentication, either the OIDC subject or the SPIFFE ID.
	Subject string `json:"subject"`
	// KubeAttributes contains information about the user's Kubernetes context.
	KubeAttributes *KubeAttributes `json:"kubeAttributes"`
}

// KubeAttributes contains information about the user's Kubernetes context.
type KubeAttributes struct {
	// Namespace is the namespace of the user's context.
	Namespace string `json:"namespace"`
	// ServiceAccount is the user's service account.
	ServiceAccount *ServiceAccount `json:"serviceaccount"`
	// Pod is the user's pod, if any.
	Pod *PodInfo `json:"pod,omitempty"`
}

// ServiceAccount contains information about the user's service account.
type ServiceAccount struct {
	// Name is the name of the service account.
	Name string `json:"name"`
	// UID is the UID of the service account.
	UID string `json:"uid"`
}

// PodInfo contains information about the user's pod.
type PodInfo struct {
	// Name is the name of the pod.
	Name string `json:"name"`
	// UID is the UID of the pod.
	UID string `json:"uid"`
}

// WorkloadInfo contains information about the workload context extracted from x-workload-token.
type WorkloadInfo struct {
	// Namespace is the namespace of the workload.
	Namespace string `json:"namespace"`
	// ServiceAccount is the workload's service account.
	ServiceAccount *ServiceAccount `json:"serviceaccount"`
	// Pod is the workload's pod, if any.
	Pod *PodInfo `json:"pod,omitempty"`
}

// Authenticator is the interface that an authentication implementation must
// implement.
type Authenticator interface {
	// Authenticate authenticates the given request and returns an Info
	// if the authentication is successful. The returned Info contains
	// information about the authenticated user.
	Authenticate(r *http.Request) (*Info, error)
}

// Registry is the registry of authenticators, mapping names to
// implementations.
var Registry = make(map[string]Authenticator)

// Register registers an authenticator implementation with the given name.
func Register(name string, a Authenticator) {
	Registry[name] = a
}

// WorkloadTokenClaims represents the claims in a Kubernetes service account token.
type WorkloadTokenClaims struct {
	jwt.RegisteredClaims
	Kubernetes struct {
		Namespace      string `json:"namespace"`
		ServiceAccount struct {
			Name string `json:"name"`
			UID  string `json:"uid"`
		} `json:"serviceaccount"`
		Pod *struct {
			Name string `json:"name"`
			UID  string `json:"uid"`
		} `json:"pod,omitempty"`
	} `json:"kubernetes.io"`
}

// ParseWorkloadToken parses the x-workload-token header and extracts workload information.
// It performs unverified parsing to extract claims without signature validation.
// Returns nil if the token is missing (not an error).
// Returns an error if the token is present but malformed.
func ParseWorkloadToken(r *http.Request) (*WorkloadInfo, error) {
	tokenString := r.Header.Get("x-workload-token")
	if tokenString == "" {
		// No token provided - this is acceptable
		return nil, nil
	}

	// Parse token without verification to extract claims
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, err := parser.ParseUnverified(tokenString, &WorkloadTokenClaims{})
	if err != nil {
		return nil, fmt.Errorf("failed to parse x-workload-token: %w", err)
	}

	claims, ok := token.Claims.(*WorkloadTokenClaims)
	if !ok {
		return nil, errors.New("invalid x-workload-token claims format")
	}

	// Validate required fields
	if claims.Kubernetes.Namespace == "" {
		return nil, errors.New("x-workload-token missing kubernetes.io.namespace")
	}
	if claims.Kubernetes.ServiceAccount.Name == "" {
		return nil, errors.New("x-workload-token missing kubernetes.io.serviceaccount.name")
	}
	if claims.Kubernetes.ServiceAccount.UID == "" {
		return nil, errors.New("x-workload-token missing kubernetes.io.serviceaccount.uid")
	}

	// Build WorkloadInfo
	workloadInfo := &WorkloadInfo{
		Namespace: claims.Kubernetes.Namespace,
		ServiceAccount: &ServiceAccount{
			Name: claims.Kubernetes.ServiceAccount.Name,
			UID:  claims.Kubernetes.ServiceAccount.UID,
		},
	}

	// Add pod info if available
	if claims.Kubernetes.Pod != nil {
		workloadInfo.Pod = &PodInfo{
			Name: claims.Kubernetes.Pod.Name,
			UID:  claims.Kubernetes.Pod.UID,
		}
	}

	return workloadInfo, nil
}
