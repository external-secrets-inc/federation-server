// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"net/http"
	"os"

	"github.com/go-logr/logr"
	"go.uber.org/zap/zapcore"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/metrics/server"

	idfedv1alpha1 "github.com/external-secrets/external-secrets-federation/apis/enterprise/federation/identity/v1alpha1"
	fedv1alpha1 "github.com/external-secrets/external-secrets-federation/apis/enterprise/federation/v1alpha1"
	"github.com/external-secrets/external-secrets-federation/pkg/enterprise/controllers/federation"
	"github.com/external-secrets/external-secrets-federation/pkg/enterprise/federation/deps"
	federationserver "github.com/external-secrets/external-secrets-federation/pkg/enterprise/federation/server"
	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	genv1alpha1 "github.com/external-secrets/external-secrets/apis/generators/v1alpha1"
)

var (
	scheme                  = runtime.NewScheme()
	setupLog                = ctrl.Log.WithName("setup")
	metricsAddr             string
	probeAddr               string
	serverPort              string
	serverTLSPort           string
	controllerClass         string
	spireAgentSocketPath    string
	enableLeaderElection    bool
	enableFederationTLS     bool
	enableFloodGate         bool
	metricsSecure           bool
	metricsCertDir          string
	metricsCertName         string
	metricsKeyName          string
	concurrent              int
	clientQPS               float64
	clientBurst             int
	enableHTTP2             bool
	defaultControllerClass  = "external-secrets"
	defaultSpireAgentSocket = "unix:///tmp/spire-agent/public/api.sock"
)

type externalSecretAccessor struct {
	client          client.Client
	scheme          *runtime.Scheme
	controllerClass string
	floodGate       bool
}

func (a *externalSecretAccessor) RuntimeClient() client.Client { return a.client }
func (a *externalSecretAccessor) RuntimeScheme() *runtime.Scheme {
	return a.scheme
}
func (a *externalSecretAccessor) ControllerClassName() string { return a.controllerClass }
func (a *externalSecretAccessor) FloodGateEnabled() bool      { return a.floodGate }

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(esv1.AddToScheme(scheme))
	utilruntime.Must(genv1alpha1.AddToScheme(scheme))
	utilruntime.Must(fedv1alpha1.AddToScheme(scheme))
	utilruntime.Must(idfedv1alpha1.AddToScheme(scheme))
}

func main() {
	fs := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	zapOpts := zap.Options{
		Development: false,
		TimeEncoder: zapcore.EpochNanosTimeEncoder,
	}
	fs.StringVar(&metricsAddr, "metrics-addr", ":8080", "The address the metrics endpoint binds to.")
	fs.BoolVar(&metricsSecure, "metrics-secure", false, "Enable HTTPS for the metrics endpoint.")
	fs.StringVar(&metricsCertDir, "metrics-cert-dir", "", "Directory containing TLS certificate and key for metrics endpoint.")
	fs.StringVar(&metricsCertName, "metrics-cert-name", "tls.crt", "TLS certificate filename for metrics endpoint.")
	fs.StringVar(&metricsKeyName, "metrics-key-name", "tls.key", "TLS key filename for metrics endpoint.")
	fs.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoints bind to.")
	fs.StringVar(&controllerClass, "controller-class", defaultControllerClass, "Controller class label used for federation reconciliation.")
	fs.BoolVar(&enableLeaderElection, "leader-elect", false, "Enable leader election for the federation manager.")
	fs.IntVar(&concurrent, "concurrent", 1, "The number of concurrent reconciles.")
	fs.Float64Var(&clientQPS, "client-qps", 50, "QPS configuration to be passed to rest.Config.")
	fs.IntVar(&clientBurst, "client-burst", 100, "Burst configuration to be passed to rest.Config.")
	fs.StringVar(&serverPort, "server-port", ":8000", "Federation server port.")
	fs.StringVar(&serverTLSPort, "server-tls-port", ":8001", "Federation server TLS port.")
	fs.BoolVar(&enableFederationTLS, "enable-federation-tls", false, "Enable federation server TLS.")
	fs.StringVar(&spireAgentSocketPath, "spire-agent-socket-path", defaultSpireAgentSocket, "Path to the Spire agent socket.")
	fs.BoolVar(&enableFloodGate, "enable-flood-gate", true, "Enable flood gate behavior when resolving stores.")
	fs.BoolVar(&enableHTTP2, "enable-http2", false, "If set, HTTP/2 will be enabled for the metrics server.")
	zapOpts.BindFlags(fs)
	_ = fs.Parse(os.Args[1:])

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&zapOpts)))

	cfg := ctrl.GetConfigOrDie()
	cfg.QPS = float32(clientQPS)
	cfg.Burst = clientBurst

	metricsOpts := server.Options{BindAddress: metricsAddr}
	if metricsSecure {
		metricsOpts.SecureServing = true
		metricsOpts.CertDir = metricsCertDir
		metricsOpts.CertName = metricsCertName
		metricsOpts.KeyName = metricsKeyName
	}
	if !enableHTTP2 {
		metricsOpts.TLSOpts = []func(*tls.Config){disableHTTP2}
	}

	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsOpts,
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "federation.external-secrets.io",
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	// Register federation controllers.
	register := []func(ctrl.Manager, controller.Options) error{
		func(m ctrl.Manager, opts controller.Options) error {
			return (&federation.AuthorizationController{
				Client: m.GetClient(),
				Log:    ctrl.Log.WithName("controllers").WithName("Authorization"),
				Scheme: m.GetScheme(),
			}).SetupWithManager(m, opts)
		},
		func(m ctrl.Manager, opts controller.Options) error {
			return (&federation.KubernetesFederationController{
				Client: m.GetClient(),
				Log:    ctrl.Log.WithName("controllers").WithName("KubernetesFederation"),
				Scheme: m.GetScheme(),
			}).SetupWithManager(m, opts)
		},
		func(m ctrl.Manager, opts controller.Options) error {
			return (&federation.OktaFederationController{
				Client: m.GetClient(),
				Log:    ctrl.Log.WithName("controllers").WithName("OktaFederation"),
				Scheme: m.GetScheme(),
			}).SetupWithManager(m, opts)
		},
		func(m ctrl.Manager, opts controller.Options) error {
			return (&federation.PingIdentityFederationController{
				Client: m.GetClient(),
				Log:    ctrl.Log.WithName("controllers").WithName("PingIdentityFederation"),
				Scheme: m.GetScheme(),
			}).SetupWithManager(m, opts)
		},
		func(m ctrl.Manager, opts controller.Options) error {
			return (&federation.SpiffeFederationController{
				Client: m.GetClient(),
				Log:    ctrl.Log.WithName("controllers").WithName("SpiffeFederation"),
				Scheme: m.GetScheme(),
			}).SetupWithManager(m, opts)
		},
		func(m ctrl.Manager, opts controller.Options) error {
			return (&federation.AuthorizedIdentityReconciler{
				Client: m.GetClient(),
				Log:    ctrl.Log.WithName("controllers").WithName("AuthorizedIdentity"),
				Scheme: m.GetScheme(),
			}).SetupWithManager(m, opts)
		},
	}

	controllerOpts := controller.Options{MaxConcurrentReconciles: concurrent}
	for _, setup := range register {
		if err := setup(mgr, controllerOpts); err != nil {
			setupLog.Error(err, "unable to create controller")
			os.Exit(1)
		}
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to add healthz check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", func(_ *http.Request) error { return nil }); err != nil {
		setupLog.Error(err, "unable to add readyz check")
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(ctrl.SetupSignalHandler())
	defer cancel()

	accessor := &externalSecretAccessor{
		client:          mgr.GetClient(),
		scheme:          mgr.GetScheme(),
		controllerClass: controllerClass,
		floodGate:       enableFloodGate,
	}
	handler := federationserver.NewHandler(accessor, serverPort, serverTLSPort, spireAgentSocketPath, enableFederationTLS, federationserver.WithDependencies(deps.DefaultDependencies()))

	go func(log logr.Logger) {
		log.Info("starting federation server", "port", serverPort, "tlsPort", serverTLSPort, "tlsEnabled", enableFederationTLS)
		handler.SetupEcho(ctx)
	}(ctrl.Log.WithName("federation-server"))

	setupLog.Info("starting manager")
	if err := mgr.Start(ctx); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}

func disableHTTP2(cfg *tls.Config) {
	cfg.NextProtos = []string{"http/1.1"}
}
