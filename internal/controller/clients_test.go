/*
Copyright 2025 Valkey Contributors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"maps"
	"math/big"
	"net"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	vclient "github.com/valkey-io/valkey-go"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	valkeyiov1alpha1 "github.com/valkey-io/valkey-operator/api/v1alpha1"
	"github.com/valkey-io/valkey-operator/internal/valkey"
)

// stubClient satisfies vclient.Client for tests that never issue commands.
// Only Close is implemented; any other method panics on the nil embed.
type stubClient struct {
	vclient.Client
	closed int
}

func (s *stubClient) Close() { s.closed++ }

// recordNewClient returns a newClient func that records each option and
// answers with a new stubClient.
func recordNewClient(got *[]vclient.ClientOption) func(vclient.ClientOption) (vclient.Client, error) {
	return func(opt vclient.ClientOption) (vclient.Client, error) {
		*got = append(*got, opt)
		return &stubClient{}, nil
	}
}

// newTestProvider returns a provider whose pool records each option it dials.
func newTestProvider(c client.Client, got *[]vclient.ClientOption) ClientProvider {
	return NewClientProvider(c, c, valkey.NewPool(valkey.DefaultIdleTTL, recordNewClient(got)))
}

func providerTestClient(t *testing.T, objs ...client.Object) client.WithWatch {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, valkeyiov1alpha1.AddToScheme(scheme))
	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()
}

// operatorPasswordSecret returns the operator password secret for cluster
// "vc" in namespace "ns", holding password "pw".
func operatorPasswordSecret() *corev1.Secret {
	return operatorPasswordSecretFor("vc", "ns")
}

// operatorPasswordSecretFor returns the operator password secret for cluster
// name in namespace, holding password "pw".
func operatorPasswordSecretFor(name, namespace string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: getSystemPasswordSecretName(name), Namespace: namespace},
		Data:       map[string][]byte{operatorUser: []byte("pw")},
	}
}

// testTLSSecret returns a server certificate secret named "vc-tls" in
// namespace "ns", holding a self-signed CA that doubles as the certificate
// and key.
func testTLSSecret(t *testing.T) *corev1.Secret {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "vc-tls", Namespace: "ns"},
		Data: map[string][]byte{
			tlsSecretKeyCA:   certPEM,
			tlsSecretKeyCert: certPEM,
			tlsSecretKeyKey:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
		},
	}
}

func TestForCluster(t *testing.T) {
	ctx := context.Background()
	newCluster := func(tlsSpec *valkeyiov1alpha1.TLSSpec) *valkeyiov1alpha1.ValkeyCluster {
		return &valkeyiov1alpha1.ValkeyCluster{
			ObjectMeta: metav1.ObjectMeta{Name: "vc", Namespace: "ns"},
			Spec: valkeyiov1alpha1.ValkeyClusterSpec{
				Networking: &valkeyiov1alpha1.NetworkingSpec{TLS: tlsSpec},
			},
		}
	}
	tlsOn := &valkeyiov1alpha1.TLSSpec{
		Certificates: valkeyiov1alpha1.TLSCertificates{
			Server: valkeyiov1alpha1.CertificateSource{SecretName: "vc-tls"},
		},
	}
	mTLS := tlsOn.DeepCopy()
	mTLS.ClientAuth = &valkeyiov1alpha1.TLSClientAuthSpec{Mode: valkeyiov1alpha1.TLSAuthClientsRequired}

	t.Run("TLS off dials with operator credentials", func(t *testing.T) {
		var got []vclient.ClientOption
		p := newTestProvider(providerTestClient(t, operatorPasswordSecret()), &got)
		dial, err := p.ForCluster(ctx, newCluster(nil))
		require.NoError(t, err)

		_, err = dial(ctx, "10.0.0.1:6379")
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, []string{"10.0.0.1:6379"}, got[0].InitAddress)
		assert.True(t, got[0].ForceSingleClient)
		assert.Equal(t, "valkey-operator", got[0].ClientName)
		assert.Equal(t, operatorUser, got[0].Username)
		assert.Equal(t, "pw", got[0].Password)
		assert.Nil(t, got[0].TLSConfig)
		assert.Equal(t, -1, got[0].PipelineMultiplex)
		assert.Equal(t, 4*1024, got[0].ReadBufferEachConn)
		assert.Equal(t, 4*1024, got[0].WriteBufferEachConn)
		assert.Equal(t, 4, got[0].RingScaleEachConn)
	})

	t.Run("TLS on sets the CA and server name", func(t *testing.T) {
		var got []vclient.ClientOption
		cluster := newCluster(tlsOn)
		p := newTestProvider(providerTestClient(t, operatorPasswordSecret(), testTLSSecret(t)), &got)
		dial, err := p.ForCluster(ctx, cluster)
		require.NoError(t, err)

		_, err = dial(ctx, "10.0.0.1:6379")
		require.NoError(t, err)
		require.Len(t, got, 1)
		require.NotNil(t, got[0].TLSConfig)
		assert.NotNil(t, got[0].TLSConfig.RootCAs)
		assert.Equal(t, nodeTLSFromCluster(cluster).ServerName, got[0].TLSConfig.ServerName)
		assert.Empty(t, got[0].TLSConfig.Certificates)
	})

	t.Run("mTLS presents the client certificate", func(t *testing.T) {
		var got []vclient.ClientOption
		p := newTestProvider(providerTestClient(t, operatorPasswordSecret(), testTLSSecret(t)), &got)
		dial, err := p.ForCluster(ctx, newCluster(mTLS))
		require.NoError(t, err)

		_, err = dial(ctx, "10.0.0.1:6379")
		require.NoError(t, err)
		require.Len(t, got, 1)
		require.NotNil(t, got[0].TLSConfig)
		assert.Len(t, got[0].TLSConfig.Certificates, 1)
	})

	t.Run("missing TLS secret fails every dial without dialling", func(t *testing.T) {
		var got []vclient.ClientOption
		p := newTestProvider(providerTestClient(t, operatorPasswordSecret()), &got)
		dial, err := p.ForCluster(ctx, newCluster(tlsOn))
		require.NoError(t, err, "a missing TLS secret must not stop the cluster reconcile")
		require.NotNil(t, dial)

		for _, address := range []string{"10.0.0.1:6379", "10.0.0.2:6379"} {
			c, err := dial(ctx, address)
			require.ErrorContains(t, err, "TLS config")
			assert.Nil(t, c)
		}
		assert.Empty(t, got)
	})

	t.Run("missing operator password secret is an error", func(t *testing.T) {
		var got []vclient.ClientOption
		dial, err := newTestProvider(providerTestClient(t), &got).ForCluster(ctx, newCluster(nil))
		require.Error(t, err)
		assert.True(t, apierrors.IsNotFound(err))
		assert.Nil(t, dial)
		assert.Empty(t, got)
	})

	t.Run("password secret without the operator key is an error", func(t *testing.T) {
		var got []vclient.ClientOption
		secret := operatorPasswordSecret()
		secret.Data = map[string][]byte{"_exporter": []byte("other")}
		dial, err := newTestProvider(providerTestClient(t, secret), &got).ForCluster(ctx, newCluster(nil))
		require.ErrorContains(t, err, "has no _operator key")
		assert.Nil(t, dial)
		assert.Empty(t, got)
	})

	t.Run("reuses the client across scrapes", func(t *testing.T) {
		var got []vclient.ClientOption
		p := newTestProvider(providerTestClient(t, operatorPasswordSecret(), testTLSSecret(t)), &got)
		clients := make([]vclient.Client, 0, 2)
		for range 2 {
			dial, err := p.ForCluster(ctx, newCluster(tlsOn))
			require.NoError(t, err)
			c, err := dial(ctx, "10.0.0.1:6379")
			require.NoError(t, err)
			clients = append(clients, c)
		}
		assert.Same(t, clients[0], clients[1])
		assert.Len(t, got, 1)
	})
}

func TestForNode(t *testing.T) {
	ctx := context.Background()
	newNode := func(podIP string, labels map[string]string, tlsSpec *valkeyiov1alpha1.NodeTLSSpec) *valkeyiov1alpha1.ValkeyNode {
		return &valkeyiov1alpha1.ValkeyNode{
			ObjectMeta: metav1.ObjectMeta{Name: "vc-0-0", Namespace: "ns", Labels: labels},
			Spec:       valkeyiov1alpha1.ValkeyNodeSpec{TLS: tlsSpec},
			Status:     valkeyiov1alpha1.ValkeyNodeStatus{PodIP: podIP},
		}
	}
	inCluster := map[string]string{LabelCluster: "vc"}
	tlsOn := &valkeyiov1alpha1.NodeTLSSpec{
		ServerName: "vc.ns.svc",
		Certificates: valkeyiov1alpha1.NodeTLSCertificates{
			Server: valkeyiov1alpha1.NodeCertificateRef{SecretName: "vc-tls"},
		},
	}
	mTLS := tlsOn.DeepCopy()
	mTLS.ClientAuth = &valkeyiov1alpha1.NodeTLSClientAuthSpec{Mode: valkeyiov1alpha1.TLSAuthClientsRequired}

	t.Run("no pod IP is an error", func(t *testing.T) {
		var got []vclient.ClientOption
		c, err := newTestProvider(providerTestClient(t), &got).ForNode(ctx, newNode("", inCluster, nil))
		require.ErrorContains(t, err, "no pod IP")
		assert.Nil(t, c)
		assert.Empty(t, got)
	})

	t.Run("cluster node dials its pod with operator credentials", func(t *testing.T) {
		var got []vclient.ClientOption
		p := newTestProvider(providerTestClient(t, operatorPasswordSecret()), &got)
		_, err := p.ForNode(ctx, newNode("10.0.0.5", inCluster, nil))
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, []string{"10.0.0.5:6379"}, got[0].InitAddress)
		assert.Equal(t, operatorUser, got[0].Username)
		assert.Equal(t, "pw", got[0].Password)
		assert.Nil(t, got[0].TLSConfig)
	})

	t.Run("IPv6 pod IP is bracketed", func(t *testing.T) {
		var got []vclient.ClientOption
		p := newTestProvider(providerTestClient(t, operatorPasswordSecret()), &got)
		_, err := p.ForNode(ctx, newNode("fd00::5", inCluster, nil))
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.Equal(t, []string{"[fd00::5]:6379"}, got[0].InitAddress)
	})

	t.Run("node without a cluster label is an error", func(t *testing.T) {
		var got []vclient.ClientOption
		c, err := newTestProvider(providerTestClient(t), &got).ForNode(ctx, newNode("10.0.0.5", nil, nil))
		require.ErrorContains(t, err, "no "+LabelCluster+" label")
		assert.Nil(t, c)
		assert.Empty(t, got)
	})

	t.Run("missing password secret is an error", func(t *testing.T) {
		var got []vclient.ClientOption
		c, err := newTestProvider(providerTestClient(t), &got).ForNode(ctx, newNode("10.0.0.5", inCluster, nil))
		require.Error(t, err)
		assert.True(t, apierrors.IsNotFound(err))
		assert.Nil(t, c)
		assert.Empty(t, got)
	})

	t.Run("password secret without the operator key is an error", func(t *testing.T) {
		var got []vclient.ClientOption
		secret := operatorPasswordSecret()
		secret.Data = map[string][]byte{"_exporter": []byte("other")}
		c, err := newTestProvider(providerTestClient(t, secret), &got).ForNode(ctx, newNode("10.0.0.5", inCluster, nil))
		require.ErrorContains(t, err, "has no _operator key")
		assert.Nil(t, c)
		assert.Empty(t, got)
	})

	t.Run("other password lookup errors are returned", func(t *testing.T) {
		var got []vclient.ClientOption
		timeout := errors.New("etcdserver: request timed out")
		scheme := runtime.NewScheme()
		require.NoError(t, corev1.AddToScheme(scheme))
		c := fake.NewClientBuilder().WithScheme(scheme).WithInterceptorFuncs(interceptor.Funcs{
			Get: func(context.Context, client.WithWatch, client.ObjectKey, client.Object, ...client.GetOption) error {
				return timeout
			},
		}).Build()
		vc, err := newTestProvider(c, &got).ForNode(ctx, newNode("10.0.0.5", inCluster, nil))
		require.ErrorIs(t, err, timeout)
		assert.Nil(t, vc)
		assert.Empty(t, got)
	})

	t.Run("TLS on sets the CA and server name", func(t *testing.T) {
		var got []vclient.ClientOption
		p := newTestProvider(providerTestClient(t, operatorPasswordSecret(), testTLSSecret(t)), &got)
		_, err := p.ForNode(ctx, newNode("10.0.0.5", inCluster, tlsOn))
		require.NoError(t, err)
		require.Len(t, got, 1)
		require.NotNil(t, got[0].TLSConfig)
		assert.NotNil(t, got[0].TLSConfig.RootCAs)
		assert.Equal(t, "vc.ns.svc", got[0].TLSConfig.ServerName)
		assert.Empty(t, got[0].TLSConfig.Certificates)
	})

	t.Run("mTLS presents the client certificate", func(t *testing.T) {
		var got []vclient.ClientOption
		p := newTestProvider(providerTestClient(t, operatorPasswordSecret(), testTLSSecret(t)), &got)
		_, err := p.ForNode(ctx, newNode("10.0.0.5", inCluster, mTLS))
		require.NoError(t, err)
		require.Len(t, got, 1)
		require.NotNil(t, got[0].TLSConfig)
		assert.Len(t, got[0].TLSConfig.Certificates, 1)
	})

	// A ValkeyNode created by v0.6.0 has no spec.tls.serverName until the
	// cluster controller updates it. Verifying against the pod IP would fail a
	// certificate with DNS SANs only.
	t.Run("cluster node without a server name verifies against the cluster default", func(t *testing.T) {
		var got []vclient.ClientOption
		c := providerTestClient(t, operatorPasswordSecret(), testTLSSecret(t))
		noServerName := tlsOn.DeepCopy()
		noServerName.ServerName = ""
		_, err := newTestProvider(c, &got).ForNode(ctx, newNode("10.0.0.5", inCluster, noServerName))
		require.NoError(t, err)
		require.Len(t, got, 1)
		require.NotNil(t, got[0].TLSConfig)
		assert.Equal(t, "valkey-vc.ns.svc.cluster.local", got[0].TLSConfig.ServerName)
	})

	t.Run("missing TLS secret is an error", func(t *testing.T) {
		var got []vclient.ClientOption
		p := newTestProvider(providerTestClient(t, operatorPasswordSecret()), &got)
		c, err := p.ForNode(ctx, newNode("10.0.0.5", inCluster, tlsOn))
		require.ErrorContains(t, err, "TLS config")
		assert.Nil(t, c)
		assert.Empty(t, got)
	})

	t.Run("reuses the client across calls", func(t *testing.T) {
		var got []vclient.ClientOption
		p := newTestProvider(providerTestClient(t, operatorPasswordSecret(), testTLSSecret(t)), &got)
		first, err := p.ForNode(ctx, newNode("10.0.0.5", inCluster, tlsOn))
		require.NoError(t, err)
		second, err := p.ForNode(ctx, newNode("10.0.0.5", inCluster, tlsOn))
		require.NoError(t, err)
		assert.Same(t, first, second)
		assert.Len(t, got, 1)
	})
}

func TestForNodeRebuildsOnTLSChange(t *testing.T) {
	ctx := context.Background()
	for name, tc := range map[string]struct {
		change func(t *testing.T, c client.Client, spec *valkeyiov1alpha1.NodeTLSSpec)
		// cached is set when the change shows only once the kept TLS config
		// expires.
		cached bool
	}{
		"secret updated": {cached: true, change: func(t *testing.T, c client.Client, _ *valkeyiov1alpha1.NodeTLSSpec) {
			secret := &corev1.Secret{}
			require.NoError(t, c.Get(ctx, client.ObjectKey{Namespace: "ns", Name: "vc-tls"}, secret))
			secret.Labels = map[string]string{"renewed": "true"}
			require.NoError(t, c.Update(ctx, secret))
		}},
		"server name changed": {change: func(_ *testing.T, _ client.Client, spec *valkeyiov1alpha1.NodeTLSSpec) {
			spec.ServerName = "other.ns.svc"
		}},
		"client certificate required": {change: func(_ *testing.T, _ client.Client, spec *valkeyiov1alpha1.NodeTLSSpec) {
			spec.ClientAuth = &valkeyiov1alpha1.NodeTLSClientAuthSpec{Mode: valkeyiov1alpha1.TLSAuthClientsRequired}
		}},
	} {
		t.Run(name, func(t *testing.T) {
			var got []vclient.ClientOption
			c := providerTestClient(t, operatorPasswordSecret(), testTLSSecret(t))
			p := newTestProvider(c, &got).(*provider)
			clock := newTestClock()
			p.tlsConfigs.now = clock.Now
			node := &valkeyiov1alpha1.ValkeyNode{
				ObjectMeta: metav1.ObjectMeta{Name: "vc-0-0", Namespace: "ns", Labels: map[string]string{LabelCluster: "vc"}},
				Spec: valkeyiov1alpha1.ValkeyNodeSpec{TLS: &valkeyiov1alpha1.NodeTLSSpec{
					ServerName: "vc.ns.svc",
					Certificates: valkeyiov1alpha1.NodeTLSCertificates{
						Server: valkeyiov1alpha1.NodeCertificateRef{SecretName: "vc-tls"},
					},
				}},
				Status: valkeyiov1alpha1.ValkeyNodeStatus{PodIP: "10.0.0.5"},
			}
			before, err := p.ForNode(ctx, node)
			require.NoError(t, err)

			tc.change(t, c, node.Spec.TLS)
			if tc.cached {
				still, err := p.ForNode(ctx, node)
				require.NoError(t, err)
				assert.Same(t, before, still)
				clock.Advance(tlsConfigTTL)
			}
			after, err := p.ForNode(ctx, node)
			require.NoError(t, err)

			assert.NotSame(t, before, after)
			assert.Len(t, got, 2)
			assert.Equal(t, 1, before.(*stubClient).closed)
		})
	}
}

func TestProviderSharesClientsAcrossPaths(t *testing.T) {
	ctx := context.Background()
	tlsOn := &valkeyiov1alpha1.TLSSpec{
		Certificates: valkeyiov1alpha1.TLSCertificates{
			Server: valkeyiov1alpha1.CertificateSource{SecretName: "vc-tls"},
		},
	}
	for name, tc := range map[string]struct {
		tlsSpec *valkeyiov1alpha1.TLSSpec
		// noServerName leaves spec.tls.serverName empty on the node, as on a
		// ValkeyNode created by v0.6.0.
		noServerName bool
	}{
		"TLS off":             {},
		"TLS on":              {tlsSpec: tlsOn},
		"TLS on, v0.6.0 node": {tlsSpec: tlsOn, noServerName: true},
	} {
		t.Run(name, func(t *testing.T) {
			var got []vclient.ClientOption
			p := newTestProvider(providerTestClient(t, operatorPasswordSecret(), testTLSSecret(t)), &got)
			cluster := &valkeyiov1alpha1.ValkeyCluster{
				ObjectMeta: metav1.ObjectMeta{Name: "vc", Namespace: "ns"},
				Spec: valkeyiov1alpha1.ValkeyClusterSpec{
					Networking: &valkeyiov1alpha1.NetworkingSpec{TLS: tc.tlsSpec},
				},
			}
			// The cluster controller builds each ValkeyNode's TLS the same way.
			node := &valkeyiov1alpha1.ValkeyNode{
				ObjectMeta: metav1.ObjectMeta{Name: "vc-0-0", Namespace: "ns", Labels: map[string]string{LabelCluster: "vc"}},
				Spec:       valkeyiov1alpha1.ValkeyNodeSpec{TLS: nodeTLSFromCluster(cluster)},
				Status:     valkeyiov1alpha1.ValkeyNodeStatus{PodIP: "10.0.0.5"},
			}
			if tc.noServerName {
				node.Spec.TLS.ServerName = ""
			}

			dial, err := p.ForCluster(ctx, cluster)
			require.NoError(t, err)
			fromScrape, err := dial(ctx, "10.0.0.5:6379")
			require.NoError(t, err)
			fromNode, err := p.ForNode(ctx, node)
			require.NoError(t, err)

			assert.Same(t, fromScrape, fromNode)
			assert.Len(t, got, 1)
		})
	}
}

func TestSetupWithManagerRequiresValkeyClients(t *testing.T) {
	// The check comes before the manager is used, so none is needed.
	assert.ErrorContains(t, (&ValkeyClusterReconciler{}).SetupWithManager(nil), "no ClientProvider")
	assert.ErrorContains(t, (&ValkeyNodeReconciler{}).SetupWithManager(nil), "no ClientProvider")
}

var errDialFailed = errors.New("dial tcp: connect: connection refused")

// testClock is a clock that moves only when the test advances it. It is safe
// for concurrent use.
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func newTestClock() *testClock {
	return &testClock{now: time.Date(2026, 11, 28, 12, 0, 0, 0, time.UTC)}
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// countingReader counts the Gets that reach it. The provider reads only TLS
// secrets through its API reader.
type countingReader struct {
	client.Reader
	gets atomic.Int64
}

func (r *countingReader) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	r.gets.Add(1)
	return r.Reader.Get(ctx, key, obj, opts...)
}

// testDialer stands in for vclient.NewClient: it records each option and
// fails the dials to the addresses in refused. It is safe for concurrent use.
type testDialer struct {
	refused map[string]bool
	mu      sync.Mutex
	opts    []vclient.ClientOption
}

func (d *testDialer) newClient(opt vclient.ClientOption) (vclient.Client, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.opts = append(d.opts, opt)
	if d.refused[opt.InitAddress[0]] {
		return nil, errDialFailed
	}
	return &stubClient{}, nil
}

// options returns every option dialled so far.
func (d *testDialer) options() []vclient.ClientOption {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.opts)
}

// tlsCacheFixture is a provider whose TLS secret reads are counted, whose
// dials to refused addresses fail, and whose TLS config cache reads clock.
type tlsCacheFixture struct {
	p      *provider
	c      client.Client
	reads  *countingReader
	dialer *testDialer
	clock  *testClock
}

func newTLSCacheFixture(t *testing.T, refused []string, objs ...client.Object) *tlsCacheFixture {
	t.Helper()
	c := providerTestClient(t, objs...)
	f := &tlsCacheFixture{
		c:      c,
		reads:  &countingReader{Reader: c},
		dialer: &testDialer{refused: map[string]bool{}},
		clock:  newTestClock(),
	}
	for _, address := range refused {
		f.dialer.refused[address] = true
	}
	f.p = NewClientProvider(c, f.reads, valkey.NewPool(valkey.DefaultIdleTTL, f.dialer.newClient)).(*provider)
	f.p.tlsConfigs.now = f.clock.Now
	return f
}

// secretReads returns how many times the provider has read a TLS secret.
func (f *tlsCacheFixture) secretReads() int {
	return int(f.reads.gets.Load())
}

// tlsTestCluster returns cluster name in namespace, with its server
// certificate in secretName.
func tlsTestCluster(namespace, name, secretName string, mode valkeyiov1alpha1.TLSAuthClients) *valkeyiov1alpha1.ValkeyCluster {
	return &valkeyiov1alpha1.ValkeyCluster{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: valkeyiov1alpha1.ValkeyClusterSpec{
			Networking: &valkeyiov1alpha1.NetworkingSpec{TLS: &valkeyiov1alpha1.TLSSpec{
				Certificates: valkeyiov1alpha1.TLSCertificates{
					Server: valkeyiov1alpha1.CertificateSource{SecretName: secretName},
				},
				ClientAuth: &valkeyiov1alpha1.TLSClientAuthSpec{Mode: mode},
			}},
		},
	}
}

// lookupFunc returns the client for the pod at podIP of cluster.
type lookupFunc func(ctx context.Context, p *provider, cluster *valkeyiov1alpha1.ValkeyCluster, podIP string) (vclient.Client, error)

// clusterLookups are the two ways the controllers get a client: ForNode in a
// ValkeyNode reconcile, and ForCluster in a cluster scrape or a role poll.
func clusterLookups() map[string]lookupFunc {
	return map[string]lookupFunc{
		"ForNode": func(ctx context.Context, p *provider, cluster *valkeyiov1alpha1.ValkeyCluster, podIP string) (vclient.Client, error) {
			return p.ForNode(ctx, &valkeyiov1alpha1.ValkeyNode{
				ObjectMeta: metav1.ObjectMeta{
					Name:      cluster.Name + "-0-0",
					Namespace: cluster.Namespace,
					Labels:    map[string]string{LabelCluster: cluster.Name},
				},
				Spec:   valkeyiov1alpha1.ValkeyNodeSpec{TLS: nodeTLSFromCluster(cluster)},
				Status: valkeyiov1alpha1.ValkeyNodeStatus{PodIP: podIP},
			})
		},
		"ForCluster": func(ctx context.Context, p *provider, cluster *valkeyiov1alpha1.ValkeyCluster, podIP string) (vclient.Client, error) {
			dial, err := p.ForCluster(ctx, cluster)
			if err != nil {
				return nil, err
			}
			return dial(ctx, net.JoinHostPort(podIP, strconv.Itoa(DefaultPort)))
		},
	}
}

// caPool returns the pool of the CA certificates in secret's ca.crt.
func caPool(t *testing.T, secret *corev1.Secret) *x509.CertPool {
	t.Helper()
	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM(secret.Data[tlsSecretKeyCA]))
	return roots
}

func TestTLSConfigCacheReusesAConfigForTheTTL(t *testing.T) {
	ctx := context.Background()
	cluster := tlsTestCluster("ns", "vc", "vc-tls", valkeyiov1alpha1.TLSAuthClientsOptional)
	for name, lookup := range clusterLookups() {
		t.Run(name, func(t *testing.T) {
			f := newTLSCacheFixture(t, nil, operatorPasswordSecret(), testTLSSecret(t))
			for _, podIP := range []string{"10.0.0.5", "10.0.0.6"} {
				_, err := lookup(ctx, f.p, cluster, podIP)
				require.NoError(t, err)
			}
			assert.Equal(t, 1, f.secretReads(), "two pods within the TTL read the secret once")

			f.clock.Advance(tlsConfigTTL - time.Nanosecond)
			_, err := lookup(ctx, f.p, cluster, "10.0.0.5")
			require.NoError(t, err)
			assert.Equal(t, 1, f.secretReads())

			f.clock.Advance(time.Nanosecond)
			_, err = lookup(ctx, f.p, cluster, "10.0.0.5")
			require.NoError(t, err)
			assert.Equal(t, 2, f.secretReads(), "an expired config reads the secret again")
			assert.Len(t, f.dialer.options(), 2, "an unchanged secret keeps the pooled clients")
		})
	}

	t.Run("node reconcile and cluster scrape share a config", func(t *testing.T) {
		f := newTLSCacheFixture(t, nil, operatorPasswordSecret(), testTLSSecret(t))
		for _, lookup := range clusterLookups() {
			_, err := lookup(ctx, f.p, cluster, "10.0.0.5")
			require.NoError(t, err)
		}
		assert.Equal(t, 1, f.secretReads())
	})
}

func TestTLSConfigCacheIsNotUsedWithoutTLS(t *testing.T) {
	ctx := context.Background()
	cluster := &valkeyiov1alpha1.ValkeyCluster{ObjectMeta: metav1.ObjectMeta{Name: "vc", Namespace: "ns"}}
	for name, lookup := range clusterLookups() {
		t.Run(name, func(t *testing.T) {
			f := newTLSCacheFixture(t, []string{"10.0.0.6:6379"}, operatorPasswordSecret())
			first, err := lookup(ctx, f.p, cluster, "10.0.0.5")
			require.NoError(t, err)
			_, err = lookup(ctx, f.p, cluster, "10.0.0.6")
			require.ErrorIs(t, err, errDialFailed)
			again, err := lookup(ctx, f.p, cluster, "10.0.0.5")
			require.NoError(t, err)

			assert.Same(t, first, again)
			assert.Nil(t, f.dialer.options()[0].TLSConfig)
			assert.Zero(t, f.secretReads())
			assert.Empty(t, f.p.tlsConfigs.entries)
		})
	}
}

func TestTLSConfigCacheDropsAConfigWhenADialFails(t *testing.T) {
	ctx := context.Background()
	cluster := tlsTestCluster("ns", "vc", "vc-tls", valkeyiov1alpha1.TLSAuthClientsOptional)
	for name, lookup := range clusterLookups() {
		t.Run(name, func(t *testing.T) {
			// 10.0.0.6 stands for a pod that already serves a certificate
			// from the new CA below, which the kept config does not trust.
			f := newTLSCacheFixture(t, []string{"10.0.0.6:6379"}, operatorPasswordSecret(), testTLSSecret(t))
			before, err := lookup(ctx, f.p, cluster, "10.0.0.5")
			require.NoError(t, err)

			reissued := testTLSSecret(t)
			secret := &corev1.Secret{}
			require.NoError(t, f.c.Get(ctx, client.ObjectKeyFromObject(reissued), secret))
			secret.Data = reissued.Data
			require.NoError(t, f.c.Update(ctx, secret))
			still, err := lookup(ctx, f.p, cluster, "10.0.0.5")
			require.NoError(t, err)
			assert.Same(t, before, still, "within the TTL the secret is not read again")

			_, err = lookup(ctx, f.p, cluster, "10.0.0.6")
			require.ErrorIs(t, err, errDialFailed)
			after, err := lookup(ctx, f.p, cluster, "10.0.0.5")
			require.NoError(t, err)

			assert.Equal(t, 2, f.secretReads(), "the failed dial dropped the config")
			assert.NotSame(t, before, after, "the reissued secret replaces the pooled client")
			opts := f.dialer.options()
			assert.True(t, opts[len(opts)-1].TLSConfig.RootCAs.Equal(caPool(t, reissued)))
		})
	}
}

func TestTLSConfigCacheKeepsNoFailedBuild(t *testing.T) {
	ctx := context.Background()
	for name, tc := range map[string]struct {
		mode valkeyiov1alpha1.TLSAuthClients
		// breakSecret damages the secret; nil leaves it missing.
		breakSecret func(*corev1.Secret)
	}{
		"missing secret": {mode: valkeyiov1alpha1.TLSAuthClientsOptional},
		"ca.crt is not PEM": {mode: valkeyiov1alpha1.TLSAuthClientsOptional, breakSecret: func(s *corev1.Secret) {
			s.Data[tlsSecretKeyCA] = []byte("not PEM")
		}},
		"tls.key is not PEM": {mode: valkeyiov1alpha1.TLSAuthClientsRequired, breakSecret: func(s *corev1.Secret) {
			s.Data[tlsSecretKeyKey] = []byte("not PEM")
		}},
	} {
		for lookupName, lookup := range clusterLookups() {
			t.Run(name+"/"+lookupName, func(t *testing.T) {
				good := testTLSSecret(t)
				objs := []client.Object{operatorPasswordSecret()}
				if tc.breakSecret != nil {
					broken := good.DeepCopy()
					tc.breakSecret(broken)
					objs = append(objs, broken)
				}
				f := newTLSCacheFixture(t, nil, objs...)
				cluster := tlsTestCluster("ns", "vc", "vc-tls", tc.mode)
				for range 2 {
					_, err := lookup(ctx, f.p, cluster, "10.0.0.5")
					require.ErrorContains(t, err, "TLS config")
				}
				assert.Equal(t, 2, f.secretReads(), "each lookup reads the secret again")

				if tc.breakSecret == nil {
					require.NoError(t, f.c.Create(ctx, good))
				} else {
					secret := &corev1.Secret{}
					require.NoError(t, f.c.Get(ctx, client.ObjectKeyFromObject(good), secret))
					secret.Data = good.Data
					require.NoError(t, f.c.Update(ctx, secret))
				}
				_, err := lookup(ctx, f.p, cluster, "10.0.0.5")
				require.NoError(t, err, "a fixed secret is used without waiting for the TTL")
				assert.Equal(t, 3, f.secretReads())
			})
		}
	}
}

func TestTLSConfigCacheKeysOnEveryInput(t *testing.T) {
	ctx := context.Background()
	base := &valkeyiov1alpha1.NodeTLSSpec{
		ServerName: "vc.ns.svc",
		Certificates: valkeyiov1alpha1.NodeTLSCertificates{
			Server: valkeyiov1alpha1.NodeCertificateRef{SecretName: "vc-tls"},
		},
	}
	for name, tc := range map[string]struct {
		namespace string
		change    func(spec *valkeyiov1alpha1.NodeTLSSpec)
	}{
		"namespace": {namespace: "other"},
		"secret name": {namespace: "ns", change: func(spec *valkeyiov1alpha1.NodeTLSSpec) {
			spec.Certificates.Server.SecretName = "other-tls"
		}},
		"server name": {namespace: "ns", change: func(spec *valkeyiov1alpha1.NodeTLSSpec) {
			spec.ServerName = "other.ns.svc"
		}},
		"client certificate": {namespace: "ns", change: func(spec *valkeyiov1alpha1.NodeTLSSpec) {
			spec.ClientAuth = &valkeyiov1alpha1.NodeTLSClientAuthSpec{Mode: valkeyiov1alpha1.TLSAuthClientsRequired}
		}},
	} {
		t.Run(name, func(t *testing.T) {
			// Each secret has its own CA.
			keys := []client.ObjectKey{
				{Namespace: "ns", Name: "vc-tls"},
				{Namespace: "other", Name: "vc-tls"},
				{Namespace: "ns", Name: "other-tls"},
			}
			secrets := make(map[client.ObjectKey]*corev1.Secret, len(keys))
			objs := make([]client.Object, 0, len(keys))
			for _, key := range keys {
				secret := testTLSSecret(t)
				secret.Namespace, secret.Name = key.Namespace, key.Name
				secrets[key] = secret
				objs = append(objs, secret)
			}
			f := newTLSCacheFixture(t, nil, objs...)
			spec := base.DeepCopy()
			if tc.change != nil {
				tc.change(spec)
			}

			first, _, err := f.p.tlsConfig(ctx, "ns", base)
			require.NoError(t, err)
			cfg, _, err := f.p.tlsConfig(ctx, tc.namespace, spec)
			require.NoError(t, err)
			again, _, err := f.p.tlsConfig(ctx, "ns", base)
			require.NoError(t, err)

			assert.Equal(t, 2, f.secretReads())
			assert.Same(t, first, again)
			assert.NotSame(t, first, cfg)
			from := secrets[client.ObjectKey{Namespace: tc.namespace, Name: spec.Certificates.Server.SecretName}]
			assert.True(t, cfg.RootCAs.Equal(caPool(t, from)), "built from its own secret")
			assert.Equal(t, spec.ServerName, cfg.ServerName)
			assert.Equal(t, spec.RequiresClientCertificate(), len(cfg.Certificates) == 1)
		})
	}
}

func TestTLSConfigCacheHoldsOnlyUnexpiredConfigs(t *testing.T) {
	clock := newTestClock()
	cache := newTLSConfigCache()
	cache.now = clock.Now
	for i := range 100 {
		key := tlsConfigKey{namespace: "ns", secretName: fmt.Sprintf("vc%d-tls", i)}
		cache.put(key, builtTLSConfig{token: key.secretName, readAt: clock.Now()})
		// One secret read every quarter TTL leaves four unexpired configs.
		require.Len(t, cache.entries, min(i+1, 4))
		clock.Advance(tlsConfigTTL / 4)
	}

	last := tlsConfigKey{namespace: "ns", secretName: "vc99-tls"}
	e, ok := cache.get(last)
	require.True(t, ok)
	assert.Equal(t, "vc99-tls", e.token)
	cache.forget(last)
	_, ok = cache.get(last)
	assert.False(t, ok)
}

func TestTLSConfigCacheConcurrentLookups(t *testing.T) {
	ctx := context.Background()
	const podsPerCluster = 10
	type tlsClusterCase struct {
		cluster *valkeyiov1alpha1.ValkeyCluster
		roots   *x509.CertPool
	}
	cases := []tlsClusterCase{
		{cluster: tlsTestCluster("ns", "vc", "vc-tls", valkeyiov1alpha1.TLSAuthClientsOptional)},
		{cluster: tlsTestCluster("ns", "mtls", "mtls-tls", valkeyiov1alpha1.TLSAuthClientsRequired)},
		{cluster: tlsTestCluster("other", "vc", "vc-tls", valkeyiov1alpha1.TLSAuthClientsOptional)},
	}
	podIP := func(cluster, pod int) string { return fmt.Sprintf("10.0.%d.%d", cluster, pod) }
	objs := make([]client.Object, 0, 2*len(cases))
	caseOf := map[string]int{}
	refused := make([]string, 0, len(cases))
	for i := range cases {
		cluster := cases[i].cluster
		secret := testTLSSecret(t)
		secret.Namespace, secret.Name = cluster.Namespace, cluster.GetTLS().Certificates.Server.SecretName
		cases[i].roots = caPool(t, secret)
		objs = append(objs, secret, operatorPasswordSecretFor(cluster.Name, cluster.Namespace))
		for pod := range podsPerCluster {
			caseOf[net.JoinHostPort(podIP(i, pod), strconv.Itoa(DefaultPort))] = i
		}
		// The last pod of each cluster refuses every dial, so its lookups
		// keep dropping the config the other pods reuse.
		refused = append(refused, net.JoinHostPort(podIP(i, podsPerCluster-1), strconv.Itoa(DefaultPort)))
	}
	f := newTLSCacheFixture(t, refused, objs...)
	lookups := slices.Collect(maps.Values(clusterLookups()))

	var wg sync.WaitGroup
	for worker := range 8 {
		wg.Go(func() {
			for i := range 100 {
				n, pod := (worker+i)%len(cases), i%podsPerCluster
				_, err := lookups[i%len(lookups)](ctx, f.p, cases[n].cluster, podIP(n, pod))
				if pod == podsPerCluster-1 {
					assert.ErrorIs(t, err, errDialFailed)
				} else {
					assert.NoError(t, err)
				}
				if i%25 == 0 {
					f.clock.Advance(tlsConfigTTL / 2)
				}
			}
		})
	}
	wg.Wait()

	for _, opt := range f.dialer.options() {
		want := cases[caseOf[opt.InitAddress[0]]]
		require.NotNil(t, opt.TLSConfig)
		assert.Equal(t, nodeTLSFromCluster(want.cluster).ServerName, opt.TLSConfig.ServerName)
		assert.True(t, opt.TLSConfig.RootCAs.Equal(want.roots), "dialled %s with another cluster's CA", opt.InitAddress[0])
		assert.Equal(t, want.cluster.GetTLS().ClientAuthMode() == valkeyiov1alpha1.TLSAuthClientsRequired,
			len(opt.TLSConfig.Certificates) == 1)
	}
}
