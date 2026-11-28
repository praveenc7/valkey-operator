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
	"crypto/tls"
	"fmt"
	"maps"
	"net"
	"strconv"
	"sync"
	"time"

	vclient "github.com/valkey-io/valkey-go"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	valkeyiov1alpha1 "github.com/valkey-io/valkey-operator/api/v1alpha1"
	"github.com/valkey-io/valkey-operator/internal/valkey"
)

// connConfig is what a connection to a Valkey node needs beyond its address.
type connConfig struct {
	tls      *tls.Config
	username string
	password string
}

// clientOption is the option for a single-node client to address (host:port).
func clientOption(address string, cfg connConfig) vclient.ClientOption {
	return vclient.ClientOption{
		InitAddress:       []string{address},
		ForceSingleClient: true,              // Don't connect to another cluster node.
		ClientName:        "valkey-operator", // Names the connection in CLIENT LIST.
		Username:          cfg.username,
		Password:          cfg.password,
		TLSConfig:         cfg.tls,
		// valkey-go defaults to data-plane sizes: up to 4 connections per
		// client, each with 0.5 MiB buffers either way and a 1024-entry ring.
		// Tuned to this controller's usage: one connection shared by the
		// poller and both reconcilers, each issuing a few commands, CLUSTER
		// NODES the largest response and CLUSTER MIGRATESLOTS the largest
		// request. Exceeding a buffer costs a flush, no error. The pool keeps
		// a client per node, so these sizes are paid once per node.
		PipelineMultiplex:   -1, // at most 1 connection, not the default 4
		ReadBufferEachConn:  4 * 1024,
		WriteBufferEachConn: 4 * 1024,
		RingScaleEachConn:   4, // 2^4 slots, used by concurrent ops only
	}
}

// ClientProvider hands out pooled Valkey clients. The provider owns every
// client it returns; callers never call Close on one. A TLS config built from
// a secret is reused for up to tlsConfigTTL, and rebuilt on the next lookup
// after a dial fails.
type ClientProvider interface {
	// ForCluster resolves the cluster's TLS config and operator credentials
	// once and returns a DialFunc that returns the pooled client for any of
	// its nodes. It returns an error only when the operator password cannot be
	// read or is empty. A TLS config that cannot be built fails each dial
	// instead.
	ForCluster(ctx context.Context, cluster *valkeyiov1alpha1.ValkeyCluster) (valkey.DialFunc, error)

	// ForNode returns the pooled client for the node's pod. It returns an
	// error when the node has no pod IP or cluster label, the TLS config cannot
	// be built, the operator password cannot be read or is empty, or the dial
	// fails. On error the client is nil.
	ForNode(ctx context.Context, node *valkeyiov1alpha1.ValkeyNode) (vclient.Client, error)
}

// NewClientProvider returns a ClientProvider that takes its clients from
// pool. c reads the operator password secret, apiReader the TLS secret.
func NewClientProvider(c client.Client, apiReader client.Reader, pool *valkey.Pool) ClientProvider {
	return &provider{client: c, apiReader: apiReader, pool: pool, tlsConfigs: newTLSConfigCache()}
}

type provider struct {
	client     client.Client
	apiReader  client.Reader
	pool       *valkey.Pool
	tlsConfigs *tlsConfigCache
}

// tlsConfigTTL is how long a TLS config built from a secret is reused before
// the secret is read again.
const tlsConfigTTL = 10 * time.Second

// tlsConfigKey is every input a TLS config is built from.
type tlsConfigKey struct {
	namespace  string
	secretName string
	serverName string
	clientCert bool
}

// builtTLSConfig is a TLS config and its pool token. readAt is taken before
// the secret is read, so an entry never outlives a change to the secret by
// more than tlsConfigTTL.
type builtTLSConfig struct {
	cfg    *tls.Config
	token  string
	readAt time.Time
}

// tlsConfigCache keeps the TLS configs built from server certificate secrets,
// which the manager cache does not hold, so that a client lookup does not
// read the secret from the API server each time. Callers share an entry's
// config and must not modify it.
type tlsConfigCache struct {
	mu      sync.Mutex
	entries map[tlsConfigKey]builtTLSConfig
	// now is time.Now; tests replace it.
	now func() time.Time
}

func newTLSConfigCache() *tlsConfigCache {
	return &tlsConfigCache{entries: map[tlsConfigKey]builtTLSConfig{}, now: time.Now}
}

// get returns the entry for key if its secret was read less than
// tlsConfigTTL ago.
func (c *tlsConfigCache) get(key tlsConfigKey) (builtTLSConfig, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok || c.now().Sub(e.readAt) >= tlsConfigTTL {
		return builtTLSConfig{}, false
	}
	return e, true
}

// put stores e for key and drops every expired entry, so the config of a
// secret that is no longer dialled does not stay in memory.
func (c *tlsConfigCache) put(key tlsConfigKey, e builtTLSConfig) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	maps.DeleteFunc(c.entries, func(_ tlsConfigKey, old builtTLSConfig) bool {
		return now.Sub(old.readAt) >= tlsConfigTTL
	})
	c.entries[key] = e
}

// forget drops the entry for key.
func (c *tlsConfigCache) forget(key tlsConfigKey) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, key)
}

// tlsConfigKeyFor returns the cache key for spec, and false when spec names
// no server certificate secret.
func tlsConfigKeyFor(namespace string, spec *valkeyiov1alpha1.NodeTLSSpec) (tlsConfigKey, bool) {
	if spec == nil || spec.Certificates.Server.SecretName == "" {
		return tlsConfigKey{}, false
	}
	return tlsConfigKey{
		namespace:  namespace,
		secretName: spec.Certificates.Server.SecretName,
		serverName: spec.ServerName,
		clientCert: spec.RequiresClientCertificate(),
	}, true
}

// tlsConfig returns the TLS config for spec and a token that changes whenever
// the config would. Both are empty when spec names no server certificate
// secret. A config is reused for tlsConfigTTL after its secret is read, or
// until forgetTLSConfig drops it. A failed build is not kept.
func (p *provider) tlsConfig(ctx context.Context, namespace string, spec *valkeyiov1alpha1.NodeTLSSpec) (*tls.Config, string, error) {
	key, tlsOn := tlsConfigKeyFor(namespace, spec)
	if !tlsOn {
		return nil, "", nil
	}
	if e, cached := p.tlsConfigs.get(key); cached {
		return e.cfg, e.token, nil
	}
	readAt := p.tlsConfigs.now()
	cfg, resourceVersion, err := getTLSConfig(ctx, p.apiReader, key.secretName, key.serverName, namespace, key.clientCert)
	if err != nil {
		return nil, "", err
	}
	token := fmt.Sprintf("%s/%s/%s/%t", key.secretName, resourceVersion, key.serverName, key.clientCert)
	p.tlsConfigs.put(key, builtTLSConfig{cfg: cfg, token: token, readAt: readAt})
	return cfg, token, nil
}

// forgetTLSConfig drops the TLS config kept for spec, so the next lookup reads
// its secret. A failed dial calls it, since the certificate may have changed.
func (p *provider) forgetTLSConfig(namespace string, spec *valkeyiov1alpha1.NodeTLSSpec) {
	if key, tlsOn := tlsConfigKeyFor(namespace, spec); tlsOn {
		p.tlsConfigs.forget(key)
	}
}

// operatorPassword reads the operator password from the cluster's system
// passwords Secret. The operator always connects as operatorUser, so a missing
// Secret or an empty password is an error.
func (p *provider) operatorPassword(ctx context.Context, clusterName, namespace string) (string, error) {
	password, err := fetchSystemUserPassword(ctx, operatorUser, p.client, clusterName, namespace)
	if err != nil {
		return "", fmt.Errorf("operator password: %w", err)
	}
	if password == "" {
		return "", fmt.Errorf("operator password: secret %s has no %s key", getSystemPasswordSecretName(clusterName), operatorUser)
	}
	return password, nil
}

func (p *provider) ForCluster(ctx context.Context, cluster *valkeyiov1alpha1.ValkeyCluster) (valkey.DialFunc, error) {
	password, err := p.operatorPassword(ctx, cluster.Name, cluster.Namespace)
	if err != nil {
		return nil, err
	}
	cfg := connConfig{username: operatorUser, password: password}

	tlsSpec := nodeTLSFromCluster(cluster)
	tlsCfg, token, err := p.tlsConfig(ctx, cluster.Namespace, tlsSpec)
	if err != nil {
		// Fail each dial, not the caller: the cluster reconcile still has
		// ValkeyNodes to create while the secret is being issued.
		logf.FromContext(ctx).Error(err, "failed to build TLS config for cluster state",
			"secretName", tlsSpec.Certificates.Server.SecretName)
		tlsErr := fmt.Errorf("TLS config: %w", err)
		return func(context.Context, string) (vclient.Client, error) {
			return nil, tlsErr
		}, nil
	}
	cfg.tls = tlsCfg
	namespace := cluster.Namespace

	return func(ctx context.Context, address string) (vclient.Client, error) {
		c, err := p.pool.Get(ctx, clientOption(address, cfg), token)
		if err != nil {
			p.forgetTLSConfig(namespace, tlsSpec)
			return nil, err
		}
		return c, nil
	}, nil
}

func (p *provider) ForNode(ctx context.Context, node *valkeyiov1alpha1.ValkeyNode) (vclient.Client, error) {
	if node.Status.PodIP == "" {
		return nil, fmt.Errorf("node %s has no pod IP", node.Name)
	}
	clusterName := node.Labels[LabelCluster]
	if clusterName == "" {
		return nil, fmt.Errorf("node %s has no %s label", node.Name, LabelCluster)
	}
	tlsSpec := node.Spec.TLS
	if tlsSpec != nil {
		tlsSpec = tlsSpec.DeepCopy()
		tlsSpec.ServerName = nodeTLSServerName(node)
	}
	tlsCfg, token, err := p.tlsConfig(ctx, node.Namespace, tlsSpec)
	if err != nil {
		return nil, fmt.Errorf("TLS config: %w", err)
	}
	password, err := p.operatorPassword(ctx, clusterName, node.Namespace)
	if err != nil {
		return nil, err
	}
	cfg := connConfig{tls: tlsCfg, username: operatorUser, password: password}

	c, err := p.pool.Get(ctx, clientOption(net.JoinHostPort(node.Status.PodIP, strconv.Itoa(DefaultPort)), cfg), token)
	if err != nil {
		p.forgetTLSConfig(node.Namespace, tlsSpec)
		return nil, err
	}
	return c, nil
}
