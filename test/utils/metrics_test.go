/*
Copyright 2026 Valkey Contributors.

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

package utils

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const scrape = `# HELP valkey_operator_build_info A metric with a constant '1' value.
# TYPE valkey_operator_build_info gauge
valkey_operator_build_info{branch="main",goversion="go1.26.2",version="v0.0.1"} 1
# HELP valkey_operator_cluster_state_info Information about a ValkeyCluster.
# TYPE valkey_operator_cluster_state_info gauge
valkey_operator_cluster_state_info{state="Failed",target_namespace="default",valkey_cluster="a"} 0
valkey_operator_cluster_state_info{state="Ready",target_namespace="default",valkey_cluster="a"} 1
valkey_operator_cluster_state_info{state="Ready",target_namespace="default",valkey_cluster="b"} 0
valkey_operator_cluster_state_info{state="Ready",target_namespace="other",valkey_cluster="a"} 0
# HELP controller_runtime_reconcile_total Total number of reconciliations per controller
# TYPE controller_runtime_reconcile_total counter
controller_runtime_reconcile_total{controller="valkeycluster",result="requeue_after"} 7
controller_runtime_reconcile_total{controller="valkeycluster",result="success"} 0
# HELP controller_runtime_reconcile_time_seconds Length of time per reconciliation per controller
# TYPE controller_runtime_reconcile_time_seconds histogram
controller_runtime_reconcile_time_seconds_bucket{controller="valkeycluster",le="+Inf"} 7
controller_runtime_reconcile_time_seconds_sum{controller="valkeycluster"} 0.25
controller_runtime_reconcile_time_seconds_count{controller="valkeycluster"} 7
untyped_metric{path="a \"quoted\" value"} 2.5
`

func TestParseMetrics(t *testing.T) {
	metrics, err := ParseMetrics(scrape)
	require.NoError(t, err)

	assert.Equal(t, []MetricSample{{
		Labels: map[string]string{"branch": "main", "goversion": "go1.26.2", "version": "v0.0.1"},
		Value:  1,
	}}, metrics["valkey_operator_build_info"])
	assert.ElementsMatch(t, []MetricSample{
		{Labels: map[string]string{"controller": "valkeycluster", "result": "requeue_after"}, Value: 7},
		{Labels: map[string]string{"controller": "valkeycluster", "result": "success"}, Value: 0},
	}, metrics["controller_runtime_reconcile_total"])
	assert.Equal(t, []MetricSample{{Labels: map[string]string{"path": `a "quoted" value`}, Value: 2.5}},
		metrics["untyped_metric"])
	assert.Len(t, metrics["valkey_operator_cluster_state_info"], 4)
	for name := range metrics {
		assert.NotContains(t, name, "controller_runtime_reconcile_time_seconds", "histograms are left out")
	}
}

func TestParseMetricsAcceptsTrimmedOutput(t *testing.T) {
	metrics, err := ParseMetrics(strings.TrimSpace(scrape))
	require.NoError(t, err)
	assert.Equal(t, []MetricSample{{Labels: map[string]string{"path": `a "quoted" value`}, Value: 2.5}},
		metrics["untyped_metric"])
}

func TestParseMetricsRejectsMalformedInput(t *testing.T) {
	for _, text := range []string{
		"valkey_operator_cluster_shards{valkey_cluster=\"a\" 2\n",
		"Error from server (NotFound): pods \"curl\" not found\n",
	} {
		_, err := ParseMetrics(text)
		assert.Error(t, err, text)
	}
}

func TestMetricsSelect(t *testing.T) {
	metrics, err := ParseMetrics(scrape)
	require.NoError(t, err)

	assert.ElementsMatch(t, []MetricSample{
		{Labels: map[string]string{"state": "Failed", "target_namespace": "default", "valkey_cluster": "a"}, Value: 0},
		{Labels: map[string]string{"state": "Ready", "target_namespace": "default", "valkey_cluster": "a"}, Value: 1},
	}, metrics.Select("valkey_operator_cluster_state_info",
		map[string]string{"valkey_cluster": "a", "target_namespace": "default"}))
	assert.Equal(t, []MetricSample{
		{Labels: map[string]string{"controller": "valkeycluster", "result": "requeue_after"}, Value: 7},
	}, metrics.Select("controller_runtime_reconcile_total",
		map[string]string{"controller": "valkeycluster", "result": "requeue_after"}))
	assert.Len(t, metrics.Select("valkey_operator_cluster_state_info", nil), 4)
	assert.Empty(t, metrics.Select("valkey_operator_cluster_state_info", map[string]string{"valkey_cluster": "c"}))
	assert.Empty(t, metrics.Select("controller_runtime_reconcile_total", map[string]string{"controller": "valkeynode"}))
	assert.Empty(t, metrics.Select("missing", nil))
}
