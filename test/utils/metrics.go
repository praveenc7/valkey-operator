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

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
)

// MetricSample is one series of a scraped metric family.
type MetricSample struct {
	Labels map[string]string
	Value  float64
}

// Metrics holds the samples of each metric family in a scrape, keyed by
// family name.
type Metrics map[string][]MetricSample

// ParseMetrics parses a scrape in the Prometheus text format, such as the body
// a /metrics endpoint serves. Counters, gauges and untyped metrics are kept.
// Histograms and summaries have no single value per series and are left out.
func ParseMetrics(text string) (Metrics, error) {
	// The parser fails on a last line that has no newline, as in output
	// trimmed with strings.TrimSpace.
	if !strings.HasSuffix(text, "\n") {
		text += "\n"
	}
	parser := expfmt.NewTextParser(model.UTF8Validation)
	families, err := parser.TextToMetricFamilies(strings.NewReader(text))
	if err != nil {
		return nil, err
	}
	metrics := Metrics{}
	for name, family := range families {
		for _, metric := range family.GetMetric() {
			value, ok := sampleValue(family.GetType(), metric)
			if !ok {
				continue
			}
			labels := make(map[string]string, len(metric.GetLabel()))
			for _, pair := range metric.GetLabel() {
				labels[pair.GetName()] = pair.GetValue()
			}
			metrics[name] = append(metrics[name], MetricSample{Labels: labels, Value: value})
		}
	}
	return metrics, nil
}

// Select returns the samples of the metric family name that carry every label
// in labels, whatever their other labels.
func (m Metrics) Select(name string, labels map[string]string) []MetricSample {
	selected := make([]MetricSample, 0, len(m[name]))
	for _, sample := range m[name] {
		if hasLabels(sample.Labels, labels) {
			selected = append(selected, sample)
		}
	}
	return selected
}

func sampleValue(metricType dto.MetricType, metric *dto.Metric) (float64, bool) {
	switch metricType {
	case dto.MetricType_COUNTER:
		return metric.GetCounter().GetValue(), true
	case dto.MetricType_GAUGE:
		return metric.GetGauge().GetValue(), true
	case dto.MetricType_UNTYPED:
		return metric.GetUntyped().GetValue(), true
	default:
		return 0, false
	}
}

func hasLabels(got, want map[string]string) bool {
	for name, value := range want {
		if got[name] != value {
			return false
		}
	}
	return true
}
