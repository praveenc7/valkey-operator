//go:build e2e

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

package e2e

import (
	"fmt"
	"os/exec"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	valkeyiov1alpha1 "github.com/valkey-io/valkey-operator/api/v1alpha1"
	"github.com/valkey-io/valkey-operator/test/utils"
)

var _ = Describe("Operator metrics", Label("operator-metrics"), func() {
	AfterEach(func() {
		specReport := CurrentSpecReport()
		if specReport.Failed() {
			utils.CollectDebugInfo(namespace)
		}
	})

	It("serves the build info, a Ready cluster's gauges and both controllers' reconcile counts", func() {
		const (
			clusterName = "valkeycluster-metrics-e2e"
			shards      = 2
			podName     = "curl-operator-metrics"
			bindingName = "valkey-operator-metrics-e2e-binding"
		)
		DeferCleanup(func() {
			_, _ = utils.Run(exec.Command("kubectl", "delete", "valkeycluster", clusterName,
				"--ignore-not-found=true", "--wait=false"))
			_, _ = utils.Run(exec.Command("kubectl", "delete", "pod", podName, "-n", namespace,
				"--ignore-not-found=true", "--wait=false"))
			_, _ = utils.Run(exec.Command("kubectl", "delete", "clusterrolebinding", bindingName,
				"--ignore-not-found=true"))
		})

		By("allowing the controller-manager service account to read the metrics")
		_, _ = utils.Run(exec.Command("kubectl", "delete", "clusterrolebinding", bindingName, "--ignore-not-found=true"))
		cmd := exec.Command("kubectl", "create", "clusterrolebinding", bindingName,
			"--clusterrole=valkey-operator-metrics-reader",
			fmt.Sprintf("--serviceaccount=%s:%s", namespace, serviceAccountName))
		_, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to create ClusterRoleBinding")

		By("starting a pod that runs as that service account")
		_, _ = utils.Run(exec.Command("kubectl", "delete", "pod", podName, "-n", namespace,
			"--ignore-not-found=true", "--wait=true", "--timeout=30s"))
		cmd = exec.Command("kubectl", "run", podName, "--restart=Never",
			"--namespace", namespace,
			"--image=curlimages/curl:latest",
			"--overrides",
			fmt.Sprintf(`{
				"spec": {
					"containers": [{
						"name": "curl",
						"image": "curlimages/curl:latest",
						"command": ["/bin/sh", "-c"],
						"args": ["sleep 3600"],
						"securityContext": {
							"readOnlyRootFilesystem": true,
							"allowPrivilegeEscalation": false,
							"capabilities": {
								"drop": ["ALL"]
							},
							"runAsNonRoot": true,
							"runAsUser": 1000,
							"seccompProfile": {
								"type": "RuntimeDefault"
							}
						}
					}],
					"serviceAccountName": "%s"
				}
			}`, serviceAccountName))
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to create the metrics pod")

		By(fmt.Sprintf("creating a ValkeyCluster with %d shards", shards))
		cmd = exec.Command("kubectl", "apply", "-f", "-")
		cmd.Stdin = strings.NewReader(fmt.Sprintf(`apiVersion: valkey.io/v1alpha1
kind: ValkeyCluster
metadata:
  name: %s
spec:
  acl:
    users:
      - name: default
        password:
          type: Any
        permissions: "~* &* +@all"
  shards: %d
  replicasPerShard: 0
  exporter:
    enabled: false
`, clusterName, shards))
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to create ValkeyCluster")

		By("waiting for the cluster to become Ready")
		var clusterNamespace string
		Eventually(func(g Gomega) {
			cr, err := utils.GetValkeyClusterStatus(clusterName)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(cr.Status.State).To(Equal(valkeyiov1alpha1.ClusterStateReady))
			g.Expect(cr.Status.Shards).To(Equal(int32(shards)))
			g.Expect(cr.Status.ReadyShards).To(Equal(int32(shards)))
			clusterNamespace = cr.Namespace
		}, 10*time.Minute, 2*time.Second).Should(Succeed())

		By("waiting for the metrics pod to run")
		Eventually(func(g Gomega) {
			out, err := utils.Run(exec.Command("kubectl", "get", "pod", podName, "-n", namespace,
				"-o", "jsonpath={.status.phase}"))
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(out).To(Equal("Running"))
		}).Should(Succeed())

		By("checking the build info, the cluster's gauges and both controllers' reconcile counts")
		// utils.Run returns stderr along with stdout, so on success the command
		// must print nothing but the response body, which is parsed.
		scrape := fmt.Sprintf(`curl -sSf -k --max-time 10 `+
			`-H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" `+
			`https://%s.%s.svc.cluster.local:8443/metrics`, metricsServiceName, namespace)
		clusterLabels := map[string]string{"valkey_cluster": clusterName, "target_namespace": clusterNamespace}
		wantStates := map[string]float64{}
		for _, state := range valkeyiov1alpha1.ClusterStates {
			wantStates[string(state)] = 0
		}
		wantStates[string(valkeyiov1alpha1.ClusterStateReady)] = 1
		Eventually(func(g Gomega) {
			out, err := utils.Run(exec.Command("kubectl", "exec", podName, "-n", namespace, "-c", "curl", "--",
				"sh", "-c", scrape))
			g.Expect(err).NotTo(HaveOccurred())
			metrics, err := utils.ParseMetrics(out)
			g.Expect(err).NotTo(HaveOccurred())

			g.Expect(metrics.Select("valkey_operator_build_info", nil)).To(ConsistOf(HaveField("Value", 1.0)))

			states := map[string]float64{}
			for _, sample := range metrics.Select("valkey_operator_cluster_state_info", clusterLabels) {
				states[sample.Labels["state"]] = sample.Value
			}
			g.Expect(states).To(Equal(wantStates))
			g.Expect(metrics.Select("valkey_operator_cluster_shards", clusterLabels)).
				To(ConsistOf(HaveField("Value", float64(shards))))
			g.Expect(metrics.Select("valkey_operator_cluster_shards_ready", clusterLabels)).
				To(ConsistOf(HaveField("Value", float64(shards))))

			for _, name := range []string{"valkeycluster", "valkeynode"} {
				g.Expect(metrics.Select("controller_runtime_reconcile_total", map[string]string{"controller": name})).
					To(ContainElement(HaveField("Value", BeNumerically(">", 0))),
						"no reconcile counted for controller %s", name)
			}
		}).Should(Succeed())
	})
})
