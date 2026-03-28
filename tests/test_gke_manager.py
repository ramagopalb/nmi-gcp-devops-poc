"""Tests for GKE Cluster Manager — NMI Payments Platform."""
import pytest
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from gke_manager import (
    GKEClusterManager, GKECluster, GKENode, NodePool, KubernetesWorkload,
    NodeStatus, ClusterHealth, WorkloadIdentityStatus
)


def make_cluster(name="nmi-payments", private=True, wi=True, kms="key", vpc_sc=True, binauthz=True):
    return GKECluster(
        name=name, project="nmi-prod", region="europe-west2", zone="europe-west2-a",
        private_endpoint_only=private, workload_identity_enabled=wi, kms_key=kms,
        vpc_service_controls=vpc_sc, binary_authorization_enabled=binauthz
    )


def make_node(name, status=NodeStatus.READY, cpu=30.0, mem=40.0, disk=20.0, pool="payments-pool"):
    return GKENode(name=name, status=status, cpu_usage_percent=cpu,
                   memory_usage_percent=mem, disk_usage_percent=disk, pool=pool, zone="europe-west2-a")


def make_workload(name, ns="payments", desired=3, ready=3, sa="payment-sa",
                  wi_ann="serviceAccount:nmi-prod.svc.id.goog[payments/payment-sa]", crashes=0):
    return KubernetesWorkload(name=name, namespace=ns, replicas_desired=desired,
                               replicas_ready=ready, service_account=sa,
                               workload_identity_annotation=wi_ann, crash_loop_count=crashes)


# Cluster health tests
class TestClusterHealth:
    def test_all_ready_nodes_healthy(self):
        cluster = make_cluster()
        cluster.nodes = [make_node(f"node-{i}") for i in range(3)]
        mgr = GKEClusterManager(cluster)
        result = mgr.get_cluster_health()
        assert result["health"] == ClusterHealth.HEALTHY.value
        assert result["score"] == 100
        assert result["ready_nodes"] == 3
        assert result["total_nodes"] == 3

    def test_one_not_ready_node_degraded(self):
        # 4 nodes, 1 NOT_READY => 3/4 = 75% => CRITICAL (below 80%)
        # Use 5 nodes with 1 NOT_READY => 4/5 = 80% => DEGRADED
        cluster = make_cluster()
        cluster.nodes = [make_node(f"node-{i}") for i in range(4)] + [make_node("node-4", NodeStatus.NOT_READY)]
        mgr = GKEClusterManager(cluster)
        result = mgr.get_cluster_health()
        assert result["health"] == ClusterHealth.DEGRADED.value
        assert result["ready_nodes"] == 4
        assert "node-4" in result["critical_nodes"]

    def test_majority_not_ready_critical(self):
        cluster = make_cluster()
        cluster.nodes = [make_node("n0"), make_node("n1", NodeStatus.NOT_READY),
                         make_node("n2", NodeStatus.NOT_READY), make_node("n3", NodeStatus.NOT_READY)]
        mgr = GKEClusterManager(cluster)
        result = mgr.get_cluster_health()
        assert result["health"] == ClusterHealth.CRITICAL.value
        assert result["score"] < 50

    def test_empty_cluster_critical(self):
        cluster = make_cluster()
        mgr = GKEClusterManager(cluster)
        result = mgr.get_cluster_health()
        assert result["health"] == ClusterHealth.CRITICAL.value
        assert result["score"] == 0

    def test_disk_pressure_node_critical(self):
        cluster = make_cluster()
        cluster.nodes = [make_node("n0"), make_node("n1", NodeStatus.DISK_PRESSURE)]
        mgr = GKEClusterManager(cluster)
        result = mgr.get_cluster_health()
        assert "n1" in result["critical_nodes"]


# PCI-DSS control tests
class TestPCIDSSControls:
    def test_full_pci_compliant_cluster(self):
        cluster = make_cluster()
        mgr = GKEClusterManager(cluster)
        result = mgr.check_pci_dss_controls()
        assert result["compliant"] is True
        assert len(result["blocking_findings"]) == 0
        assert result["passed_count"] == 5

    def test_no_private_endpoint_blocks(self):
        cluster = make_cluster(private=False)
        mgr = GKEClusterManager(cluster)
        result = mgr.check_pci_dss_controls()
        assert result["compliant"] is False
        blocking = [f["rule"] for f in result["blocking_findings"]]
        assert "private_endpoint_only" in blocking

    def test_no_kms_blocks(self):
        cluster = make_cluster(kms="")
        mgr = GKEClusterManager(cluster)
        result = mgr.check_pci_dss_controls()
        assert result["compliant"] is False
        blocking = [f["rule"] for f in result["blocking_findings"]]
        assert "kms_encryption" in blocking

    def test_no_workload_identity_fails(self):
        cluster = make_cluster(wi=False)
        mgr = GKEClusterManager(cluster)
        result = mgr.check_pci_dss_controls()
        findings = [f["rule"] for f in result["findings"]]
        assert "workload_identity" in findings

    def test_no_vpc_sc_fails(self):
        cluster = make_cluster(vpc_sc=False)
        mgr = GKEClusterManager(cluster)
        result = mgr.check_pci_dss_controls()
        findings = [f["rule"] for f in result["findings"]]
        assert "vpc_service_controls" in findings

    def test_no_binary_auth_fails(self):
        cluster = make_cluster(binauthz=False)
        mgr = GKEClusterManager(cluster)
        result = mgr.check_pci_dss_controls()
        findings = [f["rule"] for f in result["findings"]]
        assert "binary_authorization" in findings


# Workload Identity tests
class TestWorkloadIdentity:
    def test_bound_workload_identity(self):
        cluster = make_cluster()
        cluster.workloads = [make_workload("payment-gateway")]
        mgr = GKEClusterManager(cluster)
        results = mgr.check_workload_identity()
        assert len(results) == 1
        assert results[0]["status"] == WorkloadIdentityStatus.BOUND.value

    def test_unbound_workload_identity(self):
        cluster = make_cluster()
        cluster.workloads = [make_workload("legacy-service", wi_ann=None)]
        mgr = GKEClusterManager(cluster)
        results = mgr.check_workload_identity()
        assert results[0]["status"] == WorkloadIdentityStatus.UNBOUND.value

    def test_multiple_workloads(self):
        cluster = make_cluster()
        cluster.workloads = [
            make_workload("payment-gateway"),
            make_workload("legacy-svc", wi_ann=None),
        ]
        mgr = GKEClusterManager(cluster)
        results = mgr.check_workload_identity()
        statuses = {r["workload"]: r["status"] for r in results}
        assert statuses["payment-gateway"] == WorkloadIdentityStatus.BOUND.value
        assert statuses["legacy-svc"] == WorkloadIdentityStatus.UNBOUND.value


# Crash loop tests
class TestCrashLoopDetection:
    def test_crash_looping_workload_detected(self):
        cluster = make_cluster()
        cluster.workloads = [make_workload("broken-svc", crashes=5)]
        mgr = GKEClusterManager(cluster)
        crashing = mgr.get_crashlooping_workloads()
        assert len(crashing) == 1
        assert crashing[0]["name"] == "broken-svc"
        assert crashing[0]["severity"] == "CRITICAL"

    def test_low_crash_count_warning(self):
        cluster = make_cluster()
        cluster.workloads = [make_workload("flaky-svc", crashes=2)]
        mgr = GKEClusterManager(cluster)
        crashing = mgr.get_crashlooping_workloads()
        assert crashing[0]["severity"] == "WARNING"

    def test_no_crashes_empty(self):
        cluster = make_cluster()
        cluster.workloads = [make_workload("healthy-svc")]
        mgr = GKEClusterManager(cluster)
        crashing = mgr.get_crashlooping_workloads()
        assert crashing == []


# Terraform HCL generation tests
class TestTerraformGeneration:
    def test_generates_valid_hcl(self):
        cluster = make_cluster()
        cluster.node_pools = [NodePool("payments-pool", "n1-standard-4", 2, 10, 3)]
        mgr = GKEClusterManager(cluster)
        hcl = mgr.generate_terraform_hcl()
        assert "google_container_cluster" in hcl
        assert "nmi-payments" in hcl
        assert "enable_private_endpoint = true" in hcl
        assert "ENCRYPTED" in hcl
        assert "google_container_node_pool" in hcl
        assert "GKE_METADATA" in hcl

    def test_private_endpoint_disabled_in_hcl(self):
        cluster = make_cluster(private=False)
        mgr = GKEClusterManager(cluster)
        hcl = mgr.generate_terraform_hcl()
        assert "enable_private_endpoint = false" in hcl


# Resource pressure tests
class TestNodeResourcePressure:
    def test_high_cpu_node_flagged(self):
        cluster = make_cluster()
        cluster.nodes = [make_node("hot-node", cpu=90.0)]
        mgr = GKEClusterManager(cluster)
        result = mgr.get_node_resource_pressure()
        assert len(result) == 1
        assert any("CPU" in i for i in result[0]["issues"])

    def test_normal_node_not_flagged(self):
        cluster = make_cluster()
        cluster.nodes = [make_node("healthy-node", cpu=40.0, mem=50.0, disk=30.0)]
        mgr = GKEClusterManager(cluster)
        result = mgr.get_node_resource_pressure()
        assert result == []

    def test_multi_issue_node_critical(self):
        cluster = make_cluster()
        cluster.nodes = [make_node("struggling-node", cpu=90.0, mem=95.0)]
        mgr = GKEClusterManager(cluster)
        result = mgr.get_node_resource_pressure()
        assert result[0]["severity"] == "CRITICAL"
