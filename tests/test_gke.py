"""
Tests for GKE cluster manager — NMI GCP Payments DevOps POC.
Covers cluster creation, node pool management, HPA/PDB, Workload Identity,
network policy generation, and PCI-DSS compliance validation.
"""

import pytest
from gcp.gke_manager import (
    GKEManager,
    GKEClusterConfig,
    NodePoolConfig,
    HPAConfig,
    PDBConfig,
    WorkloadIdentityConfig,
    ClusterStatus,
    NodePoolStatus,
)


# ─────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────

@pytest.fixture
def manager():
    return GKEManager(project_id="nmi-payments-prod", dry_run=True)


@pytest.fixture
def default_node_pool():
    return NodePoolConfig(
        name="payments-pool",
        machine_type="n2-standard-4",
        min_nodes=2,
        max_nodes=10,
        preemptible=False,
        disk_size_gb=100,
        disk_type="pd-ssd",
        labels={"role": "payments"},
    )


@pytest.fixture
def cluster_config(default_node_pool):
    return GKEClusterConfig(
        project_id="nmi-payments-prod",
        cluster_name="nmi-payments-gke",
        region="europe-west2",
        network="nmi-vpc",
        subnetwork="nmi-payments-subnet",
        node_pools=[default_node_pool],
        release_channel="STABLE",
        private_cluster=True,
        labels={"env": "prod", "team": "platform"},
    )


@pytest.fixture
def manager_with_cluster(manager, cluster_config):
    manager.create_cluster(cluster_config)
    return manager


# ─────────────────────────────────────────
# GKEManager init
# ─────────────────────────────────────────

class TestGKEManagerInit:
    def test_init_sets_project_id(self):
        m = GKEManager(project_id="test-project")
        assert m.project_id == "test-project"

    def test_init_dry_run_default(self):
        m = GKEManager(project_id="test-project")
        assert m.dry_run is True

    def test_init_dry_run_false(self):
        m = GKEManager(project_id="test-project", dry_run=False)
        assert m.dry_run is False

    def test_list_clusters_empty_on_init(self, manager):
        assert manager.list_clusters() == []


# ─────────────────────────────────────────
# Cluster creation
# ─────────────────────────────────────────

class TestClusterCreation:
    def test_create_cluster_returns_operation(self, manager, cluster_config):
        result = manager.create_cluster(cluster_config)
        assert result["operation"] == "CREATE_CLUSTER"

    def test_create_cluster_returns_cluster_dict(self, manager, cluster_config):
        result = manager.create_cluster(cluster_config)
        assert "cluster" in result

    def test_create_cluster_stores_cluster(self, manager, cluster_config):
        manager.create_cluster(cluster_config)
        assert "nmi-payments-gke" in [c["name"] for c in manager.list_clusters()]

    def test_create_cluster_status_running_dry_run(self, manager, cluster_config):
        result = manager.create_cluster(cluster_config)
        assert result["cluster"]["status"] == ClusterStatus.RUNNING.value

    def test_create_cluster_sets_private_config(self, manager, cluster_config):
        result = manager.create_cluster(cluster_config)
        assert result["cluster"]["privateClusterConfig"]["enablePrivateNodes"] is True

    def test_create_cluster_sets_workload_identity(self, manager, cluster_config):
        result = manager.create_cluster(cluster_config)
        wi = result["cluster"]["workloadIdentityConfig"]
        assert "nmi-payments-prod.svc.id.goog" in wi["workloadPool"]

    def test_create_cluster_includes_node_pools(self, manager, cluster_config):
        result = manager.create_cluster(cluster_config)
        assert len(result["cluster"]["nodePools"]) == 1

    def test_create_cluster_node_pool_name(self, manager, cluster_config):
        result = manager.create_cluster(cluster_config)
        assert result["cluster"]["nodePools"][0]["name"] == "payments-pool"

    def test_duplicate_cluster_raises(self, manager, cluster_config):
        manager.create_cluster(cluster_config)
        with pytest.raises(ValueError, match="already exists"):
            manager.create_cluster(cluster_config)

    def test_create_cluster_sets_release_channel(self, manager, cluster_config):
        result = manager.create_cluster(cluster_config)
        assert result["cluster"]["releaseChannel"]["channel"] == "STABLE"

    def test_create_cluster_invalid_config_raises(self, manager):
        bad_config = GKEClusterConfig(
            project_id="",
            cluster_name="bad",
            region="europe-west2",
            network="vpc",
            subnetwork="subnet",
        )
        with pytest.raises(ValueError, match="Invalid cluster config"):
            manager.create_cluster(bad_config)


# ─────────────────────────────────────────
# Cluster retrieval and deletion
# ─────────────────────────────────────────

class TestClusterRetrieval:
    def test_get_cluster_returns_dict(self, manager_with_cluster):
        cluster = manager_with_cluster.get_cluster("nmi-payments-gke")
        assert cluster["name"] == "nmi-payments-gke"

    def test_get_nonexistent_cluster_raises(self, manager):
        with pytest.raises(KeyError):
            manager.get_cluster("does-not-exist")

    def test_list_clusters_returns_list(self, manager_with_cluster):
        clusters = manager_with_cluster.list_clusters()
        assert isinstance(clusters, list)
        assert len(clusters) == 1

    def test_delete_cluster_removes_it(self, manager_with_cluster):
        manager_with_cluster.delete_cluster("nmi-payments-gke")
        assert manager_with_cluster.list_clusters() == []

    def test_delete_nonexistent_raises(self, manager):
        with pytest.raises(KeyError):
            manager.delete_cluster("ghost-cluster")


# ─────────────────────────────────────────
# Node pool management
# ─────────────────────────────────────────

class TestNodePoolManagement:
    def test_add_node_pool_returns_operation(self, manager_with_cluster):
        new_pool = NodePoolConfig(
            name="spot-pool",
            machine_type="n2-standard-2",
            min_nodes=0,
            max_nodes=5,
            preemptible=True,
        )
        result = manager_with_cluster.add_node_pool("nmi-payments-gke", new_pool)
        assert result["operation"] == "ADD_NODE_POOL"

    def test_add_node_pool_appends_to_cluster(self, manager_with_cluster):
        new_pool = NodePoolConfig(
            name="spot-pool",
            machine_type="n2-standard-2",
            min_nodes=0,
            max_nodes=5,
        )
        manager_with_cluster.add_node_pool("nmi-payments-gke", new_pool)
        cluster = manager_with_cluster.get_cluster("nmi-payments-gke")
        assert len(cluster["nodePools"]) == 2

    def test_add_pool_to_nonexistent_cluster_raises(self, manager):
        pool = NodePoolConfig("pool", "n2-standard-2", 1, 3)
        with pytest.raises(KeyError):
            manager.add_node_pool("ghost", pool)

    def test_invalid_node_pool_config_raises(self, manager_with_cluster):
        bad_pool = NodePoolConfig(
            name="bad-pool",
            machine_type="n2-standard-2",
            min_nodes=10,
            max_nodes=5,  # max < min
        )
        with pytest.raises(ValueError):
            manager_with_cluster.add_node_pool("nmi-payments-gke", bad_pool)


# ─────────────────────────────────────────
# NodePoolConfig validation
# ─────────────────────────────────────────

class TestNodePoolConfigValidation:
    def test_valid_config_no_errors(self):
        pool = NodePoolConfig("pool", "n2-standard-4", 1, 5)
        assert pool.validate() == []

    def test_invalid_min_nodes(self):
        pool = NodePoolConfig("pool", "n2-standard-4", -1, 5)
        errors = pool.validate()
        assert any("min_nodes" in e for e in errors)

    def test_invalid_max_less_than_min(self):
        pool = NodePoolConfig("pool", "n2-standard-4", 5, 2)
        errors = pool.validate()
        assert any("max_nodes" in e for e in errors)

    def test_invalid_disk_size(self):
        pool = NodePoolConfig("pool", "n2-standard-4", 1, 5, disk_size_gb=5)
        errors = pool.validate()
        assert any("disk_size_gb" in e for e in errors)

    def test_empty_name_invalid(self):
        pool = NodePoolConfig("", "n2-standard-4", 1, 5)
        errors = pool.validate()
        assert any("name" in e for e in errors)


# ─────────────────────────────────────────
# HPA configuration
# ─────────────────────────────────────────

class TestHPAConfiguration:
    def test_configure_hpa_returns_operation(self, manager):
        config = HPAConfig(
            deployment_name="payment-gateway",
            namespace="payments",
            min_replicas=2,
            max_replicas=20,
            cpu_utilization_percent=70,
        )
        result = manager.configure_hpa(config)
        assert result["operation"] == "CONFIGURE_HPA"

    def test_hpa_manifest_has_correct_kind(self, manager):
        config = HPAConfig("svc", "ns", 1, 5, 80)
        result = manager.configure_hpa(config)
        assert result["manifest"]["kind"] == "HorizontalPodAutoscaler"

    def test_hpa_manifest_min_replicas(self, manager):
        config = HPAConfig("svc", "ns", 3, 10, 70)
        result = manager.configure_hpa(config)
        assert result["manifest"]["spec"]["minReplicas"] == 3

    def test_hpa_manifest_max_replicas(self, manager):
        config = HPAConfig("svc", "ns", 1, 15, 70)
        result = manager.configure_hpa(config)
        assert result["manifest"]["spec"]["maxReplicas"] == 15

    def test_hpa_with_memory_metric(self, manager):
        config = HPAConfig("svc", "ns", 1, 5, 70, memory_utilization_percent=80)
        result = manager.configure_hpa(config)
        metrics = result["manifest"]["spec"]["metrics"]
        resource_names = [m["resource"]["name"] for m in metrics]
        assert "memory" in resource_names

    def test_invalid_hpa_min_replicas_raises(self, manager):
        config = HPAConfig("svc", "ns", 0, 5, 70)
        with pytest.raises(ValueError):
            manager.configure_hpa(config)

    def test_invalid_hpa_cpu_threshold_raises(self, manager):
        config = HPAConfig("svc", "ns", 1, 5, 110)
        with pytest.raises(ValueError):
            manager.configure_hpa(config)


# ─────────────────────────────────────────
# PDB configuration
# ─────────────────────────────────────────

class TestPDBConfiguration:
    def test_configure_pdb_returns_operation(self, manager):
        config = PDBConfig(
            deployment_name="payment-gateway",
            namespace="payments",
            min_available=1,
        )
        result = manager.configure_pdb(config)
        assert result["operation"] == "CONFIGURE_PDB"

    def test_pdb_manifest_has_correct_kind(self, manager):
        config = PDBConfig("svc", "ns", min_available=1)
        result = manager.configure_pdb(config)
        assert result["manifest"]["kind"] == "PodDisruptionBudget"

    def test_pdb_min_available_in_manifest(self, manager):
        config = PDBConfig("svc", "ns", min_available=2)
        result = manager.configure_pdb(config)
        assert result["manifest"]["spec"]["minAvailable"] == 2

    def test_pdb_max_unavailable_in_manifest(self, manager):
        config = PDBConfig("svc", "ns", max_unavailable=1)
        result = manager.configure_pdb(config)
        assert result["manifest"]["spec"]["maxUnavailable"] == 1

    def test_pdb_no_policy_raises(self, manager):
        config = PDBConfig("svc", "ns")
        with pytest.raises(ValueError):
            manager.configure_pdb(config)


# ─────────────────────────────────────────
# Workload Identity
# ─────────────────────────────────────────

class TestWorkloadIdentity:
    def test_configure_workload_identity_returns_operation(self, manager):
        config = WorkloadIdentityConfig(
            workload_pool="nmi-payments-prod.svc.id.goog",
            namespace="payments",
            service_account="payment-gateway-sa",
            gcp_service_account="payment-gw@nmi-payments-prod.iam.gserviceaccount.com",
        )
        result = manager.configure_workload_identity(config)
        assert result["operation"] == "CONFIGURE_WORKLOAD_IDENTITY"

    def test_workload_identity_binding_format(self, manager):
        config = WorkloadIdentityConfig(
            workload_pool="proj.svc.id.goog",
            namespace="ns",
            service_account="sa",
            gcp_service_account="sa@proj.iam.gserviceaccount.com",
        )
        result = manager.configure_workload_identity(config)
        assert "proj.svc.id.goog" in result["binding"]
        assert "ns/sa" in result["binding"]

    def test_workload_identity_annotation(self, manager):
        config = WorkloadIdentityConfig(
            workload_pool="proj.svc.id.goog",
            namespace="ns",
            service_account="sa",
            gcp_service_account="sa@proj.iam.gserviceaccount.com",
        )
        result = manager.configure_workload_identity(config)
        assert "iam.gke.io/gcp-service-account" in result["annotation"]

    def test_workload_identity_iam_policy(self, manager):
        config = WorkloadIdentityConfig(
            workload_pool="proj.svc.id.goog",
            namespace="ns",
            service_account="sa",
            gcp_service_account="sa@proj.iam.gserviceaccount.com",
        )
        result = manager.configure_workload_identity(config)
        bindings = result["iam_policy"]["bindings"]
        assert bindings[0]["role"] == "roles/iam.workloadIdentityUser"


# ─────────────────────────────────────────
# Cluster health
# ─────────────────────────────────────────

class TestClusterHealth:
    def test_get_cluster_health_returns_dict(self, manager_with_cluster):
        health = manager_with_cluster.get_cluster_health("nmi-payments-gke")
        assert "healthy" in health

    def test_healthy_cluster_is_healthy(self, manager_with_cluster):
        health = manager_with_cluster.get_cluster_health("nmi-payments-gke")
        assert health["healthy"] is True

    def test_cluster_health_node_pool_count(self, manager_with_cluster):
        health = manager_with_cluster.get_cluster_health("nmi-payments-gke")
        assert health["node_pool_count"] == 1


# ─────────────────────────────────────────
# Cluster upgrade
# ─────────────────────────────────────────

class TestClusterUpgrade:
    def test_upgrade_cluster_returns_operation(self, manager_with_cluster):
        result = manager_with_cluster.upgrade_cluster("nmi-payments-gke", "1.29")
        assert result["operation"] == "UPGRADE_CLUSTER"

    def test_upgrade_sets_target_version(self, manager_with_cluster):
        result = manager_with_cluster.upgrade_cluster("nmi-payments-gke", "1.29")
        assert result["to_version"] == "1.29"

    def test_upgrade_dry_run_updates_state(self, manager_with_cluster):
        manager_with_cluster.upgrade_cluster("nmi-payments-gke", "1.29")
        cluster = manager_with_cluster.get_cluster("nmi-payments-gke")
        assert cluster["currentMasterVersion"] == "1.29"


# ─────────────────────────────────────────
# Network policy generation
# ─────────────────────────────────────────

class TestNetworkPolicyGeneration:
    def test_generate_network_policy_kind(self, manager):
        policy = manager.generate_network_policy("payments", "payment-gateway", [8080])
        assert policy["kind"] == "NetworkPolicy"

    def test_network_policy_has_pci_label(self, manager):
        policy = manager.generate_network_policy("payments", "svc", [443])
        assert policy["metadata"]["labels"]["pci-dss"] == "compliant"

    def test_network_policy_ingress_ports(self, manager):
        policy = manager.generate_network_policy("ns", "svc", [8080, 9090])
        ingress_ports = [
            p["port"]
            for rule in policy["spec"]["ingress"]
            for p in rule["ports"]
        ]
        assert 8080 in ingress_ports
        assert 9090 in ingress_ports

    def test_network_policy_egress_includes_https(self, manager):
        policy = manager.generate_network_policy("ns", "svc", [8080])
        egress_ports = [
            p["port"]
            for rule in policy["spec"]["egress"]
            for p in rule["ports"]
        ]
        assert 443 in egress_ports

    def test_network_policy_policy_types(self, manager):
        policy = manager.generate_network_policy("ns", "svc", [8080])
        assert "Ingress" in policy["spec"]["policyTypes"]
        assert "Egress" in policy["spec"]["policyTypes"]

    def test_network_policy_namespace(self, manager):
        policy = manager.generate_network_policy("payments-ns", "svc", [8080])
        assert policy["metadata"]["namespace"] == "payments-ns"
