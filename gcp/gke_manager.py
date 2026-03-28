"""
GKE cluster management for NMI payments platform.
Handles cluster provisioning, Workload Identity, node pool management,
HPA/PDB configuration, and PCI-DSS compliant network policies.
"""

import json
import logging
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum

logger = logging.getLogger(__name__)


class ClusterStatus(Enum):
    RUNNING = "RUNNING"
    PROVISIONING = "PROVISIONING"
    STOPPING = "STOPPING"
    ERROR = "ERROR"
    RECONCILING = "RECONCILING"


class NodePoolStatus(Enum):
    RUNNING = "RUNNING"
    PROVISIONING = "PROVISIONING"
    ERROR = "ERROR"


@dataclass
class WorkloadIdentityConfig:
    """Workload Identity configuration for PCI-DSS compliant GKE workloads."""
    workload_pool: str
    namespace: str
    service_account: str
    gcp_service_account: str

    def to_annotation(self) -> dict:
        return {
            "iam.gke.io/gcp-service-account": self.gcp_service_account
        }

    def to_binding_resource(self) -> str:
        return (
            f"serviceAccount:{self.workload_pool}["
            f"{self.namespace}/{self.service_account}]"
        )


@dataclass
class NodePoolConfig:
    """GKE node pool configuration."""
    name: str
    machine_type: str
    min_nodes: int
    max_nodes: int
    preemptible: bool = False
    disk_size_gb: int = 100
    disk_type: str = "pd-ssd"
    labels: dict = field(default_factory=dict)
    taints: list = field(default_factory=list)

    def validate(self) -> list:
        errors = []
        if self.min_nodes < 0:
            errors.append("min_nodes must be >= 0")
        if self.max_nodes < self.min_nodes:
            errors.append("max_nodes must be >= min_nodes")
        if self.disk_size_gb < 10:
            errors.append("disk_size_gb must be >= 10")
        if not self.name:
            errors.append("name is required")
        if not self.machine_type:
            errors.append("machine_type is required")
        return errors


@dataclass
class HPAConfig:
    """Horizontal Pod Autoscaler configuration."""
    deployment_name: str
    namespace: str
    min_replicas: int
    max_replicas: int
    cpu_utilization_percent: int = 70
    memory_utilization_percent: Optional[int] = None

    def validate(self) -> list:
        errors = []
        if self.min_replicas < 1:
            errors.append("min_replicas must be >= 1")
        if self.max_replicas < self.min_replicas:
            errors.append("max_replicas must be >= min_replicas")
        if not (1 <= self.cpu_utilization_percent <= 100):
            errors.append("cpu_utilization_percent must be between 1 and 100")
        if self.memory_utilization_percent is not None:
            if not (1 <= self.memory_utilization_percent <= 100):
                errors.append("memory_utilization_percent must be between 1 and 100")
        return errors

    def to_manifest(self) -> dict:
        metrics = [
            {
                "type": "Resource",
                "resource": {
                    "name": "cpu",
                    "target": {
                        "type": "Utilization",
                        "averageUtilization": self.cpu_utilization_percent
                    }
                }
            }
        ]
        if self.memory_utilization_percent:
            metrics.append({
                "type": "Resource",
                "resource": {
                    "name": "memory",
                    "target": {
                        "type": "Utilization",
                        "averageUtilization": self.memory_utilization_percent
                    }
                }
            })
        return {
            "apiVersion": "autoscaling/v2",
            "kind": "HorizontalPodAutoscaler",
            "metadata": {
                "name": f"{self.deployment_name}-hpa",
                "namespace": self.namespace
            },
            "spec": {
                "scaleTargetRef": {
                    "apiVersion": "apps/v1",
                    "kind": "Deployment",
                    "name": self.deployment_name
                },
                "minReplicas": self.min_replicas,
                "maxReplicas": self.max_replicas,
                "metrics": metrics
            }
        }


@dataclass
class PDBConfig:
    """Pod Disruption Budget for payment service resilience."""
    deployment_name: str
    namespace: str
    min_available: Optional[int] = None
    max_unavailable: Optional[int] = None

    def validate(self) -> list:
        errors = []
        if self.min_available is None and self.max_unavailable is None:
            errors.append("Either min_available or max_unavailable must be set")
        if self.min_available is not None and self.min_available < 0:
            errors.append("min_available must be >= 0")
        if self.max_unavailable is not None and self.max_unavailable < 0:
            errors.append("max_unavailable must be >= 0")
        return errors

    def to_manifest(self) -> dict:
        spec = {
            "selector": {
                "matchLabels": {"app": self.deployment_name}
            }
        }
        if self.min_available is not None:
            spec["minAvailable"] = self.min_available
        if self.max_unavailable is not None:
            spec["maxUnavailable"] = self.max_unavailable
        return {
            "apiVersion": "policy/v1",
            "kind": "PodDisruptionBudget",
            "metadata": {
                "name": f"{self.deployment_name}-pdb",
                "namespace": self.namespace
            },
            "spec": spec
        }


@dataclass
class GKEClusterConfig:
    """GKE cluster configuration for NMI payments platform."""
    project_id: str
    cluster_name: str
    region: str
    network: str
    subnetwork: str
    node_pools: list = field(default_factory=list)
    workload_identity_pool: Optional[str] = None
    release_channel: str = "STABLE"
    private_cluster: bool = True
    enable_autopilot: bool = False
    labels: dict = field(default_factory=dict)

    def validate(self) -> list:
        errors = []
        if not self.project_id:
            errors.append("project_id is required")
        if not self.cluster_name:
            errors.append("cluster_name is required")
        if not self.region:
            errors.append("region is required")
        if not self.network:
            errors.append("network is required")
        if not self.subnetwork:
            errors.append("subnetwork is required")
        if self.release_channel not in ("RAPID", "REGULAR", "STABLE", "UNSPECIFIED"):
            errors.append(f"Invalid release_channel: {self.release_channel}")
        for pool in self.node_pools:
            pool_errors = pool.validate()
            errors.extend([f"NodePool '{pool.name}': {e}" for e in pool_errors])
        return errors

    def get_workload_identity_pool(self) -> str:
        if self.workload_identity_pool:
            return self.workload_identity_pool
        return f"{self.project_id}.svc.id.goog"


class GKEManager:
    """
    Manages GKE clusters for NMI payments platform.
    Handles cluster lifecycle, node pool management, Workload Identity,
    HPA/PDB configuration, and PCI-DSS network policy enforcement.
    """

    def __init__(self, project_id: str, dry_run: bool = True):
        self.project_id = project_id
        self.dry_run = dry_run
        self._clusters: dict[str, dict] = {}
        self._hpa_configs: dict[str, HPAConfig] = {}
        self._pdb_configs: dict[str, PDBConfig] = {}
        logger.info(
            "GKEManager initialized",
            extra={"project_id": project_id, "dry_run": dry_run}
        )

    def create_cluster(self, config: GKEClusterConfig) -> dict:
        """
        Create a GKE cluster with Workload Identity and private networking.
        Returns operation dict with cluster details.
        """
        errors = config.validate()
        if errors:
            raise ValueError(f"Invalid cluster config: {errors}")

        if config.cluster_name in self._clusters:
            raise ValueError(f"Cluster '{config.cluster_name}' already exists")

        cluster_resource = {
            "name": config.cluster_name,
            "project": config.project_id,
            "region": config.region,
            "network": config.network,
            "subnetwork": config.subnetwork,
            "status": ClusterStatus.PROVISIONING.value,
            "releaseChannel": {"channel": config.release_channel},
            "privateClusterConfig": {
                "enablePrivateNodes": config.private_cluster,
                "enablePrivateEndpoint": False,
            },
            "workloadIdentityConfig": {
                "workloadPool": config.get_workload_identity_pool()
            },
            "labels": config.labels,
            "autopilot": {"enabled": config.enable_autopilot},
            "nodePools": [
                {
                    "name": pool.name,
                    "config": {
                        "machineType": pool.machine_type,
                        "diskSizeGb": pool.disk_size_gb,
                        "diskType": pool.disk_type,
                        "preemptible": pool.preemptible,
                        "labels": pool.labels,
                        "taints": pool.taints,
                    },
                    "autoscaling": {
                        "enabled": True,
                        "minNodeCount": pool.min_nodes,
                        "maxNodeCount": pool.max_nodes,
                    },
                    "status": NodePoolStatus.PROVISIONING.value,
                }
                for pool in config.node_pools
            ]
        }

        if not self.dry_run:
            logger.info(f"Creating GKE cluster: {config.cluster_name}")
            # Real API call would go here
        else:
            logger.info(f"[DRY RUN] Would create GKE cluster: {config.cluster_name}")
            cluster_resource["status"] = ClusterStatus.RUNNING.value
            for pool in cluster_resource["nodePools"]:
                pool["status"] = NodePoolStatus.RUNNING.value

        self._clusters[config.cluster_name] = cluster_resource
        return {"operation": "CREATE_CLUSTER", "cluster": cluster_resource}

    def get_cluster(self, cluster_name: str) -> dict:
        """Get cluster details by name."""
        if cluster_name not in self._clusters:
            raise KeyError(f"Cluster '{cluster_name}' not found")
        return self._clusters[cluster_name]

    def list_clusters(self) -> list:
        """List all managed clusters."""
        return list(self._clusters.values())

    def delete_cluster(self, cluster_name: str) -> dict:
        """Delete a GKE cluster."""
        if cluster_name not in self._clusters:
            raise KeyError(f"Cluster '{cluster_name}' not found")

        cluster = self._clusters[cluster_name]
        cluster["status"] = ClusterStatus.STOPPING.value

        if not self.dry_run:
            logger.info(f"Deleting GKE cluster: {cluster_name}")
        else:
            logger.info(f"[DRY RUN] Would delete GKE cluster: {cluster_name}")
            del self._clusters[cluster_name]

        return {"operation": "DELETE_CLUSTER", "cluster_name": cluster_name}

    def add_node_pool(self, cluster_name: str, pool_config: NodePoolConfig) -> dict:
        """Add a node pool to an existing cluster."""
        if cluster_name not in self._clusters:
            raise KeyError(f"Cluster '{cluster_name}' not found")

        errors = pool_config.validate()
        if errors:
            raise ValueError(f"Invalid node pool config: {errors}")

        cluster = self._clusters[cluster_name]
        new_pool = {
            "name": pool_config.name,
            "config": {
                "machineType": pool_config.machine_type,
                "diskSizeGb": pool_config.disk_size_gb,
                "diskType": pool_config.disk_type,
                "preemptible": pool_config.preemptible,
                "labels": pool_config.labels,
            },
            "autoscaling": {
                "enabled": True,
                "minNodeCount": pool_config.min_nodes,
                "maxNodeCount": pool_config.max_nodes,
            },
            "status": NodePoolStatus.RUNNING.value,
        }
        cluster["nodePools"].append(new_pool)
        return {"operation": "ADD_NODE_POOL", "pool": new_pool}

    def configure_hpa(self, config: HPAConfig) -> dict:
        """Configure HPA for a payment service deployment."""
        errors = config.validate()
        if errors:
            raise ValueError(f"Invalid HPA config: {errors}")

        key = f"{config.namespace}/{config.deployment_name}"
        self._hpa_configs[key] = config
        manifest = config.to_manifest()
        logger.info(f"HPA configured for {key}")
        return {"operation": "CONFIGURE_HPA", "manifest": manifest}

    def configure_pdb(self, config: PDBConfig) -> dict:
        """Configure PDB for payment service disruption budget."""
        errors = config.validate()
        if errors:
            raise ValueError(f"Invalid PDB config: {errors}")

        key = f"{config.namespace}/{config.deployment_name}"
        self._pdb_configs[key] = config
        manifest = config.to_manifest()
        logger.info(f"PDB configured for {key}")
        return {"operation": "CONFIGURE_PDB", "manifest": manifest}

    def configure_workload_identity(self, config: WorkloadIdentityConfig) -> dict:
        """Configure Workload Identity binding for PCI-DSS compliance."""
        binding = config.to_binding_resource()
        annotation = config.to_annotation()
        return {
            "operation": "CONFIGURE_WORKLOAD_IDENTITY",
            "binding": binding,
            "annotation": annotation,
            "iam_policy": {
                "bindings": [
                    {
                        "role": "roles/iam.workloadIdentityUser",
                        "members": [f"serviceAccount:{binding}"]
                    }
                ]
            }
        }

    def get_cluster_health(self, cluster_name: str) -> dict:
        """Get cluster health status including node pool conditions."""
        cluster = self.get_cluster(cluster_name)
        node_pools = cluster.get("nodePools", [])
        healthy_pools = [
            p for p in node_pools
            if p.get("status") == NodePoolStatus.RUNNING.value
        ]
        return {
            "cluster_name": cluster_name,
            "cluster_status": cluster.get("status"),
            "node_pool_count": len(node_pools),
            "healthy_node_pools": len(healthy_pools),
            "healthy": (
                cluster.get("status") == ClusterStatus.RUNNING.value
                and len(healthy_pools) == len(node_pools)
            )
        }

    def upgrade_cluster(self, cluster_name: str, target_version: str) -> dict:
        """Trigger a cluster version upgrade."""
        cluster = self.get_cluster(cluster_name)
        previous_version = cluster.get("currentMasterVersion", "unknown")
        cluster["pendingUpgrade"] = {
            "targetVersion": target_version,
            "previousVersion": previous_version
        }
        if not self.dry_run:
            logger.info(
                f"Upgrading cluster {cluster_name} to {target_version}"
            )
        else:
            logger.info(
                f"[DRY RUN] Would upgrade {cluster_name} to {target_version}"
            )
            cluster["currentMasterVersion"] = target_version
        return {
            "operation": "UPGRADE_CLUSTER",
            "cluster_name": cluster_name,
            "from_version": previous_version,
            "to_version": target_version,
        }

    def generate_network_policy(
        self, namespace: str, app_label: str, ingress_ports: list
    ) -> dict:
        """Generate PCI-DSS compliant Kubernetes network policy."""
        return {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {
                "name": f"{app_label}-network-policy",
                "namespace": namespace,
                "labels": {
                    "pci-dss": "compliant",
                    "managed-by": "gke-manager"
                }
            },
            "spec": {
                "podSelector": {
                    "matchLabels": {"app": app_label}
                },
                "policyTypes": ["Ingress", "Egress"],
                "ingress": [
                    {
                        "ports": [
                            {"port": port, "protocol": "TCP"}
                            for port in ingress_ports
                        ]
                    }
                ],
                "egress": [
                    {"ports": [{"port": 443, "protocol": "TCP"}]},
                    {"ports": [{"port": 53, "protocol": "UDP"}]},
                ]
            }
        }
