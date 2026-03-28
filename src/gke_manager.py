"""
GKE Cluster Health & Operations Manager for NMI Payments Platform.
Manages GKE private cluster lifecycle, node health, workload identity, and PCI-DSS controls.
"""
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from enum import Enum


class NodeStatus(Enum):
    READY = "Ready"
    NOT_READY = "NotReady"
    UNKNOWN = "Unknown"
    DISK_PRESSURE = "DiskPressure"
    MEMORY_PRESSURE = "MemoryPressure"


class ClusterHealth(Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    CRITICAL = "critical"


class WorkloadIdentityStatus(Enum):
    BOUND = "bound"
    UNBOUND = "unbound"
    ERROR = "error"


@dataclass
class NodePool:
    name: str
    machine_type: str
    min_nodes: int
    max_nodes: int
    current_nodes: int
    preemptible: bool = False
    workload_identity_enabled: bool = True


@dataclass
class GKENode:
    name: str
    status: NodeStatus
    cpu_usage_percent: float
    memory_usage_percent: float
    disk_usage_percent: float
    pool: str
    zone: str
    labels: Dict[str, str] = field(default_factory=dict)


@dataclass
class KubernetesWorkload:
    name: str
    namespace: str
    replicas_desired: int
    replicas_ready: int
    service_account: str
    workload_identity_annotation: Optional[str] = None
    image: str = ""
    crash_loop_count: int = 0


@dataclass
class GKECluster:
    name: str
    project: str
    region: str
    zone: str
    private_endpoint_only: bool
    workload_identity_enabled: bool
    kms_key: str
    vpc_service_controls: bool
    binary_authorization_enabled: bool
    node_pools: List[NodePool] = field(default_factory=list)
    nodes: List[GKENode] = field(default_factory=list)
    workloads: List[KubernetesWorkload] = field(default_factory=list)
    kubernetes_version: str = "1.29"


class GKEClusterManager:
    """Manages GKE cluster operations for NMI payments platform."""

    def __init__(self, cluster: GKECluster):
        self.cluster = cluster

    def get_cluster_health(self) -> Dict:
        """Compute cluster health score and status."""
        ready_nodes = [n for n in self.cluster.nodes if n.status == NodeStatus.READY]
        total_nodes = len(self.cluster.nodes)
        if total_nodes == 0:
            return {"health": ClusterHealth.CRITICAL.value, "score": 0, "ready_nodes": 0, "total_nodes": 0}

        ready_ratio = len(ready_nodes) / total_nodes
        critical_nodes = [n for n in self.cluster.nodes if n.status in (NodeStatus.NOT_READY, NodeStatus.DISK_PRESSURE, NodeStatus.MEMORY_PRESSURE)]

        if ready_ratio == 1.0 and not critical_nodes:
            health = ClusterHealth.HEALTHY
            score = 100
        elif ready_ratio >= 0.8:
            health = ClusterHealth.DEGRADED
            score = int(ready_ratio * 100)
        else:
            health = ClusterHealth.CRITICAL
            score = int(ready_ratio * 100)

        return {
            "health": health.value,
            "score": score,
            "ready_nodes": len(ready_nodes),
            "total_nodes": total_nodes,
            "critical_nodes": [n.name for n in critical_nodes],
        }

    def check_pci_dss_controls(self) -> Dict:
        """Verify PCI-DSS required GKE controls."""
        findings = []
        passed = []

        if self.cluster.private_endpoint_only:
            passed.append("private_endpoint_only: PASS")
        else:
            findings.append({"rule": "private_endpoint_only", "severity": "CRITICAL", "msg": "Public GKE endpoint must be disabled for PCI-DSS"})

        if self.cluster.workload_identity_enabled:
            passed.append("workload_identity: PASS")
        else:
            findings.append({"rule": "workload_identity", "severity": "HIGH", "msg": "Workload Identity must be enabled — no node SA key files"})

        if self.cluster.kms_key:
            passed.append("kms_encryption: PASS")
        else:
            findings.append({"rule": "kms_encryption", "severity": "CRITICAL", "msg": "Cloud KMS encryption required for PCI-DSS data at rest"})

        if self.cluster.vpc_service_controls:
            passed.append("vpc_service_controls: PASS")
        else:
            findings.append({"rule": "vpc_service_controls", "severity": "HIGH", "msg": "VPC Service Controls required to prevent data exfiltration"})

        if self.cluster.binary_authorization_enabled:
            passed.append("binary_authorization: PASS")
        else:
            findings.append({"rule": "binary_authorization", "severity": "HIGH", "msg": "Binary Authorization required for container provenance"})

        blocking = [f for f in findings if f["severity"] == "CRITICAL"]
        return {
            "compliant": len(blocking) == 0,
            "passed_count": len(passed),
            "findings": findings,
            "blocking_findings": blocking,
            "passed": passed,
        }

    def check_workload_identity(self) -> List[Dict]:
        """Check workload identity binding status for all workloads."""
        results = []
        for wl in self.cluster.workloads:
            if wl.workload_identity_annotation:
                status = WorkloadIdentityStatus.BOUND
                msg = f"Bound to GCP SA: {wl.workload_identity_annotation}"
            else:
                status = WorkloadIdentityStatus.UNBOUND
                msg = "No workload identity annotation — uses node SA (risk)"
            results.append({
                "workload": wl.name,
                "namespace": wl.namespace,
                "status": status.value,
                "message": msg,
                "service_account": wl.service_account,
            })
        return results

    def get_crashlooping_workloads(self) -> List[Dict]:
        """Identify crash-looping workloads."""
        return [
            {
                "name": wl.name,
                "namespace": wl.namespace,
                "crash_loop_count": wl.crash_loop_count,
                "severity": "CRITICAL" if wl.crash_loop_count >= 5 else "WARNING",
            }
            for wl in self.cluster.workloads
            if wl.crash_loop_count > 0
        ]

    def get_hpa_throttled_workloads(self) -> List[Dict]:
        """Identify workloads at max replicas (HPA throttled)."""
        throttled = []
        for wl in self.cluster.workloads:
            # Simulate: if ready replicas < desired by >20%, flag as throttled
            if wl.replicas_desired > 0 and wl.replicas_ready < wl.replicas_desired:
                ratio = wl.replicas_ready / wl.replicas_desired
                if ratio < 0.8:
                    throttled.append({
                        "name": wl.name,
                        "namespace": wl.namespace,
                        "desired": wl.replicas_desired,
                        "ready": wl.replicas_ready,
                        "availability_ratio": ratio,
                    })
        return throttled

    def generate_terraform_hcl(self) -> str:
        """Generate Terraform HCL for GKE private cluster."""
        hcl = f'''resource "google_container_cluster" "{self.cluster.name}" {{
  name     = "{self.cluster.name}"
  project  = "{self.cluster.project}"
  location = "{self.cluster.region}"

  # PCI-DSS: private cluster only
  private_cluster_config {{
    enable_private_nodes    = true
    enable_private_endpoint = {str(self.cluster.private_endpoint_only).lower()}
    master_ipv4_cidr_block  = "172.16.0.0/28"
  }}

  # PCI-DSS: Workload Identity
  workload_identity_config {{
    workload_pool = "{self.cluster.project}.svc.id.goog"
  }}

  # PCI-DSS: KMS encryption
  database_encryption {{
    state    = "ENCRYPTED"
    key_name = "{self.cluster.kms_key}"
  }}

  # PCI-DSS: Binary Authorization
  binary_authorization {{
    evaluation_mode = "PROJECT_SINGLETON_POLICY_ENFORCE"
  }}

  # Remove default node pool
  remove_default_node_pool = true
  initial_node_count       = 1

  min_master_version = "{self.cluster.kubernetes_version}"
}}
'''
        for pool in self.cluster.node_pools:
            hcl += f'''
resource "google_container_node_pool" "{pool.name}" {{
  name       = "{pool.name}"
  cluster    = google_container_cluster.{self.cluster.name}.name
  location   = "{self.cluster.region}"

  autoscaling {{
    min_node_count = {pool.min_nodes}
    max_node_count = {pool.max_nodes}
  }}

  node_config {{
    machine_type = "{pool.machine_type}"
    preemptible  = {str(pool.preemptible).lower()}

    workload_metadata_config {{
      mode = "GKE_METADATA"
    }}

    shielded_instance_config {{
      enable_secure_boot          = true
      enable_integrity_monitoring = true
    }}
  }}
}}
'''
        return hcl

    def get_node_resource_pressure(self) -> List[Dict]:
        """Report nodes under resource pressure."""
        pressured = []
        for node in self.cluster.nodes:
            issues = []
            if node.cpu_usage_percent > 85:
                issues.append(f"CPU {node.cpu_usage_percent}%")
            if node.memory_usage_percent > 90:
                issues.append(f"Memory {node.memory_usage_percent}%")
            if node.disk_usage_percent > 80:
                issues.append(f"Disk {node.disk_usage_percent}%")
            if issues:
                pressured.append({
                    "node": node.name,
                    "zone": node.zone,
                    "pool": node.pool,
                    "issues": issues,
                    "severity": "CRITICAL" if len(issues) >= 2 else "WARNING",
                })
        return pressured
