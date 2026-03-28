"""
Grafana Dashboard Builder for NMI Payments Platform.
Builds payment transaction dashboards, GKE fleet dashboards, Cloud SQL dashboards.
"""
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from enum import Enum


class PanelType(Enum):
    GRAPH = "timeseries"
    STAT = "stat"
    GAUGE = "gauge"
    TABLE = "table"
    HEATMAP = "heatmap"
    BAR_CHART = "barchart"


@dataclass
class DashboardPanel:
    title: str
    panel_type: PanelType
    metric_expr: str
    unit: str = ""
    thresholds: List[Dict] = field(default_factory=list)
    description: str = ""


@dataclass
class GrafanaDashboard:
    title: str
    uid: str
    description: str
    tags: List[str]
    panels: List[DashboardPanel] = field(default_factory=list)


class NMIDashboardBuilder:
    """Builds Grafana dashboards for NMI's payments platform observability."""

    def build_payment_transactions_dashboard(self) -> GrafanaDashboard:
        """Build payment transaction overview dashboard."""
        panels = [
            DashboardPanel(
                title="Payment Success Rate",
                panel_type=PanelType.GAUGE,
                metric_expr='rate(nmi_payment_transactions_total{status="success"}[5m]) / rate(nmi_payment_transactions_total[5m])',
                unit="percentunit",
                thresholds=[
                    {"value": 0.999, "color": "green"},
                    {"value": 0.99, "color": "yellow"},
                    {"value": 0.95, "color": "red"},
                ],
                description="Payment transaction success rate — SLO target 99.9%",
            ),
            DashboardPanel(
                title="Payment Gateway P99 Latency",
                panel_type=PanelType.GRAPH,
                metric_expr='histogram_quantile(0.99, rate(nmi_payment_gateway_duration_seconds_bucket[5m]))',
                unit="s",
                thresholds=[{"value": 0.5, "color": "red"}],
                description="P99 payment gateway latency — SLO threshold 500ms",
            ),
            DashboardPanel(
                title="Transactions Per Second",
                panel_type=PanelType.STAT,
                metric_expr='rate(nmi_payment_transactions_total[1m])',
                unit="reqps",
                description="Current payment transaction rate",
            ),
            DashboardPanel(
                title="Payment State Distribution",
                panel_type=PanelType.BAR_CHART,
                metric_expr='nmi_payment_state_total',
                unit="short",
                description="Distribution of payment states: submitted/authorised/settled/failed",
            ),
            DashboardPanel(
                title="Fraud Flag Rate",
                panel_type=PanelType.GRAPH,
                metric_expr='rate(nmi_fraud_flags_total[5m])',
                unit="reqps",
                thresholds=[{"value": 10, "color": "red"}],
                description="Rate of fraud-flagged transactions",
            ),
            DashboardPanel(
                title="Payment Error Budget Remaining",
                panel_type=PanelType.GAUGE,
                metric_expr='1 - (1 - rate(nmi_payment_transactions_total{status="success"}[30d])) / 0.001',
                unit="percentunit",
                thresholds=[
                    {"value": 0.5, "color": "green"},
                    {"value": 0.1, "color": "yellow"},
                    {"value": 0.0, "color": "red"},
                ],
                description="30-day error budget remaining (SLO: 99.9%)",
            ),
        ]
        return GrafanaDashboard(
            title="NMI Payment Transactions",
            uid="nmi-payments",
            description="Payment transaction success rates, latency, fraud, and error budgets",
            tags=["payments", "slo", "nmi"],
            panels=panels,
        )

    def build_gke_fleet_dashboard(self) -> GrafanaDashboard:
        """Build GKE fleet health dashboard."""
        panels = [
            DashboardPanel(
                title="Node Ready Ratio",
                panel_type=PanelType.STAT,
                metric_expr='count(kube_node_status_condition{condition="Ready",status="true"}) / count(kube_node_status_condition{condition="Ready"})',
                unit="percentunit",
                thresholds=[{"value": 0.9, "color": "green"}, {"value": 0.8, "color": "red"}],
                description="Ratio of ready nodes",
            ),
            DashboardPanel(
                title="Node CPU Utilisation",
                panel_type=PanelType.HEATMAP,
                metric_expr='1 - avg by(node) (rate(node_cpu_seconds_total{mode="idle"}[5m]))',
                unit="percentunit",
                description="CPU utilisation per node",
            ),
            DashboardPanel(
                title="Node Memory Utilisation",
                panel_type=PanelType.GRAPH,
                metric_expr='1 - (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)',
                unit="percentunit",
                thresholds=[{"value": 0.9, "color": "red"}],
                description="Memory utilisation per node",
            ),
            DashboardPanel(
                title="Pod Restart Rate",
                panel_type=PanelType.GRAPH,
                metric_expr='rate(kube_pod_container_status_restarts_total[15m])',
                unit="short",
                thresholds=[{"value": 0.1, "color": "red"}],
                description="Container restart rate — crash loop detection",
            ),
            DashboardPanel(
                title="Deployment Availability",
                panel_type=PanelType.TABLE,
                metric_expr='kube_deployment_status_replicas_ready / kube_deployment_spec_replicas',
                unit="percentunit",
                description="Deployment replica availability by namespace",
            ),
            DashboardPanel(
                title="PodDisruptionBudget Violations",
                panel_type=PanelType.STAT,
                metric_expr='kube_poddisruptionbudget_status_pod_disruptions_allowed == 0',
                unit="short",
                description="PDBs with zero allowed disruptions — disruption blocked",
            ),
        ]
        return GrafanaDashboard(
            title="NMI GKE Fleet Health",
            uid="nmi-gke-fleet",
            description="GKE cluster node health, pod health, and deployment status",
            tags=["gke", "kubernetes", "nmi"],
            panels=panels,
        )

    def build_cloud_sql_dashboard(self) -> GrafanaDashboard:
        """Build Cloud SQL performance dashboard."""
        panels = [
            DashboardPanel(
                title="Database Connections",
                panel_type=PanelType.GRAPH,
                metric_expr='cloudsql_database_postgresql_num_backends',
                unit="short",
                thresholds=[{"value": 85, "color": "red"}],
                description="Active database connections",
            ),
            DashboardPanel(
                title="Query Operations/s",
                panel_type=PanelType.GRAPH,
                metric_expr='rate(cloudsql_database_postgresql_insights_aggregate_execution_count[5m])',
                unit="ops",
                description="Query execution rate",
            ),
            DashboardPanel(
                title="Replication Lag",
                panel_type=PanelType.GRAPH,
                metric_expr='cloudsql_replication_replica_lag_seconds',
                unit="s",
                thresholds=[{"value": 30, "color": "red"}],
                description="Read replica replication lag",
            ),
            DashboardPanel(
                title="Disk Utilisation",
                panel_type=PanelType.GAUGE,
                metric_expr='cloudsql_database_disk_utilization',
                unit="percentunit",
                thresholds=[{"value": 0.85, "color": "red"}],
                description="Cloud SQL disk space utilisation",
            ),
            DashboardPanel(
                title="Memory Utilisation",
                panel_type=PanelType.GAUGE,
                metric_expr='cloudsql_database_memory_utilization',
                unit="percentunit",
                thresholds=[{"value": 0.9, "color": "red"}],
                description="Cloud SQL memory utilisation",
            ),
        ]
        return GrafanaDashboard(
            title="NMI Cloud SQL Payments DB",
            uid="nmi-cloud-sql",
            description="Cloud SQL PostgreSQL performance, replication, and capacity for payments database",
            tags=["cloud-sql", "postgresql", "nmi", "payments"],
            panels=panels,
        )

    def build_pubsub_dashboard(self) -> GrafanaDashboard:
        """Build Pub/Sub payment event pipeline dashboard."""
        panels = [
            DashboardPanel(
                title="Payment Event Backlog",
                panel_type=PanelType.GRAPH,
                metric_expr='pubsub_subscription_num_undelivered_messages{subscription="payment-processor-sub"}',
                unit="short",
                thresholds=[{"value": 1000, "color": "red"}],
                description="Unprocessed payment events in queue",
            ),
            DashboardPanel(
                title="DLQ Message Depth",
                panel_type=PanelType.STAT,
                metric_expr='pubsub_subscription_num_undelivered_messages{subscription="dlq-processor-sub"}',
                unit="short",
                thresholds=[{"value": 100, "color": "red"}],
                description="Dead-letter queue depth — failed payment events",
            ),
            DashboardPanel(
                title="Message Processing Rate",
                panel_type=PanelType.GRAPH,
                metric_expr='rate(pubsub_subscription_pull_request_count[1m])',
                unit="reqps",
                description="Rate of messages being pulled/processed",
            ),
            DashboardPanel(
                title="Oldest Unacked Message Age",
                panel_type=PanelType.GAUGE,
                metric_expr='pubsub_subscription_oldest_unacked_message_age_seconds{subscription="payment-processor-sub"}',
                unit="s",
                thresholds=[{"value": 300, "color": "red"}],
                description="Age of oldest unacked payment event",
            ),
        ]
        return GrafanaDashboard(
            title="NMI Pub/Sub Payment Pipeline",
            uid="nmi-pubsub",
            description="Pub/Sub payment event pipeline metrics, backlog, and DLQ monitoring",
            tags=["pubsub", "payments", "nmi"],
            panels=panels,
        )

    def get_all_dashboards(self) -> List[GrafanaDashboard]:
        """Return all NMI dashboards."""
        return [
            self.build_payment_transactions_dashboard(),
            self.build_gke_fleet_dashboard(),
            self.build_cloud_sql_dashboard(),
            self.build_pubsub_dashboard(),
        ]

    def count_total_panels(self) -> int:
        """Count total panels across all dashboards."""
        return sum(len(d.panels) for d in self.get_all_dashboards())
