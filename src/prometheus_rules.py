"""
Prometheus Alert Rules Generator for NMI Payments Platform.
Payment SLOs, GKE alerts, Cloud SQL alerts, Pub/Sub backlog alerts.
"""
from dataclasses import dataclass, field
from typing import List, Dict
from enum import Enum


class AlertSeverity(Enum):
    CRITICAL = "critical"
    WARNING = "warning"
    PAGE = "page"
    TICKET = "ticket"
    INFO = "info"


@dataclass
class PrometheusRule:
    alert: str
    expr: str
    for_duration: str
    severity: AlertSeverity
    summary: str
    description: str
    labels: Dict[str, str] = field(default_factory=dict)
    annotations: Dict[str, str] = field(default_factory=dict)


@dataclass
class SLO:
    name: str
    description: str
    target: float  # e.g., 0.999 for 99.9%
    window_days: int = 30
    error_budget_minutes: float = 0.0


class PrometheusRulesGenerator:
    """Generates Prometheus alert rules for NMI payments observability."""

    # NMI Payment SLOs
    PAYMENT_SLOS = [
        SLO("nmi_payment_success_rate", "Payment transaction success rate", 0.999),
        SLO("nmi_gateway_latency_p99", "Payment gateway P99 latency < 500ms", 0.995),
        SLO("nmi_api_error_rate", "NMI API error rate < 0.5%", 0.995),
    ]

    # Multi-window burn-rate alert windows (Google SRE Workbook)
    BURN_RATE_WINDOWS = [
        {"window": "1h",   "long_window": "5h",   "factor": 14.4, "severity": AlertSeverity.PAGE,   "label": "p1_page"},
        {"window": "6h",   "long_window": "30h",  "factor": 6.0,  "severity": AlertSeverity.TICKET, "label": "p2_ticket"},
        {"window": "24h",  "long_window": "120h", "factor": 3.0,  "severity": AlertSeverity.WARNING, "label": "p3_warning"},
    ]

    def generate_payment_slo_rules(self) -> List[PrometheusRule]:
        """Generate multi-window SLO burn-rate alert rules for payment SLOs."""
        rules = []
        for slo in self.PAYMENT_SLOS:
            error_rate = 1 - slo.target
            for window in self.BURN_RATE_WINDOWS:
                rules.append(PrometheusRule(
                    alert=f"NMISLOBurnRate_{slo.name}_{window['label']}",
                    expr=(
                        f"("
                        f"  (1 - rate({slo.name}_success_total[{window['window']}])) / {error_rate:.4f} > {window['factor']}"
                        f"  and"
                        f"  (1 - rate({slo.name}_success_total[{window['long_window']}])) / {error_rate:.4f} > {window['factor']}"
                        f")"
                    ),
                    for_duration="2m",
                    severity=window["severity"],
                    summary=f"NMI SLO burn rate high: {slo.name}",
                    description=(
                        f"Payment SLO '{slo.description}' is burning error budget at "
                        f"{window['factor']}x rate over {window['window']}/{window['long_window']} windows. "
                        f"SLO target: {slo.target*100:.1f}%."
                    ),
                    labels={"slo": slo.name, "window": window["label"], "team": "payments-platform"},
                ))
        return rules

    def generate_payment_alerts(self) -> List[PrometheusRule]:
        """Generate payment-specific Prometheus alert rules."""
        return [
            PrometheusRule(
                alert="NMIPaymentSuccessRateLow",
                expr='rate(nmi_payment_transactions_total{status="success"}[5m]) / rate(nmi_payment_transactions_total[5m]) < 0.95',
                for_duration="5m",
                severity=AlertSeverity.CRITICAL,
                summary="NMI payment success rate below 95%",
                description="Payment success rate has dropped below 95% for 5 minutes. Immediate investigation required.",
                labels={"team": "payments-platform", "runbook": "payment-failure-runbook"},
            ),
            PrometheusRule(
                alert="NMIPaymentGatewayLatencyHigh",
                expr='histogram_quantile(0.99, rate(nmi_payment_gateway_duration_seconds_bucket[5m])) > 0.5',
                for_duration="5m",
                severity=AlertSeverity.WARNING,
                summary="NMI payment gateway P99 latency above 500ms",
                description="Payment gateway P99 latency is {{ $value | humanizeDuration }} — SLO threshold is 500ms.",
                labels={"team": "payments-platform"},
            ),
            PrometheusRule(
                alert="NMIPaymentGatewayDown",
                expr='up{job="nmi-payment-gateway"} == 0',
                for_duration="1m",
                severity=AlertSeverity.CRITICAL,
                summary="NMI payment gateway is down",
                description="Payment gateway instance {{ $labels.instance }} is unreachable.",
                labels={"team": "payments-platform", "pagerduty": "P1"},
            ),
            PrometheusRule(
                alert="NMIFraudFlagRateHigh",
                expr='rate(nmi_fraud_flags_total[10m]) > 10',
                for_duration="5m",
                severity=AlertSeverity.WARNING,
                summary="High fraud flag rate detected",
                description="Fraud flags at {{ $value }}/s — may indicate attack or detection system issue.",
                labels={"team": "payments-security"},
            ),
        ]

    def generate_gke_alerts(self) -> List[PrometheusRule]:
        """Generate GKE cluster Prometheus alert rules."""
        return [
            PrometheusRule(
                alert="GKENodeNotReady",
                expr='kube_node_status_condition{condition="Ready",status="true"} == 0',
                for_duration="5m",
                severity=AlertSeverity.CRITICAL,
                summary="GKE node {{ $labels.node }} not ready",
                description="GKE node {{ $labels.node }} has been NotReady for 5 minutes.",
                labels={"team": "platform"},
            ),
            PrometheusRule(
                alert="GKEPodCrashLooping",
                expr='rate(kube_pod_container_status_restarts_total[15m]) > 0.1',
                for_duration="5m",
                severity=AlertSeverity.WARNING,
                summary="Pod {{ $labels.namespace }}/{{ $labels.pod }} crash looping",
                description="Pod restart rate is {{ $value | humanize }}/s in namespace {{ $labels.namespace }}.",
                labels={"team": "platform"},
            ),
            PrometheusRule(
                alert="GKENodeHighCPU",
                expr='(1 - avg by(node) (rate(node_cpu_seconds_total{mode="idle"}[5m]))) > 0.85',
                for_duration="10m",
                severity=AlertSeverity.WARNING,
                summary="GKE node {{ $labels.node }} CPU above 85%",
                description="Node CPU utilisation is {{ $value | humanizePercentage }}.",
                labels={"team": "platform"},
            ),
            PrometheusRule(
                alert="GKENodeHighMemory",
                expr='(1 - (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)) > 0.90',
                for_duration="10m",
                severity=AlertSeverity.WARNING,
                summary="GKE node memory above 90%",
                description="Node memory utilisation is {{ $value | humanizePercentage }}.",
                labels={"team": "platform"},
            ),
            PrometheusRule(
                alert="GKEDeploymentReplicasMismatch",
                expr='kube_deployment_status_replicas_ready < kube_deployment_spec_replicas',
                for_duration="5m",
                severity=AlertSeverity.WARNING,
                summary="Deployment {{ $labels.namespace }}/{{ $labels.deployment }} replicas mismatch",
                description="{{ $labels.deployment }} has {{ $value }} ready replicas, expected {{ printf `%v` $value }}.",
                labels={"team": "platform"},
            ),
        ]

    def generate_cloud_sql_alerts(self) -> List[PrometheusRule]:
        """Generate Cloud SQL alert rules."""
        return [
            PrometheusRule(
                alert="CloudSQLReplicationLagHigh",
                expr='cloudsql_replication_replica_lag_seconds > 30',
                for_duration="5m",
                severity=AlertSeverity.WARNING,
                summary="Cloud SQL replication lag above 30s",
                description="Cloud SQL replica {{ $labels.database_id }} replication lag is {{ $value | humanizeDuration }}.",
                labels={"team": "platform", "database": "payments"},
            ),
            PrometheusRule(
                alert="CloudSQLConnectionsNearLimit",
                expr='cloudsql_database_postgresql_num_backends / cloudsql_database_postgresql_max_connections > 0.85',
                for_duration="5m",
                severity=AlertSeverity.WARNING,
                summary="Cloud SQL connections near limit",
                description="Cloud SQL instance {{ $labels.database_id }} is at {{ $value | humanizePercentage }} connection capacity.",
                labels={"team": "platform"},
            ),
            PrometheusRule(
                alert="CloudSQLDiskUsageHigh",
                expr='cloudsql_database_disk_utilization > 0.85',
                for_duration="10m",
                severity=AlertSeverity.WARNING,
                summary="Cloud SQL disk usage above 85%",
                description="Cloud SQL disk utilisation is {{ $value | humanizePercentage }} — expand storage.",
                labels={"team": "platform"},
            ),
        ]

    def generate_pubsub_alerts(self) -> List[PrometheusRule]:
        """Generate Pub/Sub backlog and processing alert rules."""
        return [
            PrometheusRule(
                alert="PubSubPaymentBacklogHigh",
                expr='pubsub_subscription_num_undelivered_messages{subscription="payment-processor-sub"} > 1000',
                for_duration="5m",
                severity=AlertSeverity.WARNING,
                summary="Payment Pub/Sub backlog above 1000 messages",
                description="Payment event backlog has {{ $value }} undelivered messages.",
                labels={"team": "payments-platform"},
            ),
            PrometheusRule(
                alert="PubSubDLQDepthHigh",
                expr='pubsub_subscription_num_undelivered_messages{subscription="dlq-processor-sub"} > 100',
                for_duration="2m",
                severity=AlertSeverity.CRITICAL,
                summary="Payment DLQ has {{ $value }} messages",
                description="Dead-letter queue has {{ $value }} unprocessable payment messages — requires investigation.",
                labels={"team": "payments-platform", "runbook": "dlq-runbook"},
            ),
            PrometheusRule(
                alert="PubSubOldestMessageAge",
                expr='pubsub_subscription_oldest_unacked_message_age_seconds{subscription="payment-processor-sub"} > 300',
                for_duration="5m",
                severity=AlertSeverity.WARNING,
                summary="Payment Pub/Sub oldest message age above 5 minutes",
                description="Oldest unacked payment message is {{ $value | humanizeDuration }} old.",
                labels={"team": "payments-platform"},
            ),
        ]

    def generate_all_rules(self) -> Dict:
        """Generate all Prometheus rules grouped by category."""
        return {
            "payment_slo_burn_rate": self.generate_payment_slo_rules(),
            "payment_alerts": self.generate_payment_alerts(),
            "gke_alerts": self.generate_gke_alerts(),
            "cloud_sql_alerts": self.generate_cloud_sql_alerts(),
            "pubsub_alerts": self.generate_pubsub_alerts(),
        }

    def render_yaml(self, rules: List[PrometheusRule]) -> str:
        """Render rules as Prometheus YAML format."""
        lines = ["groups:", "- name: nmi_payments_platform", "  rules:"]
        for rule in rules:
            lines.append(f"  - alert: {rule.alert}")
            lines.append(f"    expr: >")
            lines.append(f"      {rule.expr}")
            lines.append(f"    for: {rule.for_duration}")
            lines.append(f"    labels:")
            lines.append(f"      severity: {rule.severity.value}")
            for k, v in rule.labels.items():
                lines.append(f"      {k}: {v}")
            lines.append(f"    annotations:")
            lines.append(f"      summary: \"{rule.summary}\"")
            lines.append(f"      description: \"{rule.description}\"")
        return "\n".join(lines)

    def count_all_rules(self) -> int:
        """Count total rules generated."""
        all_rules = self.generate_all_rules()
        return sum(len(v) for v in all_rules.values())
