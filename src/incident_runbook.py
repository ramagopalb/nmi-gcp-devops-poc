"""
Incident Response Automation for NMI Payments Platform.
P1-P4 runbooks, SLO breach triage, auto-escalation.
"""
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from enum import Enum


class Severity(Enum):
    P1 = "P1"  # Payment gateway down / >5% transaction failure
    P2 = "P2"  # Degraded payment success rate / high latency
    P3 = "P3"  # Non-critical service degradation
    P4 = "P4"  # Minor issue / informational


class IncidentState(Enum):
    TRIGGERED = "TRIGGERED"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    INVESTIGATING = "INVESTIGATING"
    MITIGATING = "MITIGATING"
    RESOLVED = "RESOLVED"
    POSTMORTEM = "POSTMORTEM"


@dataclass
class RunbookStep:
    order: int
    title: str
    command: str
    expected_outcome: str
    escalate_if_fails: bool = False
    timeout_seconds: int = 60


@dataclass
class Incident:
    incident_id: str
    title: str
    severity: Severity
    state: IncidentState
    affected_service: str
    trigger_alert: str
    on_call_engineer: str
    created_at: float
    resolved_at: Optional[float] = None
    root_cause: str = ""
    runbook_steps_completed: List[str] = field(default_factory=list)


class IncidentRunbookExecutor:
    """Executes incident response runbooks for NMI payments platform."""

    RUNBOOKS = {
        "payment_gateway_down": [
            RunbookStep(1, "Verify alert", "kubectl get pods -n payments -l app=payment-gateway", "Pods in Running state", True),
            RunbookStep(2, "Check recent deployments", "kubectl rollout history deployment/payment-gateway -n payments", "Identify if recent rollout caused issue"),
            RunbookStep(3, "Check GKE node health", "kubectl get nodes -o wide", "All nodes Ready"),
            RunbookStep(4, "Check Cloud SQL connectivity", "kubectl exec -n payments deploy/payment-gateway -- pg_isready -h $DB_HOST", "pg_isready returns 0", True),
            RunbookStep(5, "Rollback if recent deploy", "kubectl rollout undo deployment/payment-gateway -n payments", "Rollout undone"),
            RunbookStep(6, "Verify Pub/Sub not backing up", "gcloud pubsub subscriptions describe payment-processor-sub --format='value(numUndeliveredMessages)'", "< 1000 messages"),
            RunbookStep(7, "Notify stakeholders", "Send P1 update to #payments-incidents Slack", "Stakeholders informed"),
        ],
        "payment_success_rate_low": [
            RunbookStep(1, "Check error rate breakdown", "kubectl exec -n monitoring deploy/prometheus -- curl -s 'localhost:9090/api/v1/query?query=rate(nmi_payment_transactions_total{status=\"error\"}[5m])'", "Identify error categories"),
            RunbookStep(2, "Check payment processor logs", "kubectl logs -n payments -l app=payment-processor --since=10m | grep ERROR", "Identify error patterns"),
            RunbookStep(3, "Check Cloud SQL replication lag", "gcloud sql instances describe nmi-payments-db --format='value(replicaNames)'", "Replication lag < 30s"),
            RunbookStep(4, "Check Pub/Sub backlog", "gcloud pubsub subscriptions describe payment-processor-sub", "Backlog < 1000 messages"),
            RunbookStep(5, "Check for fraud spike", "kubectl exec -n monitoring deploy/prometheus -- curl -s 'localhost:9090/api/v1/query?query=rate(nmi_fraud_flags_total[5m])'", "Fraud rate normal"),
            RunbookStep(6, "Scale up payment processors if backlog high", "kubectl scale deployment/payment-processor --replicas=10 -n payments", "Backlog draining"),
        ],
        "gke_node_not_ready": [
            RunbookStep(1, "Identify not-ready nodes", "kubectl get nodes | grep NotReady", "List of affected nodes"),
            RunbookStep(2, "Describe not-ready node", "kubectl describe node $NODE_NAME", "Identify condition causing NotReady"),
            RunbookStep(3, "Check node disk pressure", "kubectl get node $NODE_NAME -o jsonpath='{.status.conditions[?(@.type==\"DiskPressure\")].status}'", "DiskPressure = False"),
            RunbookStep(4, "Check pods on affected node", "kubectl get pods --all-namespaces --field-selector spec.nodeName=$NODE_NAME", "Pods rescheduled"),
            RunbookStep(5, "Cordon and drain if unrecoverable", "kubectl cordon $NODE_NAME && kubectl drain $NODE_NAME --ignore-daemonsets --delete-emptydir-data", "Node drained"),
            RunbookStep(6, "Trigger node pool instance refresh", "gcloud container clusters upgrade nmi-payments-cluster --node-pool=payments-pool --cluster-version=$(gcloud container get-server-config --format='value(defaultClusterVersion)')", "New node provisioned"),
        ],
        "cloud_sql_replication_lag": [
            RunbookStep(1, "Check replication lag", "gcloud sql instances describe nmi-payments-replica --format='value(replicationConfiguration.replicaLag)'", "Lag value in seconds"),
            RunbookStep(2, "Check replica status", "gcloud sql instances describe nmi-payments-replica --format='value(state)'", "RUNNABLE"),
            RunbookStep(3, "Check network connectivity", "gcloud sql instances describe nmi-payments-db --format='value(ipAddresses)'", "Primary IP accessible"),
            RunbookStep(4, "Check write load on primary", "kubectl exec -n payments deploy/payment-gateway -- psql -c 'SELECT * FROM pg_stat_replication;'", "Replication state = streaming"),
            RunbookStep(5, "Consider read traffic failover", "kubectl set env deployment/payment-api DB_REPLICA_HOST=$REPLICA_HOST -n payments", "Read traffic using replica"),
        ],
    }

    def __init__(self):
        self.incidents: List[Incident] = []
        self.active_incidents: Dict[str, Incident] = {}

    def create_incident(self, title: str, severity: Severity, service: str, alert: str,
                        on_call: str) -> Incident:
        """Create a new incident."""
        incident_id = f"INC-{len(self.incidents) + 1:04d}"
        incident = Incident(
            incident_id=incident_id,
            title=title,
            severity=severity,
            state=IncidentState.TRIGGERED,
            affected_service=service,
            trigger_alert=alert,
            on_call_engineer=on_call,
            created_at=1711584000.0,
        )
        self.incidents.append(incident)
        self.active_incidents[incident_id] = incident
        return incident

    def get_runbook(self, runbook_name: str) -> List[RunbookStep]:
        """Get runbook steps for a given incident type."""
        return self.RUNBOOKS.get(runbook_name, [])

    def execute_runbook_step(self, incident: Incident, step: RunbookStep, dry_run: bool = True) -> Dict:
        """Execute a runbook step (dry_run mode for POC)."""
        incident.state = IncidentState.INVESTIGATING
        incident.runbook_steps_completed.append(step.title)

        result = {
            "incident_id": incident.incident_id,
            "step": step.order,
            "title": step.title,
            "command": step.command if dry_run else f"EXECUTED: {step.command}",
            "dry_run": dry_run,
            "simulated_outcome": step.expected_outcome,
            "success": True,
        }
        return result

    def resolve_incident(self, incident_id: str, root_cause: str) -> Dict:
        """Mark an incident as resolved."""
        incident = self.active_incidents.get(incident_id)
        if not incident:
            return {"error": f"Incident {incident_id} not found"}

        incident.state = IncidentState.RESOLVED
        incident.root_cause = root_cause
        incident.resolved_at = 1711588000.0

        mttr = (incident.resolved_at - incident.created_at) / 60  # minutes

        del self.active_incidents[incident_id]
        return {
            "incident_id": incident_id,
            "resolved": True,
            "mttr_minutes": mttr,
            "root_cause": root_cause,
            "steps_completed": incident.runbook_steps_completed,
        }

    def generate_pir(self, incident: Incident) -> Dict:
        """Generate Post-Incident Review report."""
        return {
            "incident_id": incident.incident_id,
            "title": incident.title,
            "severity": incident.severity.value,
            "timeline": {
                "triggered": incident.created_at,
                "resolved": incident.resolved_at or 0,
                "duration_minutes": (incident.resolved_at or 0 - incident.created_at) / 60 if incident.resolved_at else None,
            },
            "root_cause": incident.root_cause,
            "affected_service": incident.affected_service,
            "steps_completed": incident.runbook_steps_completed,
            "action_items": [
                f"Add runbook automation for {incident.trigger_alert}",
                "Review monitoring coverage for early detection",
                "Update SLO error budget tracking",
            ],
        }

    def get_on_call_rotation(self) -> List[Dict]:
        """Return the on-call rotation schedule."""
        return [
            {"week": 1, "primary": "alice", "secondary": "bob", "escalation": "platform-lead"},
            {"week": 2, "primary": "bob", "secondary": "charlie", "escalation": "platform-lead"},
            {"week": 3, "primary": "charlie", "secondary": "alice", "escalation": "platform-lead"},
            {"week": 4, "primary": "ram", "secondary": "bob", "escalation": "cto"},
        ]

    def get_severity_response_matrix(self) -> Dict:
        """Return the P1-P4 response matrix."""
        return {
            Severity.P1.value: {
                "description": "Payment gateway down or >5% transaction failure",
                "response_time_minutes": 5,
                "escalation_minutes": 15,
                "stakeholders": ["CTO", "VP Engineering", "Payments Team"],
                "communication": "Immediate Slack + PagerDuty + Status Page update",
            },
            Severity.P2.value: {
                "description": "Degraded payment success rate or high latency SLO breach",
                "response_time_minutes": 15,
                "escalation_minutes": 30,
                "stakeholders": ["Engineering Lead", "Payments Team"],
                "communication": "Slack + PagerDuty",
            },
            Severity.P3.value: {
                "description": "Non-critical degradation, partial service impact",
                "response_time_minutes": 60,
                "escalation_minutes": 120,
                "stakeholders": ["On-call engineer"],
                "communication": "Slack",
            },
            Severity.P4.value: {
                "description": "Minor issue, no customer impact",
                "response_time_minutes": 240,
                "escalation_minutes": None,
                "stakeholders": ["On-call engineer"],
                "communication": "Ticket",
            },
        }
