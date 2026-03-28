"""
Pub/Sub Payment Event Processor for NMI Payments Platform.
Handles payment event routing, state machine, dead-letter queues, and retry policies.
"""
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Callable
from enum import Enum
import json
import time


class PaymentState(Enum):
    SUBMITTED = "submitted"
    AUTHORISED = "authorised"
    CAPTURED = "captured"
    SETTLED = "settled"
    FAILED = "failed"
    REVERSED = "reversed"
    REFUNDED = "refunded"


class PaymentEventType(Enum):
    PAYMENT_SUBMITTED = "payment.submitted"
    PAYMENT_AUTHORISED = "payment.authorised"
    PAYMENT_CAPTURED = "payment.captured"
    PAYMENT_SETTLED = "payment.settled"
    PAYMENT_FAILED = "payment.failed"
    PAYMENT_REVERSED = "payment.reversed"
    PAYMENT_REFUNDED = "payment.refunded"
    FRAUD_FLAGGED = "fraud.flagged"


@dataclass
class PaymentEvent:
    event_id: str
    event_type: PaymentEventType
    payment_id: str
    merchant_id: str
    amount_pence: int
    currency: str
    timestamp: float
    metadata: Dict = field(default_factory=dict)
    retry_count: int = 0
    max_retries: int = 3


@dataclass
class PubSubTopic:
    name: str
    project: str
    message_retention_seconds: int = 604800  # 7 days
    message_ordering: bool = True


@dataclass
class PubSubSubscription:
    name: str
    topic: str
    ack_deadline_seconds: int = 60
    max_delivery_attempts: int = 5
    dead_letter_topic: str = ""
    filter_expression: str = ""
    enable_message_ordering: bool = True


@dataclass
class ProcessingResult:
    event_id: str
    success: bool
    state: PaymentState
    error: Optional[str] = None
    retried: bool = False
    sent_to_dlq: bool = False


class PaymentEventProcessor:
    """Processes payment events from Pub/Sub for NMI's payments platform."""

    # Valid state transitions
    TRANSITIONS = {
        PaymentState.SUBMITTED: [PaymentState.AUTHORISED, PaymentState.FAILED],
        PaymentState.AUTHORISED: [PaymentState.CAPTURED, PaymentState.REVERSED, PaymentState.FAILED],
        PaymentState.CAPTURED: [PaymentState.SETTLED, PaymentState.FAILED],
        PaymentState.SETTLED: [PaymentState.REFUNDED],
        PaymentState.FAILED: [],
        PaymentState.REVERSED: [],
        PaymentState.REFUNDED: [],
    }

    def __init__(self):
        self.processed: List[ProcessingResult] = []
        self.dlq: List[PaymentEvent] = []
        self.payment_states: Dict[str, PaymentState] = {}
        self.metrics = {
            "total_processed": 0,
            "successful": 0,
            "failed": 0,
            "dlq_sent": 0,
            "retried": 0,
        }

    def is_valid_transition(self, current: Optional[PaymentState], event_type: PaymentEventType) -> bool:
        """Check if the state transition is valid."""
        event_to_target = {
            PaymentEventType.PAYMENT_SUBMITTED: PaymentState.SUBMITTED,
            PaymentEventType.PAYMENT_AUTHORISED: PaymentState.AUTHORISED,
            PaymentEventType.PAYMENT_CAPTURED: PaymentState.CAPTURED,
            PaymentEventType.PAYMENT_SETTLED: PaymentState.SETTLED,
            PaymentEventType.PAYMENT_FAILED: PaymentState.FAILED,
            PaymentEventType.PAYMENT_REVERSED: PaymentState.REVERSED,
            PaymentEventType.PAYMENT_REFUNDED: PaymentState.REFUNDED,
        }
        target = event_to_target.get(event_type)
        if target is None:
            return False
        if current is None:
            # First event must be SUBMITTED
            return target == PaymentState.SUBMITTED
        return target in self.TRANSITIONS.get(current, [])

    def process_event(self, event: PaymentEvent) -> ProcessingResult:
        """Process a single payment event with retry logic."""
        self.metrics["total_processed"] += 1
        current_state = self.payment_states.get(event.payment_id)

        # Validate transition
        if not self.is_valid_transition(current_state, event.event_type):
            if event.retry_count < event.max_retries:
                event.retry_count += 1
                self.metrics["retried"] += 1
                result = ProcessingResult(
                    event_id=event.event_id,
                    success=False,
                    state=current_state or PaymentState.FAILED,
                    error=f"Invalid transition from {current_state} via {event.event_type.value}",
                    retried=True,
                )
            else:
                self.dlq.append(event)
                self.metrics["dlq_sent"] += 1
                self.metrics["failed"] += 1
                result = ProcessingResult(
                    event_id=event.event_id,
                    success=False,
                    state=current_state or PaymentState.FAILED,
                    error=f"Max retries exceeded for {event.event_type.value}",
                    sent_to_dlq=True,
                )
            self.processed.append(result)
            return result

        # Apply transition
        state_map = {
            PaymentEventType.PAYMENT_SUBMITTED: PaymentState.SUBMITTED,
            PaymentEventType.PAYMENT_AUTHORISED: PaymentState.AUTHORISED,
            PaymentEventType.PAYMENT_CAPTURED: PaymentState.CAPTURED,
            PaymentEventType.PAYMENT_SETTLED: PaymentState.SETTLED,
            PaymentEventType.PAYMENT_FAILED: PaymentState.FAILED,
            PaymentEventType.PAYMENT_REVERSED: PaymentState.REVERSED,
            PaymentEventType.PAYMENT_REFUNDED: PaymentState.REFUNDED,
        }
        new_state = state_map[event.event_type]
        self.payment_states[event.payment_id] = new_state
        self.metrics["successful"] += 1

        result = ProcessingResult(
            event_id=event.event_id,
            success=True,
            state=new_state,
        )
        self.processed.append(result)
        return result

    def get_success_rate(self) -> float:
        """Calculate payment processing success rate."""
        total = self.metrics["total_processed"]
        if total == 0:
            return 1.0
        return self.metrics["successful"] / total

    def get_dlq_depth(self) -> int:
        """Get current dead-letter queue depth."""
        return len(self.dlq)

    def get_metrics_summary(self) -> Dict:
        return {
            **self.metrics,
            "success_rate": self.get_success_rate(),
            "dlq_depth": self.get_dlq_depth(),
        }


class PubSubTopicManager:
    """Manages Pub/Sub topics and subscriptions for NMI payments."""

    PAYMENT_TOPICS = [
        "nmi-payment-events",
        "nmi-payment-events-dlq",
        "nmi-fraud-events",
        "nmi-settlement-events",
        "nmi-audit-events",
    ]

    def __init__(self, project: str):
        self.project = project
        self.topics: Dict[str, PubSubTopic] = {}
        self.subscriptions: Dict[str, PubSubSubscription] = {}

    def create_payments_topology(self) -> Dict:
        """Create full Pub/Sub topology for NMI payments."""
        # Main payment events topic
        self.topics["nmi-payment-events"] = PubSubTopic(
            name="nmi-payment-events",
            project=self.project,
            message_retention_seconds=604800,
            message_ordering=True,
        )
        # DLQ topic
        self.topics["nmi-payment-events-dlq"] = PubSubTopic(
            name="nmi-payment-events-dlq",
            project=self.project,
            message_retention_seconds=2592000,  # 30 days for DLQ
            message_ordering=False,
        )
        # Fraud events topic
        self.topics["nmi-fraud-events"] = PubSubTopic(
            name="nmi-fraud-events",
            project=self.project,
        )

        # Payment processor subscription
        self.subscriptions["payment-processor-sub"] = PubSubSubscription(
            name="payment-processor-sub",
            topic="nmi-payment-events",
            ack_deadline_seconds=60,
            max_delivery_attempts=5,
            dead_letter_topic="nmi-payment-events-dlq",
            enable_message_ordering=True,
        )
        # Settlement subscription
        self.subscriptions["settlement-processor-sub"] = PubSubSubscription(
            name="settlement-processor-sub",
            topic="nmi-payment-events",
            filter_expression='attributes.event_type = "payment.settled"',
            ack_deadline_seconds=120,
            max_delivery_attempts=3,
            dead_letter_topic="nmi-payment-events-dlq",
        )
        # DLQ subscription
        self.subscriptions["dlq-processor-sub"] = PubSubSubscription(
            name="dlq-processor-sub",
            topic="nmi-payment-events-dlq",
            ack_deadline_seconds=300,
            max_delivery_attempts=1,
        )

        return {
            "topics": list(self.topics.keys()),
            "subscriptions": list(self.subscriptions.keys()),
            "project": self.project,
        }

    def generate_terraform_hcl(self) -> str:
        """Generate Terraform HCL for Pub/Sub resources."""
        hcl = ""
        for name, topic in self.topics.items():
            safe_name = name.replace("-", "_")
            hcl += f'''
resource "google_pubsub_topic" "{safe_name}" {{
  name    = "{name}"
  project = "{topic.project}"

  message_retention_duration = "{topic.message_retention_seconds}s"

  message_storage_policy {{
    allowed_persistence_regions = ["europe-west2"]
  }}
}}
'''
        for name, sub in self.subscriptions.items():
            safe_name = name.replace("-", "_")
            topic_ref = sub.topic.replace("-", "_")
            hcl += f'''
resource "google_pubsub_subscription" "{safe_name}" {{
  name    = "{name}"
  topic   = google_pubsub_topic.{topic_ref}.name
  project = "{self.project}"

  ack_deadline_seconds       = {sub.ack_deadline_seconds}
  enable_message_ordering    = {str(sub.enable_message_ordering).lower()}
  retain_acked_messages      = false
  message_retention_duration = "604800s"
'''
            if sub.dead_letter_topic:
                dlq_ref = sub.dead_letter_topic.replace("-", "_")
                hcl += f'''
  dead_letter_policy {{
    dead_letter_topic     = google_pubsub_topic.{dlq_ref}.id
    max_delivery_attempts = {sub.max_delivery_attempts}
  }}
'''
            if sub.filter_expression:
                hcl += f'  filter = "{sub.filter_expression}"\n'
            hcl += "}\n"
        return hcl

    def validate_topic_configuration(self, topic_name: str) -> Dict:
        """Validate topic configuration against PCI-DSS requirements."""
        topic = self.topics.get(topic_name)
        if not topic:
            return {"valid": False, "error": f"Topic {topic_name} not found"}
        findings = []
        if topic.message_retention_seconds < 86400:  # 1 day minimum
            findings.append("retention too short for audit compliance")
        if topic.message_ordering and topic_name != "nmi-payment-events-dlq":
            pass  # message ordering is good for payments
        return {
            "valid": len(findings) == 0,
            "topic": topic_name,
            "findings": findings,
            "retention_days": topic.message_retention_seconds // 86400,
        }
