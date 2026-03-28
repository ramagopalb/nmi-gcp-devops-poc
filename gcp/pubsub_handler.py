"""
GCP Pub/Sub handler for NMI payment transaction pipelines.
Handles topic/subscription management, message publishing, dead-letter
configuration, and consumer lag monitoring for PCI-DSS compliant messaging.
"""

import json
import logging
import time
import hashlib
import base64
from dataclasses import dataclass, field
from typing import Optional, Callable
from enum import Enum

logger = logging.getLogger(__name__)


class MessageStatus(Enum):
    PUBLISHED = "PUBLISHED"
    DELIVERED = "DELIVERED"
    FAILED = "FAILED"
    DEAD_LETTERED = "DEAD_LETTERED"
    PENDING = "PENDING"


class DeliveryAttemptResult(Enum):
    SUCCESS = "SUCCESS"
    NACK = "NACK"
    DEADLINE_EXCEEDED = "DEADLINE_EXCEEDED"


@dataclass
class PubSubMessage:
    """A Pub/Sub message for payment transaction events."""
    data: dict
    attributes: dict = field(default_factory=dict)
    message_id: Optional[str] = None
    publish_time: Optional[float] = None
    delivery_attempt: int = 0
    status: MessageStatus = MessageStatus.PENDING

    def encode(self) -> str:
        """Base64-encode the message data for Pub/Sub wire format."""
        return base64.b64encode(json.dumps(self.data).encode()).decode()

    @classmethod
    def decode(cls, encoded_data: str, attributes: dict = None) -> "PubSubMessage":
        """Decode a Pub/Sub message from wire format."""
        data = json.loads(base64.b64decode(encoded_data).decode())
        return cls(data=data, attributes=attributes or {})

    def get_fingerprint(self) -> str:
        """Generate a message fingerprint for deduplication."""
        content = json.dumps(self.data, sort_keys=True)
        return hashlib.sha256(content.encode()).hexdigest()[:16]


@dataclass
class DeadLetterConfig:
    """Dead-letter topic configuration for failed payment messages."""
    dead_letter_topic: str
    max_delivery_attempts: int = 5

    def validate(self) -> list:
        errors = []
        if not self.dead_letter_topic:
            errors.append("dead_letter_topic is required")
        if not (1 <= self.max_delivery_attempts <= 100):
            errors.append("max_delivery_attempts must be between 1 and 100")
        return errors


@dataclass
class RetryPolicy:
    """Retry policy for Pub/Sub subscriptions."""
    minimum_backoff_seconds: int = 10
    maximum_backoff_seconds: int = 600

    def validate(self) -> list:
        errors = []
        if self.minimum_backoff_seconds < 0:
            errors.append("minimum_backoff_seconds must be >= 0")
        if self.maximum_backoff_seconds < self.minimum_backoff_seconds:
            errors.append("maximum_backoff_seconds must be >= minimum_backoff_seconds")
        if self.maximum_backoff_seconds > 600:
            errors.append("maximum_backoff_seconds cannot exceed 600")
        return errors

    def get_backoff(self, attempt: int) -> float:
        """Exponential backoff calculation."""
        backoff = self.minimum_backoff_seconds * (2 ** (attempt - 1))
        return min(backoff, self.maximum_backoff_seconds)


@dataclass
class SubscriptionConfig:
    """Pub/Sub subscription configuration."""
    subscription_name: str
    topic_name: str
    ack_deadline_seconds: int = 30
    message_retention_seconds: int = 86400  # 24 hours
    dead_letter: Optional[DeadLetterConfig] = None
    retry_policy: Optional[RetryPolicy] = None
    filter_expression: Optional[str] = None
    enable_exactly_once: bool = False

    def validate(self) -> list:
        errors = []
        if not self.subscription_name:
            errors.append("subscription_name is required")
        if not self.topic_name:
            errors.append("topic_name is required")
        if not (10 <= self.ack_deadline_seconds <= 600):
            errors.append("ack_deadline_seconds must be between 10 and 600")
        if self.dead_letter:
            errors.extend(self.dead_letter.validate())
        if self.retry_policy:
            errors.extend(self.retry_policy.validate())
        return errors


@dataclass
class TopicConfig:
    """Pub/Sub topic configuration."""
    topic_name: str
    project_id: str
    labels: dict = field(default_factory=dict)
    message_retention_seconds: Optional[int] = None
    kms_key_name: Optional[str] = None

    def validate(self) -> list:
        errors = []
        if not self.topic_name:
            errors.append("topic_name is required")
        if not self.project_id:
            errors.append("project_id is required")
        return errors

    def full_resource_name(self) -> str:
        return f"projects/{self.project_id}/topics/{self.topic_name}"


class ConsumerLagMonitor:
    """
    Monitors Pub/Sub consumer lag for payment pipeline SLO alerting.
    Tracks oldest unacked message age and subscription backlog counts.
    """

    def __init__(self, alert_threshold_seconds: int = 60):
        self.alert_threshold_seconds = alert_threshold_seconds
        self._lag_data: dict[str, dict] = {}

    def record_lag(self, subscription: str, oldest_unacked_age_seconds: float,
                   backlog_count: int) -> None:
        """Record current consumer lag metrics."""
        self._lag_data[subscription] = {
            "oldest_unacked_age_seconds": oldest_unacked_age_seconds,
            "backlog_count": backlog_count,
            "recorded_at": time.time(),
        }

    def get_lag(self, subscription: str) -> Optional[dict]:
        """Get current lag metrics for a subscription."""
        return self._lag_data.get(subscription)

    def check_slo(self, subscription: str) -> dict:
        """Check if subscription meets SLO requirements."""
        lag = self.get_lag(subscription)
        if lag is None:
            return {"subscription": subscription, "status": "NO_DATA"}

        exceeds_threshold = lag["oldest_unacked_age_seconds"] > self.alert_threshold_seconds
        return {
            "subscription": subscription,
            "oldest_unacked_age_seconds": lag["oldest_unacked_age_seconds"],
            "backlog_count": lag["backlog_count"],
            "threshold_seconds": self.alert_threshold_seconds,
            "slo_breach": exceeds_threshold,
            "status": "BREACH" if exceeds_threshold else "OK",
        }

    def list_breaches(self) -> list:
        """List all subscriptions currently breaching SLO."""
        return [
            self.check_slo(sub)
            for sub in self._lag_data
            if self.check_slo(sub).get("slo_breach")
        ]


class PubSubHandler:
    """
    Manages GCP Pub/Sub resources for NMI payment transaction pipelines.
    Handles topic/subscription lifecycle, message publishing/consuming,
    dead-letter routing, retry policies, and consumer lag monitoring.
    """

    def __init__(self, project_id: str, dry_run: bool = True):
        self.project_id = project_id
        self.dry_run = dry_run
        self._topics: dict[str, dict] = {}
        self._subscriptions: dict[str, dict] = {}
        self._message_store: dict[str, list] = {}
        self._dead_letter_store: dict[str, list] = {}
        self.lag_monitor = ConsumerLagMonitor()
        logger.info(
            "PubSubHandler initialized",
            extra={"project_id": project_id, "dry_run": dry_run}
        )

    def create_topic(self, config: TopicConfig) -> dict:
        """Create a Pub/Sub topic with optional KMS encryption."""
        errors = config.validate()
        if errors:
            raise ValueError(f"Invalid topic config: {errors}")

        if config.topic_name in self._topics:
            raise ValueError(f"Topic '{config.topic_name}' already exists")

        topic_resource = {
            "name": config.full_resource_name(),
            "labels": config.labels,
            "kmsKeyName": config.kms_key_name,
            "messageRetentionDuration": (
                f"{config.message_retention_seconds}s"
                if config.message_retention_seconds else None
            ),
        }
        self._topics[config.topic_name] = topic_resource
        self._message_store[config.topic_name] = []

        logger.info(f"Topic created: {config.topic_name}")
        return {"operation": "CREATE_TOPIC", "topic": topic_resource}

    def delete_topic(self, topic_name: str) -> dict:
        """Delete a Pub/Sub topic."""
        if topic_name not in self._topics:
            raise KeyError(f"Topic '{topic_name}' not found")
        del self._topics[topic_name]
        self._message_store.pop(topic_name, None)
        return {"operation": "DELETE_TOPIC", "topic_name": topic_name}

    def create_subscription(self, config: SubscriptionConfig) -> dict:
        """Create a Pub/Sub subscription with dead-letter and retry policy."""
        errors = config.validate()
        if errors:
            raise ValueError(f"Invalid subscription config: {errors}")

        if config.topic_name not in self._topics:
            raise KeyError(f"Topic '{config.topic_name}' not found")

        if config.subscription_name in self._subscriptions:
            raise ValueError(
                f"Subscription '{config.subscription_name}' already exists"
            )

        sub_resource = {
            "name": f"projects/{self.project_id}/subscriptions/{config.subscription_name}",
            "topic": f"projects/{self.project_id}/topics/{config.topic_name}",
            "ackDeadlineSeconds": config.ack_deadline_seconds,
            "messageRetentionDuration": f"{config.message_retention_seconds}s",
            "enableExactlyOnceDelivery": config.enable_exactly_once,
            "filter": config.filter_expression,
            "deadLetterPolicy": (
                {
                    "deadLetterTopic": (
                        f"projects/{self.project_id}/topics/"
                        f"{config.dead_letter.dead_letter_topic}"
                    ),
                    "maxDeliveryAttempts": config.dead_letter.max_delivery_attempts,
                }
                if config.dead_letter else None
            ),
            "retryPolicy": (
                {
                    "minimumBackoff": f"{config.retry_policy.minimum_backoff_seconds}s",
                    "maximumBackoff": f"{config.retry_policy.maximum_backoff_seconds}s",
                }
                if config.retry_policy else None
            ),
        }
        self._subscriptions[config.subscription_name] = sub_resource
        logger.info(f"Subscription created: {config.subscription_name}")
        return {"operation": "CREATE_SUBSCRIPTION", "subscription": sub_resource}

    def publish_message(self, topic_name: str, message: PubSubMessage) -> dict:
        """Publish a payment event message to a Pub/Sub topic."""
        if topic_name not in self._topics:
            raise KeyError(f"Topic '{topic_name}' not found")

        message.message_id = f"msg-{len(self._message_store[topic_name]) + 1:06d}"
        message.publish_time = time.time()
        message.status = MessageStatus.PUBLISHED

        self._message_store[topic_name].append(message)
        logger.debug(
            f"Message published to {topic_name}: {message.message_id}"
        )
        return {
            "message_id": message.message_id,
            "topic": topic_name,
            "publish_time": message.publish_time,
            "fingerprint": message.get_fingerprint(),
        }

    def pull_messages(self, subscription_name: str, max_messages: int = 10) -> list:
        """Pull messages from a subscription."""
        if subscription_name not in self._subscriptions:
            raise KeyError(f"Subscription '{subscription_name}' not found")

        sub = self._subscriptions[subscription_name]
        topic_name = sub["topic"].split("/")[-1]

        if topic_name not in self._message_store:
            return []

        pending = [
            m for m in self._message_store[topic_name]
            if m.status == MessageStatus.PUBLISHED
        ]
        batch = pending[:max_messages]

        for msg in batch:
            msg.status = MessageStatus.DELIVERED

        return [
            {
                "ack_id": f"ack-{msg.message_id}",
                "message": {
                    "data": msg.encode(),
                    "attributes": msg.attributes,
                    "message_id": msg.message_id,
                    "publish_time": msg.publish_time,
                    "delivery_attempt": msg.delivery_attempt,
                }
            }
            for msg in batch
        ]

    def acknowledge_message(self, subscription_name: str, ack_id: str) -> dict:
        """Acknowledge a successfully processed message."""
        if subscription_name not in self._subscriptions:
            raise KeyError(f"Subscription '{subscription_name}' not found")
        return {
            "operation": "ACKNOWLEDGE",
            "subscription": subscription_name,
            "ack_id": ack_id,
        }

    def nack_message(self, subscription_name: str, ack_id: str,
                     reason: str = "") -> dict:
        """Negative-acknowledge a message for redelivery."""
        if subscription_name not in self._subscriptions:
            raise KeyError(f"Subscription '{subscription_name}' not found")
        return {
            "operation": "NACK",
            "subscription": subscription_name,
            "ack_id": ack_id,
            "reason": reason,
        }

    def route_to_dead_letter(self, topic_name: str, message: PubSubMessage,
                              reason: str = "") -> dict:
        """Route a message to the dead-letter topic after max delivery attempts."""
        message.status = MessageStatus.DEAD_LETTERED
        dl_key = f"{topic_name}-dead-letter"
        if dl_key not in self._dead_letter_store:
            self._dead_letter_store[dl_key] = []
        self._dead_letter_store[dl_key].append({
            "message": message,
            "reason": reason,
            "routed_at": time.time(),
        })
        logger.warning(
            f"Message {message.message_id} routed to dead-letter: {reason}"
        )
        return {
            "operation": "DEAD_LETTER",
            "original_topic": topic_name,
            "message_id": message.message_id,
            "reason": reason,
        }

    def get_topic_stats(self, topic_name: str) -> dict:
        """Get message statistics for a topic."""
        if topic_name not in self._topics:
            raise KeyError(f"Topic '{topic_name}' not found")

        messages = self._message_store.get(topic_name, [])
        status_counts = {}
        for msg in messages:
            status_counts[msg.status.value] = status_counts.get(msg.status.value, 0) + 1

        return {
            "topic": topic_name,
            "total_messages": len(messages),
            "status_breakdown": status_counts,
            "dead_lettered": len(
                self._dead_letter_store.get(f"{topic_name}-dead-letter", [])
            ),
        }

    def list_topics(self) -> list:
        """List all managed topics."""
        return list(self._topics.keys())

    def list_subscriptions(self) -> list:
        """List all managed subscriptions."""
        return list(self._subscriptions.keys())

    def get_subscription_backlog(self, subscription_name: str) -> dict:
        """Get current backlog count for a subscription."""
        if subscription_name not in self._subscriptions:
            raise KeyError(f"Subscription '{subscription_name}' not found")

        sub = self._subscriptions[subscription_name]
        topic_name = sub["topic"].split("/")[-1]
        messages = self._message_store.get(topic_name, [])
        pending = [m for m in messages if m.status == MessageStatus.PUBLISHED]

        return {
            "subscription": subscription_name,
            "backlog_count": len(pending),
            "oldest_message_age_seconds": (
                time.time() - min(m.publish_time for m in pending)
                if pending else 0
            ),
        }

    def process_payment_event(
        self,
        topic_name: str,
        transaction_id: str,
        amount: float,
        currency: str,
        merchant_id: str,
        event_type: str = "PAYMENT_AUTHORISATION",
        metadata: Optional[dict] = None,
    ) -> dict:
        """
        Publish a structured payment event to Pub/Sub.
        Enforces required fields for PCI-DSS audit trail compliance.
        """
        if not transaction_id:
            raise ValueError("transaction_id is required for payment events")
        if amount <= 0:
            raise ValueError("amount must be > 0")
        if not currency or len(currency) != 3:
            raise ValueError("currency must be a 3-character ISO 4217 code")
        if not merchant_id:
            raise ValueError("merchant_id is required")

        payload = {
            "transaction_id": transaction_id,
            "amount": amount,
            "currency": currency,
            "merchant_id": merchant_id,
            "event_type": event_type,
            "timestamp": time.time(),
            "metadata": metadata or {},
        }
        message = PubSubMessage(
            data=payload,
            attributes={
                "event_type": event_type,
                "merchant_id": merchant_id,
                "currency": currency,
            }
        )
        return self.publish_message(topic_name, message)
