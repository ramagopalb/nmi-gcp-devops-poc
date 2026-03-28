"""
Tests for GCP Pub/Sub handler — NMI GCP Payments DevOps POC.
Covers topic/subscription lifecycle, message publishing, dead-letter routing,
retry policy, consumer lag monitoring, and payment event validation.
"""

import pytest
import time
from gcp.pubsub_handler import (
    PubSubHandler,
    PubSubMessage,
    TopicConfig,
    SubscriptionConfig,
    DeadLetterConfig,
    RetryPolicy,
    ConsumerLagMonitor,
    MessageStatus,
)


# ─────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────

@pytest.fixture
def handler():
    return PubSubHandler(project_id="nmi-payments-prod", dry_run=True)


@pytest.fixture
def topic_config():
    return TopicConfig(
        topic_name="payment-transactions",
        project_id="nmi-payments-prod",
        labels={"env": "prod", "team": "payments"},
    )


@pytest.fixture
def handler_with_topic(handler, topic_config):
    handler.create_topic(topic_config)
    return handler


@pytest.fixture
def subscription_config():
    return SubscriptionConfig(
        subscription_name="payment-processor-sub",
        topic_name="payment-transactions",
        ack_deadline_seconds=60,
    )


@pytest.fixture
def handler_with_subscription(handler_with_topic, subscription_config):
    handler_with_topic.create_subscription(subscription_config)
    return handler_with_topic


@pytest.fixture
def sample_message():
    return PubSubMessage(
        data={
            "transaction_id": "txn-001",
            "amount": 99.99,
            "currency": "GBP",
            "merchant_id": "merchant-123",
        },
        attributes={"event_type": "PAYMENT_AUTHORISATION"},
    )


# ─────────────────────────────────────────
# PubSubHandler init
# ─────────────────────────────────────────

class TestPubSubHandlerInit:
    def test_init_sets_project_id(self):
        h = PubSubHandler(project_id="test-proj")
        assert h.project_id == "test-proj"

    def test_init_dry_run_default(self):
        h = PubSubHandler(project_id="test-proj")
        assert h.dry_run is True

    def test_list_topics_empty(self, handler):
        assert handler.list_topics() == []

    def test_list_subscriptions_empty(self, handler):
        assert handler.list_subscriptions() == []


# ─────────────────────────────────────────
# Topic management
# ─────────────────────────────────────────

class TestTopicManagement:
    def test_create_topic_returns_operation(self, handler, topic_config):
        result = handler.create_topic(topic_config)
        assert result["operation"] == "CREATE_TOPIC"

    def test_create_topic_stores_topic(self, handler, topic_config):
        handler.create_topic(topic_config)
        assert "payment-transactions" in handler.list_topics()

    def test_create_duplicate_topic_raises(self, handler_with_topic, topic_config):
        with pytest.raises(ValueError, match="already exists"):
            handler_with_topic.create_topic(topic_config)

    def test_create_topic_invalid_config_raises(self, handler):
        bad = TopicConfig(topic_name="", project_id="proj")
        with pytest.raises(ValueError):
            handler.create_topic(bad)

    def test_create_topic_with_kms_key(self, handler):
        config = TopicConfig(
            topic_name="encrypted-topic",
            project_id="nmi-payments-prod",
            kms_key_name="projects/nmi/locations/eur/keyRings/kr/cryptoKeys/key",
        )
        result = handler.create_topic(config)
        assert result["topic"]["kmsKeyName"] is not None

    def test_delete_topic_removes_it(self, handler_with_topic):
        handler_with_topic.delete_topic("payment-transactions")
        assert "payment-transactions" not in handler_with_topic.list_topics()

    def test_delete_nonexistent_topic_raises(self, handler):
        with pytest.raises(KeyError):
            handler.delete_topic("ghost-topic")

    def test_topic_full_resource_name(self):
        config = TopicConfig(topic_name="t1", project_id="proj1")
        assert config.full_resource_name() == "projects/proj1/topics/t1"


# ─────────────────────────────────────────
# Subscription management
# ─────────────────────────────────────────

class TestSubscriptionManagement:
    def test_create_subscription_returns_operation(
        self, handler_with_topic, subscription_config
    ):
        result = handler_with_topic.create_subscription(subscription_config)
        assert result["operation"] == "CREATE_SUBSCRIPTION"

    def test_create_subscription_stores_it(
        self, handler_with_topic, subscription_config
    ):
        handler_with_topic.create_subscription(subscription_config)
        assert "payment-processor-sub" in handler_with_topic.list_subscriptions()

    def test_create_subscription_nonexistent_topic_raises(self, handler):
        config = SubscriptionConfig("sub", "ghost-topic")
        with pytest.raises(KeyError):
            handler.create_subscription(config)

    def test_duplicate_subscription_raises(
        self, handler_with_subscription, subscription_config
    ):
        with pytest.raises(ValueError, match="already exists"):
            handler_with_subscription.create_subscription(subscription_config)

    def test_subscription_with_dead_letter(self, handler_with_topic):
        dl_config = DeadLetterConfig(
            dead_letter_topic="payment-transactions-dead-letter",
            max_delivery_attempts=5,
        )
        # Create dead-letter topic first
        handler_with_topic.create_topic(
            TopicConfig("payment-transactions-dead-letter", "nmi-payments-prod")
        )
        sub = SubscriptionConfig(
            subscription_name="sub-with-dl",
            topic_name="payment-transactions",
            dead_letter=dl_config,
        )
        result = handler_with_topic.create_subscription(sub)
        assert result["subscription"]["deadLetterPolicy"] is not None

    def test_subscription_with_retry_policy(self, handler_with_topic):
        retry = RetryPolicy(minimum_backoff_seconds=10, maximum_backoff_seconds=300)
        sub = SubscriptionConfig(
            subscription_name="sub-with-retry",
            topic_name="payment-transactions",
            retry_policy=retry,
        )
        result = handler_with_topic.create_subscription(sub)
        assert result["subscription"]["retryPolicy"] is not None

    def test_subscription_invalid_ack_deadline_raises(self, handler_with_topic):
        sub = SubscriptionConfig(
            subscription_name="bad-sub",
            topic_name="payment-transactions",
            ack_deadline_seconds=5,  # below minimum
        )
        with pytest.raises(ValueError):
            handler_with_topic.create_subscription(sub)

    def test_subscription_with_filter(self, handler_with_topic):
        sub = SubscriptionConfig(
            subscription_name="filtered-sub",
            topic_name="payment-transactions",
            filter_expression='attributes.event_type = "PAYMENT_AUTHORISATION"',
        )
        result = handler_with_topic.create_subscription(sub)
        assert "PAYMENT_AUTHORISATION" in result["subscription"]["filter"]


# ─────────────────────────────────────────
# Message publishing
# ─────────────────────────────────────────

class TestMessagePublishing:
    def test_publish_message_returns_message_id(
        self, handler_with_topic, sample_message
    ):
        result = handler_with_topic.publish_message("payment-transactions", sample_message)
        assert "message_id" in result

    def test_publish_message_sets_publish_time(
        self, handler_with_topic, sample_message
    ):
        result = handler_with_topic.publish_message("payment-transactions", sample_message)
        assert result["publish_time"] is not None

    def test_publish_to_nonexistent_topic_raises(self, handler, sample_message):
        with pytest.raises(KeyError):
            handler.publish_message("ghost-topic", sample_message)

    def test_publish_message_fingerprint_present(
        self, handler_with_topic, sample_message
    ):
        result = handler_with_topic.publish_message("payment-transactions", sample_message)
        assert "fingerprint" in result
        assert len(result["fingerprint"]) == 16

    def test_multiple_messages_have_sequential_ids(self, handler_with_topic):
        m1 = PubSubMessage(data={"id": 1})
        m2 = PubSubMessage(data={"id": 2})
        r1 = handler_with_topic.publish_message("payment-transactions", m1)
        r2 = handler_with_topic.publish_message("payment-transactions", m2)
        assert r1["message_id"] != r2["message_id"]

    def test_published_message_status(self, handler_with_topic, sample_message):
        handler_with_topic.publish_message("payment-transactions", sample_message)
        assert sample_message.status == MessageStatus.PUBLISHED


# ─────────────────────────────────────────
# Message pulling and acknowledging
# ─────────────────────────────────────────

class TestMessageConsumption:
    def test_pull_messages_returns_list(self, handler_with_subscription, sample_message):
        handler_with_subscription.publish_message("payment-transactions", sample_message)
        messages = handler_with_subscription.pull_messages("payment-processor-sub")
        assert isinstance(messages, list)

    def test_pull_messages_returns_published_message(
        self, handler_with_subscription, sample_message
    ):
        handler_with_subscription.publish_message("payment-transactions", sample_message)
        messages = handler_with_subscription.pull_messages("payment-processor-sub")
        assert len(messages) == 1

    def test_pull_messages_contains_ack_id(
        self, handler_with_subscription, sample_message
    ):
        handler_with_subscription.publish_message("payment-transactions", sample_message)
        messages = handler_with_subscription.pull_messages("payment-processor-sub")
        assert "ack_id" in messages[0]

    def test_pull_messages_max_limit(self, handler_with_subscription):
        for i in range(15):
            msg = PubSubMessage(data={"seq": i})
            handler_with_subscription.publish_message("payment-transactions", msg)
        messages = handler_with_subscription.pull_messages(
            "payment-processor-sub", max_messages=5
        )
        assert len(messages) <= 5

    def test_acknowledge_returns_operation(self, handler_with_subscription):
        result = handler_with_subscription.acknowledge_message(
            "payment-processor-sub", "ack-001"
        )
        assert result["operation"] == "ACKNOWLEDGE"

    def test_nack_returns_operation(self, handler_with_subscription):
        result = handler_with_subscription.nack_message(
            "payment-processor-sub", "ack-001", reason="processing_error"
        )
        assert result["operation"] == "NACK"

    def test_pull_from_nonexistent_subscription_raises(self, handler):
        with pytest.raises(KeyError):
            handler.pull_messages("ghost-sub")


# ─────────────────────────────────────────
# Dead-letter routing
# ─────────────────────────────────────────

class TestDeadLetterRouting:
    def test_route_to_dead_letter_returns_operation(
        self, handler_with_topic, sample_message
    ):
        result = handler_with_topic.route_to_dead_letter(
            "payment-transactions", sample_message, "max_retries_exceeded"
        )
        assert result["operation"] == "DEAD_LETTER"

    def test_dead_lettered_message_status(
        self, handler_with_topic, sample_message
    ):
        handler_with_topic.route_to_dead_letter(
            "payment-transactions", sample_message, "processing_error"
        )
        assert sample_message.status == MessageStatus.DEAD_LETTERED

    def test_get_topic_stats_includes_dead_lettered(
        self, handler_with_topic, sample_message
    ):
        handler_with_topic.publish_message("payment-transactions", sample_message)
        handler_with_topic.route_to_dead_letter(
            "payment-transactions", sample_message, "error"
        )
        stats = handler_with_topic.get_topic_stats("payment-transactions")
        assert stats["dead_lettered"] == 1


# ─────────────────────────────────────────
# Topic statistics
# ─────────────────────────────────────────

class TestTopicStatistics:
    def test_get_topic_stats_returns_dict(self, handler_with_topic):
        stats = handler_with_topic.get_topic_stats("payment-transactions")
        assert isinstance(stats, dict)

    def test_get_topic_stats_total_messages(self, handler_with_topic, sample_message):
        handler_with_topic.publish_message("payment-transactions", sample_message)
        stats = handler_with_topic.get_topic_stats("payment-transactions")
        assert stats["total_messages"] == 1

    def test_get_topic_stats_nonexistent_raises(self, handler):
        with pytest.raises(KeyError):
            handler.get_topic_stats("ghost-topic")


# ─────────────────────────────────────────
# Consumer lag monitoring
# ─────────────────────────────────────────

class TestConsumerLagMonitor:
    def test_record_and_retrieve_lag(self):
        monitor = ConsumerLagMonitor(alert_threshold_seconds=60)
        monitor.record_lag("sub-1", 30.0, 5)
        lag = monitor.get_lag("sub-1")
        assert lag["oldest_unacked_age_seconds"] == 30.0

    def test_slo_ok_below_threshold(self):
        monitor = ConsumerLagMonitor(alert_threshold_seconds=60)
        monitor.record_lag("sub-1", 30.0, 5)
        result = monitor.check_slo("sub-1")
        assert result["status"] == "OK"
        assert result["slo_breach"] is False

    def test_slo_breach_above_threshold(self):
        monitor = ConsumerLagMonitor(alert_threshold_seconds=60)
        monitor.record_lag("sub-1", 120.0, 50)
        result = monitor.check_slo("sub-1")
        assert result["status"] == "BREACH"
        assert result["slo_breach"] is True

    def test_list_breaches_returns_only_breaching(self):
        monitor = ConsumerLagMonitor(alert_threshold_seconds=60)
        monitor.record_lag("ok-sub", 10.0, 1)
        monitor.record_lag("breach-sub", 200.0, 100)
        breaches = monitor.list_breaches()
        assert len(breaches) == 1
        assert breaches[0]["subscription"] == "breach-sub"

    def test_no_data_returns_no_data_status(self):
        monitor = ConsumerLagMonitor()
        result = monitor.check_slo("unknown-sub")
        assert result["status"] == "NO_DATA"

    def test_backlog_count_tracked(self):
        monitor = ConsumerLagMonitor()
        monitor.record_lag("sub-1", 5.0, 42)
        lag = monitor.get_lag("sub-1")
        assert lag["backlog_count"] == 42

    def test_handler_lag_monitor_accessible(self, handler):
        assert handler.lag_monitor is not None

    def test_get_subscription_backlog(self, handler_with_subscription, sample_message):
        handler_with_subscription.publish_message("payment-transactions", sample_message)
        backlog = handler_with_subscription.get_subscription_backlog(
            "payment-processor-sub"
        )
        assert backlog["backlog_count"] == 1


# ─────────────────────────────────────────
# PubSubMessage encoding/decoding
# ─────────────────────────────────────────

class TestPubSubMessageEncoding:
    def test_encode_decode_roundtrip(self):
        original = PubSubMessage(data={"key": "value", "num": 42})
        encoded = original.encode()
        decoded = PubSubMessage.decode(encoded)
        assert decoded.data == original.data

    def test_encode_returns_string(self, sample_message):
        encoded = sample_message.encode()
        assert isinstance(encoded, str)

    def test_fingerprint_is_deterministic(self):
        m1 = PubSubMessage(data={"a": 1, "b": 2})
        m2 = PubSubMessage(data={"a": 1, "b": 2})
        assert m1.get_fingerprint() == m2.get_fingerprint()

    def test_different_data_different_fingerprint(self):
        m1 = PubSubMessage(data={"a": 1})
        m2 = PubSubMessage(data={"a": 2})
        assert m1.get_fingerprint() != m2.get_fingerprint()


# ─────────────────────────────────────────
# Payment event publishing
# ─────────────────────────────────────────

class TestPaymentEventPublishing:
    def test_process_payment_event_returns_message_id(self, handler_with_topic):
        result = handler_with_topic.process_payment_event(
            topic_name="payment-transactions",
            transaction_id="txn-100",
            amount=500.0,
            currency="GBP",
            merchant_id="merchant-999",
        )
        assert "message_id" in result

    def test_payment_event_invalid_amount_raises(self, handler_with_topic):
        with pytest.raises(ValueError, match="amount must be > 0"):
            handler_with_topic.process_payment_event(
                "payment-transactions", "txn-001", -10.0, "GBP", "merchant-1"
            )

    def test_payment_event_invalid_currency_raises(self, handler_with_topic):
        with pytest.raises(ValueError, match="currency"):
            handler_with_topic.process_payment_event(
                "payment-transactions", "txn-001", 100.0, "GBPX", "merchant-1"
            )

    def test_payment_event_missing_transaction_id_raises(self, handler_with_topic):
        with pytest.raises(ValueError, match="transaction_id"):
            handler_with_topic.process_payment_event(
                "payment-transactions", "", 100.0, "GBP", "merchant-1"
            )

    def test_payment_event_missing_merchant_raises(self, handler_with_topic):
        with pytest.raises(ValueError, match="merchant_id"):
            handler_with_topic.process_payment_event(
                "payment-transactions", "txn-001", 100.0, "GBP", ""
            )

    def test_payment_event_default_event_type(self, handler_with_topic):
        handler_with_topic.process_payment_event(
            "payment-transactions", "txn-001", 100.0, "GBP", "merchant-1"
        )
        stats = handler_with_topic.get_topic_stats("payment-transactions")
        assert stats["total_messages"] == 1


# ─────────────────────────────────────────
# RetryPolicy validation
# ─────────────────────────────────────────

class TestRetryPolicyValidation:
    def test_valid_retry_policy(self):
        policy = RetryPolicy(10, 300)
        assert policy.validate() == []

    def test_invalid_min_backoff(self):
        policy = RetryPolicy(-1, 300)
        errors = policy.validate()
        assert any("minimum_backoff" in e for e in errors)

    def test_max_less_than_min_raises(self):
        policy = RetryPolicy(300, 100)
        errors = policy.validate()
        assert any("maximum_backoff" in e for e in errors)

    def test_max_exceeds_600(self):
        policy = RetryPolicy(10, 601)
        errors = policy.validate()
        assert any("600" in e for e in errors)

    def test_backoff_exponential_growth(self):
        policy = RetryPolicy(10, 600)
        assert policy.get_backoff(1) == 10
        assert policy.get_backoff(2) == 20
        assert policy.get_backoff(3) == 40

    def test_backoff_capped_at_maximum(self):
        policy = RetryPolicy(10, 100)
        assert policy.get_backoff(10) == 100
