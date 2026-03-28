"""Tests for Pub/Sub Payment Event Processor — NMI Payments Platform."""
import pytest
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from pubsub_processor import (
    PaymentEventProcessor, PubSubTopicManager, PaymentEvent, PaymentState,
    PaymentEventType, ProcessingResult
)

import time


def make_event(event_type, payment_id="PAY-001", amount=1000, retry=0, max_retries=3):
    return PaymentEvent(
        event_id=f"evt-{event_type.value}-{payment_id}",
        event_type=event_type,
        payment_id=payment_id,
        merchant_id="MERCHANT-001",
        amount_pence=amount,
        currency="GBP",
        timestamp=time.time(),
        retry_count=retry,
        max_retries=max_retries,
    )


# State machine tests
class TestPaymentStateMachine:
    def test_valid_full_payment_flow(self):
        proc = PaymentEventProcessor()
        # Full happy path
        r1 = proc.process_event(make_event(PaymentEventType.PAYMENT_SUBMITTED))
        assert r1.success is True
        assert r1.state == PaymentState.SUBMITTED

        r2 = proc.process_event(make_event(PaymentEventType.PAYMENT_AUTHORISED))
        assert r2.success is True
        assert r2.state == PaymentState.AUTHORISED

        r3 = proc.process_event(make_event(PaymentEventType.PAYMENT_CAPTURED))
        assert r3.success is True
        assert r3.state == PaymentState.CAPTURED

        r4 = proc.process_event(make_event(PaymentEventType.PAYMENT_SETTLED))
        assert r4.success is True
        assert r4.state == PaymentState.SETTLED

    def test_payment_failure_flow(self):
        proc = PaymentEventProcessor()
        proc.process_event(make_event(PaymentEventType.PAYMENT_SUBMITTED))
        proc.process_event(make_event(PaymentEventType.PAYMENT_AUTHORISED))
        r = proc.process_event(make_event(PaymentEventType.PAYMENT_FAILED))
        assert r.success is True
        assert r.state == PaymentState.FAILED

    def test_payment_reversed_flow(self):
        proc = PaymentEventProcessor()
        proc.process_event(make_event(PaymentEventType.PAYMENT_SUBMITTED))
        proc.process_event(make_event(PaymentEventType.PAYMENT_AUTHORISED))
        r = proc.process_event(make_event(PaymentEventType.PAYMENT_REVERSED))
        assert r.success is True
        assert r.state == PaymentState.REVERSED

    def test_refund_after_settlement(self):
        proc = PaymentEventProcessor()
        for evt in [PaymentEventType.PAYMENT_SUBMITTED, PaymentEventType.PAYMENT_AUTHORISED,
                    PaymentEventType.PAYMENT_CAPTURED, PaymentEventType.PAYMENT_SETTLED]:
            proc.process_event(make_event(evt))
        r = proc.process_event(make_event(PaymentEventType.PAYMENT_REFUNDED))
        assert r.success is True
        assert r.state == PaymentState.REFUNDED

    def test_invalid_transition_to_dlq(self):
        proc = PaymentEventProcessor()
        proc.process_event(make_event(PaymentEventType.PAYMENT_SUBMITTED))
        # Try to settle without going through authorise/capture
        evt = make_event(PaymentEventType.PAYMENT_SETTLED, max_retries=0)
        r = proc.process_event(evt)
        assert r.success is False
        assert r.sent_to_dlq is True
        assert proc.get_dlq_depth() == 1

    def test_first_event_must_be_submitted(self):
        proc = PaymentEventProcessor()
        evt = make_event(PaymentEventType.PAYMENT_AUTHORISED)
        r = proc.process_event(evt)
        assert r.success is False

    def test_retry_before_dlq(self):
        proc = PaymentEventProcessor()
        proc.process_event(make_event(PaymentEventType.PAYMENT_SUBMITTED))
        # Invalid transition — should retry first
        evt = make_event(PaymentEventType.PAYMENT_SETTLED, retry=0, max_retries=3)
        r = proc.process_event(evt)
        assert r.retried is True
        assert r.sent_to_dlq is False


# Metrics tests
class TestProcessorMetrics:
    def test_success_rate_all_valid(self):
        proc = PaymentEventProcessor()
        proc.process_event(make_event(PaymentEventType.PAYMENT_SUBMITTED, "P1"))
        proc.process_event(make_event(PaymentEventType.PAYMENT_AUTHORISED, "P1"))
        assert proc.get_success_rate() == 1.0

    def test_success_rate_with_failures(self):
        proc = PaymentEventProcessor()
        proc.process_event(make_event(PaymentEventType.PAYMENT_SUBMITTED, "P1"))
        evt = make_event(PaymentEventType.PAYMENT_SETTLED, "P1", max_retries=0)
        proc.process_event(evt)
        rate = proc.get_success_rate()
        assert rate < 1.0

    def test_empty_processor_success_rate(self):
        proc = PaymentEventProcessor()
        assert proc.get_success_rate() == 1.0

    def test_metrics_summary_keys(self):
        proc = PaymentEventProcessor()
        proc.process_event(make_event(PaymentEventType.PAYMENT_SUBMITTED))
        summary = proc.get_metrics_summary()
        assert "total_processed" in summary
        assert "successful" in summary
        assert "success_rate" in summary
        assert "dlq_depth" in summary


# PubSub topology tests
class TestPubSubTopology:
    def test_creates_all_topics(self):
        mgr = PubSubTopicManager("nmi-prod")
        topology = mgr.create_payments_topology()
        assert "nmi-payment-events" in topology["topics"]
        assert "nmi-payment-events-dlq" in topology["topics"]
        assert "nmi-fraud-events" in topology["topics"]

    def test_creates_required_subscriptions(self):
        mgr = PubSubTopicManager("nmi-prod")
        topology = mgr.create_payments_topology()
        assert "payment-processor-sub" in topology["subscriptions"]
        assert "dlq-processor-sub" in topology["subscriptions"]

    def test_payment_sub_has_dlq_configured(self):
        mgr = PubSubTopicManager("nmi-prod")
        mgr.create_payments_topology()
        sub = mgr.subscriptions["payment-processor-sub"]
        assert sub.dead_letter_topic == "nmi-payment-events-dlq"
        assert sub.max_delivery_attempts == 5

    def test_terraform_hcl_generated(self):
        mgr = PubSubTopicManager("nmi-prod")
        mgr.create_payments_topology()
        hcl = mgr.generate_terraform_hcl()
        assert "google_pubsub_topic" in hcl
        assert "google_pubsub_subscription" in hcl
        assert "nmi-payment-events" in hcl

    def test_topic_validation_passes(self):
        mgr = PubSubTopicManager("nmi-prod")
        mgr.create_payments_topology()
        result = mgr.validate_topic_configuration("nmi-payment-events")
        assert result["valid"] is True

    def test_dlq_retention_longer(self):
        mgr = PubSubTopicManager("nmi-prod")
        mgr.create_payments_topology()
        main_topic = mgr.topics["nmi-payment-events"]
        dlq_topic = mgr.topics["nmi-payment-events-dlq"]
        assert dlq_topic.message_retention_seconds > main_topic.message_retention_seconds

    def test_settlement_subscription_has_filter(self):
        mgr = PubSubTopicManager("nmi-prod")
        mgr.create_payments_topology()
        sub = mgr.subscriptions["settlement-processor-sub"]
        assert "payment.settled" in sub.filter_expression
