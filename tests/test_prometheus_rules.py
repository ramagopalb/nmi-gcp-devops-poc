"""Tests for Prometheus Rules Generator — NMI Payments Platform."""
import pytest
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from prometheus_rules import PrometheusRulesGenerator, AlertSeverity, PrometheusRule


class TestSLOBurnRateRules:
    def test_generates_three_slo_rules(self):
        gen = PrometheusRulesGenerator()
        rules = gen.generate_payment_slo_rules()
        # 3 SLOs × 3 windows = 9 rules
        assert len(rules) == 9

    def test_page_window_is_1h_5h(self):
        gen = PrometheusRulesGenerator()
        rules = gen.generate_payment_slo_rules()
        page_rules = [r for r in rules if "p1_page" in r.alert]
        assert len(page_rules) == 3  # one per SLO
        for r in page_rules:
            assert "1h" in r.expr
            assert "5h" in r.expr
            assert r.severity == AlertSeverity.PAGE

    def test_ticket_window_is_6h_30h(self):
        gen = PrometheusRulesGenerator()
        rules = gen.generate_payment_slo_rules()
        ticket_rules = [r for r in rules if "p2_ticket" in r.alert]
        assert len(ticket_rules) == 3
        for r in ticket_rules:
            assert "6h" in r.expr
            assert "30h" in r.expr
            assert r.severity == AlertSeverity.TICKET

    def test_warning_window_is_24h_120h(self):
        gen = PrometheusRulesGenerator()
        rules = gen.generate_payment_slo_rules()
        warn_rules = [r for r in rules if "p3_warning" in r.alert]
        assert len(warn_rules) == 3
        for r in warn_rules:
            assert "24h" in r.expr
            assert "120h" in r.expr
            assert r.severity == AlertSeverity.WARNING

    def test_burn_rate_factor_page(self):
        gen = PrometheusRulesGenerator()
        rules = gen.generate_payment_slo_rules()
        page_rule = next(r for r in rules if "p1_page" in r.alert)
        assert "14.4" in page_rule.expr

    def test_all_slo_rules_have_team_label(self):
        gen = PrometheusRulesGenerator()
        rules = gen.generate_payment_slo_rules()
        for r in rules:
            assert "team" in r.labels


class TestPaymentAlerts:
    def test_generates_four_payment_alerts(self):
        gen = PrometheusRulesGenerator()
        rules = gen.generate_payment_alerts()
        assert len(rules) == 4

    def test_payment_success_rate_alert(self):
        gen = PrometheusRulesGenerator()
        rules = gen.generate_payment_alerts()
        alert = next(r for r in rules if "SuccessRate" in r.alert)
        assert "0.95" in alert.expr
        assert alert.severity == AlertSeverity.CRITICAL

    def test_gateway_latency_alert(self):
        gen = PrometheusRulesGenerator()
        rules = gen.generate_payment_alerts()
        alert = next(r for r in rules if "Latency" in r.alert)
        assert "0.99" in alert.expr
        assert "0.5" in alert.expr  # 500ms threshold

    def test_gateway_down_alert_is_critical(self):
        gen = PrometheusRulesGenerator()
        rules = gen.generate_payment_alerts()
        alert = next(r for r in rules if "Down" in r.alert)
        assert alert.severity == AlertSeverity.CRITICAL
        assert "P1" in alert.labels.get("pagerduty", "")


class TestGKEAlerts:
    def test_generates_five_gke_alerts(self):
        gen = PrometheusRulesGenerator()
        rules = gen.generate_gke_alerts()
        assert len(rules) == 5

    def test_node_not_ready_alert(self):
        gen = PrometheusRulesGenerator()
        rules = gen.generate_gke_alerts()
        alert = next(r for r in rules if "NodeNotReady" in r.alert)
        assert alert.severity == AlertSeverity.CRITICAL

    def test_crash_loop_alert(self):
        gen = PrometheusRulesGenerator()
        rules = gen.generate_gke_alerts()
        alert = next(r for r in rules if "CrashLoop" in r.alert)
        assert "restarts_total" in alert.expr

    def test_all_gke_alerts_have_team(self):
        gen = PrometheusRulesGenerator()
        rules = gen.generate_gke_alerts()
        for r in rules:
            assert "team" in r.labels


class TestCloudSQLAlerts:
    def test_generates_three_sql_alerts(self):
        gen = PrometheusRulesGenerator()
        rules = gen.generate_cloud_sql_alerts()
        assert len(rules) == 3

    def test_replication_lag_alert(self):
        gen = PrometheusRulesGenerator()
        rules = gen.generate_cloud_sql_alerts()
        alert = next(r for r in rules if "ReplicationLag" in r.alert)
        assert "30" in alert.expr  # 30s threshold


class TestPubSubAlerts:
    def test_generates_three_pubsub_alerts(self):
        gen = PrometheusRulesGenerator()
        rules = gen.generate_pubsub_alerts()
        assert len(rules) == 3

    def test_dlq_alert_is_critical(self):
        gen = PrometheusRulesGenerator()
        rules = gen.generate_pubsub_alerts()
        alert = next(r for r in rules if "DLQ" in r.alert)
        assert alert.severity == AlertSeverity.CRITICAL
        assert "100" in alert.expr

    def test_payment_backlog_alert(self):
        gen = PrometheusRulesGenerator()
        rules = gen.generate_pubsub_alerts()
        alert = next(r for r in rules if "Backlog" in r.alert)
        assert "1000" in alert.expr


class TestAllRules:
    def test_total_rule_count_above_threshold(self):
        gen = PrometheusRulesGenerator()
        total = gen.count_all_rules()
        # 9 SLO + 4 payment + 5 GKE + 3 SQL + 3 pubsub = 24 rules
        assert total >= 20

    def test_all_rules_dict_has_categories(self):
        gen = PrometheusRulesGenerator()
        all_rules = gen.generate_all_rules()
        assert "payment_slo_burn_rate" in all_rules
        assert "payment_alerts" in all_rules
        assert "gke_alerts" in all_rules
        assert "cloud_sql_alerts" in all_rules
        assert "pubsub_alerts" in all_rules

    def test_yaml_render(self):
        gen = PrometheusRulesGenerator()
        rules = gen.generate_gke_alerts()
        yaml_output = gen.render_yaml(rules)
        assert "groups:" in yaml_output
        assert "alert:" in yaml_output
        assert "severity:" in yaml_output
