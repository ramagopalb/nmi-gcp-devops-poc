"""Tests for Grafana Dashboard Builder — NMI Payments Platform."""
import pytest
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from grafana_dashboards import NMIDashboardBuilder, PanelType


class TestPaymentsDashboard:
    def test_builds_payment_dashboard(self):
        builder = NMIDashboardBuilder()
        dashboard = builder.build_payment_transactions_dashboard()
        assert dashboard.uid == "nmi-payments"
        assert "payments" in dashboard.tags
        assert len(dashboard.panels) >= 5

    def test_payment_success_rate_panel_is_gauge(self):
        builder = NMIDashboardBuilder()
        dashboard = builder.build_payment_transactions_dashboard()
        gauge_panels = [p for p in dashboard.panels if p.panel_type == PanelType.GAUGE]
        assert len(gauge_panels) >= 1
        success_panel = next((p for p in gauge_panels if "Success Rate" in p.title), None)
        assert success_panel is not None

    def test_success_rate_panel_has_slo_thresholds(self):
        builder = NMIDashboardBuilder()
        dashboard = builder.build_payment_transactions_dashboard()
        panel = next(p for p in dashboard.panels if "Success Rate" in p.title)
        threshold_values = [t["value"] for t in panel.thresholds]
        assert 0.999 in threshold_values

    def test_error_budget_panel_present(self):
        builder = NMIDashboardBuilder()
        dashboard = builder.build_payment_transactions_dashboard()
        panel = next((p for p in dashboard.panels if "Error Budget" in p.title), None)
        assert panel is not None

    def test_fraud_panel_present(self):
        builder = NMIDashboardBuilder()
        dashboard = builder.build_payment_transactions_dashboard()
        fraud_panel = next((p for p in dashboard.panels if "Fraud" in p.title), None)
        assert fraud_panel is not None


class TestGKEDashboard:
    def test_builds_gke_dashboard(self):
        builder = NMIDashboardBuilder()
        dashboard = builder.build_gke_fleet_dashboard()
        assert dashboard.uid == "nmi-gke-fleet"
        assert "gke" in dashboard.tags
        assert len(dashboard.panels) >= 5

    def test_node_ready_ratio_panel(self):
        builder = NMIDashboardBuilder()
        dashboard = builder.build_gke_fleet_dashboard()
        panel = next((p for p in dashboard.panels if "Ready Ratio" in p.title), None)
        assert panel is not None
        assert panel.panel_type == PanelType.STAT

    def test_pdb_violations_panel(self):
        builder = NMIDashboardBuilder()
        dashboard = builder.build_gke_fleet_dashboard()
        panel = next((p for p in dashboard.panels if "PodDisruptionBudget" in p.title), None)
        assert panel is not None


class TestCloudSQLDashboard:
    def test_builds_cloud_sql_dashboard(self):
        builder = NMIDashboardBuilder()
        dashboard = builder.build_cloud_sql_dashboard()
        assert dashboard.uid == "nmi-cloud-sql"
        assert "cloud-sql" in dashboard.tags
        assert len(dashboard.panels) >= 4

    def test_replication_lag_panel(self):
        builder = NMIDashboardBuilder()
        dashboard = builder.build_cloud_sql_dashboard()
        panel = next((p for p in dashboard.panels if "Replication" in p.title), None)
        assert panel is not None

    def test_disk_gauge_panel(self):
        builder = NMIDashboardBuilder()
        dashboard = builder.build_cloud_sql_dashboard()
        gauge_panels = [p for p in dashboard.panels if p.panel_type == PanelType.GAUGE]
        disk_panel = next((p for p in gauge_panels if "Disk" in p.title), None)
        assert disk_panel is not None
        assert 0.85 in [t["value"] for t in disk_panel.thresholds]


class TestPubSubDashboard:
    def test_builds_pubsub_dashboard(self):
        builder = NMIDashboardBuilder()
        dashboard = builder.build_pubsub_dashboard()
        assert dashboard.uid == "nmi-pubsub"
        assert "pubsub" in dashboard.tags
        assert len(dashboard.panels) >= 3

    def test_dlq_panel_present(self):
        builder = NMIDashboardBuilder()
        dashboard = builder.build_pubsub_dashboard()
        panel = next((p for p in dashboard.panels if "DLQ" in p.title), None)
        assert panel is not None
        assert panel.panel_type == PanelType.STAT

    def test_backlog_panel_has_threshold(self):
        builder = NMIDashboardBuilder()
        dashboard = builder.build_pubsub_dashboard()
        panel = next((p for p in dashboard.panels if "Backlog" in p.title), None)
        assert panel is not None
        threshold_values = [t["value"] for t in panel.thresholds]
        assert 1000 in threshold_values


class TestAllDashboards:
    def test_four_dashboards_generated(self):
        builder = NMIDashboardBuilder()
        dashboards = builder.get_all_dashboards()
        assert len(dashboards) == 4

    def test_total_panel_count(self):
        builder = NMIDashboardBuilder()
        total = builder.count_total_panels()
        assert total >= 18

    def test_all_dashboards_have_unique_uids(self):
        builder = NMIDashboardBuilder()
        dashboards = builder.get_all_dashboards()
        uids = [d.uid for d in dashboards]
        assert len(uids) == len(set(uids))

    def test_all_dashboards_have_tags(self):
        builder = NMIDashboardBuilder()
        dashboards = builder.get_all_dashboards()
        for d in dashboards:
            assert len(d.tags) > 0
            assert "nmi" in d.tags
