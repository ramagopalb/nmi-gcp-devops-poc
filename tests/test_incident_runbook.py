"""Tests for Incident Runbook Executor — NMI Payments Platform."""
import pytest
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from incident_runbook import (
    IncidentRunbookExecutor, Incident, Severity, IncidentState
)


def make_executor():
    return IncidentRunbookExecutor()


class TestIncidentCreation:
    def test_creates_incident_with_id(self):
        ex = make_executor()
        incident = ex.create_incident(
            "Payment gateway down", Severity.P1, "payment-gateway",
            "NMIPaymentGatewayDown", "alice"
        )
        assert incident.incident_id == "INC-0001"
        assert incident.severity == Severity.P1
        assert incident.state == IncidentState.TRIGGERED

    def test_incident_added_to_active(self):
        ex = make_executor()
        incident = ex.create_incident("Test", Severity.P2, "svc", "Alert", "bob")
        assert incident.incident_id in ex.active_incidents

    def test_multiple_incidents_sequential_ids(self):
        ex = make_executor()
        i1 = ex.create_incident("Inc1", Severity.P1, "svc", "Alert", "alice")
        i2 = ex.create_incident("Inc2", Severity.P2, "svc", "Alert", "bob")
        assert i1.incident_id == "INC-0001"
        assert i2.incident_id == "INC-0002"

    def test_incident_in_incidents_list(self):
        ex = make_executor()
        incident = ex.create_incident("Test", Severity.P3, "svc", "Alert", "charlie")
        assert incident in ex.incidents


class TestRunbookRetrieval:
    def test_payment_gateway_runbook_exists(self):
        ex = make_executor()
        steps = ex.get_runbook("payment_gateway_down")
        assert len(steps) > 0

    def test_payment_success_runbook_exists(self):
        ex = make_executor()
        steps = ex.get_runbook("payment_success_rate_low")
        assert len(steps) > 0

    def test_gke_node_runbook_exists(self):
        ex = make_executor()
        steps = ex.get_runbook("gke_node_not_ready")
        assert len(steps) > 0

    def test_cloud_sql_runbook_exists(self):
        ex = make_executor()
        steps = ex.get_runbook("cloud_sql_replication_lag")
        assert len(steps) > 0

    def test_unknown_runbook_returns_empty(self):
        ex = make_executor()
        steps = ex.get_runbook("non_existent_runbook")
        assert steps == []

    def test_runbook_steps_ordered(self):
        ex = make_executor()
        steps = ex.get_runbook("payment_gateway_down")
        orders = [s.order for s in steps]
        assert orders == sorted(orders)


class TestRunbookExecution:
    def test_execute_step_dry_run(self):
        ex = make_executor()
        incident = ex.create_incident("P1 Alert", Severity.P1, "gateway", "AlertFired", "alice")
        steps = ex.get_runbook("payment_gateway_down")
        result = ex.execute_runbook_step(incident, steps[0], dry_run=True)
        assert result["dry_run"] is True
        assert result["success"] is True
        assert result["step"] == 1

    def test_execute_step_updates_state(self):
        ex = make_executor()
        incident = ex.create_incident("P1 Alert", Severity.P1, "gateway", "AlertFired", "alice")
        steps = ex.get_runbook("payment_gateway_down")
        ex.execute_runbook_step(incident, steps[0])
        assert incident.state == IncidentState.INVESTIGATING

    def test_executed_steps_tracked(self):
        ex = make_executor()
        incident = ex.create_incident("P1 Alert", Severity.P1, "gateway", "AlertFired", "alice")
        steps = ex.get_runbook("payment_gateway_down")
        ex.execute_runbook_step(incident, steps[0])
        ex.execute_runbook_step(incident, steps[1])
        assert len(incident.runbook_steps_completed) == 2


class TestIncidentResolution:
    def test_resolve_incident(self):
        ex = make_executor()
        incident = ex.create_incident("P1 Alert", Severity.P1, "gateway", "AlertFired", "alice")
        result = ex.resolve_incident(incident.incident_id, "Memory leak in payment processor v1.1.9")
        assert result["resolved"] is True
        assert "mttr_minutes" in result
        assert incident.incident_id not in ex.active_incidents

    def test_resolve_nonexistent_incident(self):
        ex = make_executor()
        result = ex.resolve_incident("INC-9999", "root cause")
        assert "error" in result

    def test_mttr_calculated(self):
        ex = make_executor()
        incident = ex.create_incident("Alert", Severity.P2, "svc", "Alert", "bob")
        result = ex.resolve_incident(incident.incident_id, "Fixed")
        assert result["mttr_minutes"] > 0


class TestPIRGeneration:
    def test_generates_pir(self):
        ex = make_executor()
        incident = ex.create_incident("Payment failure", Severity.P1, "gateway", "Alert", "alice")
        ex.resolve_incident(incident.incident_id, "DB connection pool exhaustion")
        pir = ex.generate_pir(incident)
        assert pir["incident_id"] == incident.incident_id
        assert pir["severity"] == "P1"
        assert "action_items" in pir
        assert len(pir["action_items"]) > 0

    def test_pir_has_timeline(self):
        ex = make_executor()
        incident = ex.create_incident("Test", Severity.P2, "svc", "Alert", "bob")
        pir = ex.generate_pir(incident)
        assert "timeline" in pir
        assert "triggered" in pir["timeline"]


class TestOnCallAndSeverity:
    def test_on_call_rotation_has_four_weeks(self):
        ex = make_executor()
        rotation = ex.get_on_call_rotation()
        assert len(rotation) == 4
        for week in rotation:
            assert "primary" in week
            assert "secondary" in week
            assert "escalation" in week

    def test_severity_response_matrix_has_all_severities(self):
        ex = make_executor()
        matrix = ex.get_severity_response_matrix()
        assert "P1" in matrix
        assert "P2" in matrix
        assert "P3" in matrix
        assert "P4" in matrix

    def test_p1_fastest_response(self):
        ex = make_executor()
        matrix = ex.get_severity_response_matrix()
        assert matrix["P1"]["response_time_minutes"] < matrix["P2"]["response_time_minutes"]
        assert matrix["P2"]["response_time_minutes"] < matrix["P3"]["response_time_minutes"]

    def test_p1_has_cto_escalation(self):
        ex = make_executor()
        matrix = ex.get_severity_response_matrix()
        assert "CTO" in matrix["P1"]["stakeholders"]
