"""Tests for CI/CD Pipeline Generator — NMI Payments Platform."""
import pytest
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from cicd_pipeline import (
    CICDPipelineGenerator, DeploymentEvent, SecurityScanResult,
    DeploymentStrategy, DeploymentStage, SecurityScanStatus, DORAMetrics
)


def make_deployment(service="payment-gateway", version="v1.2.0", env="production",
                    success=True, error_rate=0.005, lead_time=45.0, rollback=False):
    return DeploymentEvent(
        service=service, version=version, environment=env,
        strategy=DeploymentStrategy.CANARY, stage=DeploymentStage.CANARY_10,
        success=success, error_rate_at_deploy=error_rate,
        lead_time_minutes=lead_time, triggered_rollback=rollback,
    )


class TestGitHubActionsWorkflow:
    def test_generates_workflow_yaml(self):
        gen = CICDPipelineGenerator()
        workflow = gen.generate_github_actions_workflow("payment-gateway", "nmi-prod", "nmi-payments-cluster")
        assert "payment-gateway" in workflow
        assert "nmi-prod" in workflow
        assert "nmi-payments-cluster" in workflow

    def test_security_gates_job_present(self):
        gen = CICDPipelineGenerator()
        workflow = gen.generate_github_actions_workflow("svc", "proj", "cluster")
        assert "security-gates" in workflow
        assert "Trivy" in workflow
        assert "Checkov" in workflow
        assert "OPA" in workflow

    def test_binary_authorization_check_present(self):
        gen = CICDPipelineGenerator()
        workflow = gen.generate_github_actions_workflow("svc", "proj", "cluster")
        assert "binauthz" in workflow

    def test_canary_deploy_job_present(self):
        gen = CICDPipelineGenerator()
        workflow = gen.generate_github_actions_workflow("svc", "proj", "cluster")
        assert "deploy-canary" in workflow
        assert "canary" in workflow.lower()

    def test_rollback_on_high_error_rate(self):
        gen = CICDPipelineGenerator()
        workflow = gen.generate_github_actions_workflow("svc", "proj", "cluster")
        # Workflow uses "rollout undo" for rollback (kubectl idiom)
        assert "rollout undo" in workflow.lower() or "rolling back" in workflow.lower()
        assert "0.01" in workflow

    def test_buildkit_gcs_cache_present(self):
        gen = CICDPipelineGenerator()
        workflow = gen.generate_github_actions_workflow("svc", "proj", "cluster")
        assert "gcs" in workflow.lower()
        assert "cache" in workflow.lower()

    def test_workload_identity_provider_present(self):
        gen = CICDPipelineGenerator()
        workflow = gen.generate_github_actions_workflow("svc", "proj", "cluster")
        assert "workload_identity_provider" in workflow

    def test_dora_metrics_recording_present(self):
        gen = CICDPipelineGenerator()
        workflow = gen.generate_github_actions_workflow("svc", "proj", "cluster")
        assert "dora" in workflow.lower() or "lead_time" in workflow.lower()


class TestCanaryGate:
    def test_low_error_rate_promotes(self):
        gen = CICDPipelineGenerator()
        deploy = make_deployment(error_rate=0.002)
        result = gen.evaluate_canary_gate(deploy, error_rate_threshold=0.01)
        assert result["action"] == "PROMOTE"
        assert result["passed"] is True

    def test_high_error_rate_rolls_back(self):
        gen = CICDPipelineGenerator()
        deploy = make_deployment(error_rate=0.05)
        result = gen.evaluate_canary_gate(deploy, error_rate_threshold=0.01)
        assert result["action"] == "ROLLBACK"
        assert result["passed"] is False

    def test_exactly_at_threshold_promotes(self):
        gen = CICDPipelineGenerator()
        deploy = make_deployment(error_rate=0.01)
        result = gen.evaluate_canary_gate(deploy, error_rate_threshold=0.01)
        assert result["action"] == "PROMOTE"

    def test_custom_threshold(self):
        gen = CICDPipelineGenerator()
        deploy = make_deployment(error_rate=0.03)
        result = gen.evaluate_canary_gate(deploy, error_rate_threshold=0.05)
        assert result["action"] == "PROMOTE"


class TestDORAMetrics:
    def test_calculates_deployment_frequency(self):
        gen = CICDPipelineGenerator()
        deployments = [make_deployment() for _ in range(30)]
        metrics = gen.calculate_dora_metrics(deployments)
        assert metrics.deployment_frequency_per_day == 1.0

    def test_calculates_change_failure_rate(self):
        gen = CICDPipelineGenerator()
        deployments = [make_deployment()] * 8 + [make_deployment(rollback=True)] * 2
        metrics = gen.calculate_dora_metrics(deployments)
        assert metrics.change_failure_rate == 0.2

    def test_empty_deployments(self):
        gen = CICDPipelineGenerator()
        metrics = gen.calculate_dora_metrics([])
        assert metrics.deployment_frequency_per_day == 0
        assert metrics.change_failure_rate == 0

    def test_elite_classification(self):
        gen = CICDPipelineGenerator()
        metrics = DORAMetrics(
            deployment_frequency_per_day=2.0,
            lead_time_minutes=30.0,
            mttr_minutes=10.0,
            change_failure_rate=0.02,
        )
        classification = gen.classify_dora_performance(metrics)
        assert classification["deployment_frequency"]["class"] == "Elite"
        assert classification["change_failure_rate"]["class"] == "Elite"

    def test_low_classification(self):
        gen = CICDPipelineGenerator()
        metrics = DORAMetrics(
            deployment_frequency_per_day=0.01,
            lead_time_minutes=50000.0,
            mttr_minutes=500.0,
            change_failure_rate=0.5,
        )
        classification = gen.classify_dora_performance(metrics)
        assert classification["deployment_frequency"]["class"] == "Low"


class TestSecurityGate:
    def test_no_critical_findings_passes(self):
        gen = CICDPipelineGenerator()
        scans = [
            SecurityScanResult("Trivy", SecurityScanStatus.PASS),
            SecurityScanResult("Checkov", SecurityScanStatus.PASS),
        ]
        result = gen.run_security_gate(scans)
        assert result["passed"] is True
        assert result["blocking_scans"] == []

    def test_critical_trivy_finding_blocks(self):
        gen = CICDPipelineGenerator()
        scans = [
            SecurityScanResult("Trivy", SecurityScanStatus.FAIL, critical_count=2),
            SecurityScanResult("Checkov", SecurityScanStatus.PASS),
        ]
        result = gen.run_security_gate(scans)
        assert result["passed"] is False
        assert "Trivy" in result["blocking_scans"]

    def test_high_severity_only_warns(self):
        gen = CICDPipelineGenerator()
        scans = [
            SecurityScanResult("Checkov", SecurityScanStatus.FAIL, critical_count=0, high_count=3),
        ]
        result = gen.run_security_gate(scans)
        assert result["passed"] is True  # No CRITICAL findings
        assert "Checkov" in result["warning_scans"]

    def test_total_counts_aggregated(self):
        gen = CICDPipelineGenerator()
        scans = [
            SecurityScanResult("Trivy", SecurityScanStatus.FAIL, critical_count=1, high_count=2),
            SecurityScanResult("Checkov", SecurityScanStatus.FAIL, critical_count=0, high_count=3),
        ]
        result = gen.run_security_gate(scans)
        assert result["total_critical"] == 1
        assert result["total_high"] == 5
