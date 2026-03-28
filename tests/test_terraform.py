"""
Tests for Terraform runner — NMI GCP Payments DevOps POC.
Covers plan/apply/destroy operations, remote state config, OPA policy validation,
drift detection, and PCI-DSS compliance checks.
"""

import pytest
import tempfile
import os
from gcp.terraform_runner import (
    TerraformRunner,
    RemoteStateConfig,
    TerraformBackendType,
    OPAPolicyEngine,
    OPAPolicyResult,
    TerraformPlanResult,
    TerraformApplyResult,
    TerraformOperationStatus,
    DriftReport,
)


# ─────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────

@pytest.fixture
def tmp_dir():
    with tempfile.TemporaryDirectory() as d:
        yield d


@pytest.fixture
def runner(tmp_dir):
    return TerraformRunner(working_dir=tmp_dir, dry_run=True)


@pytest.fixture
def runner_with_remote_state(tmp_dir):
    state = RemoteStateConfig(
        backend_type=TerraformBackendType.GCS,
        bucket="nmi-terraform-state",
        prefix="payments/prod",
        project="nmi-payments-prod",
    )
    return TerraformRunner(working_dir=tmp_dir, remote_state=state, dry_run=True)


@pytest.fixture
def opa():
    return OPAPolicyEngine()


@pytest.fixture
def gke_resource():
    return {
        "type": "google_container_cluster",
        "labels": {
            "env": "prod",
            "project": "nmi-payments",
            "team": "platform",
            "cost-center": "eng-001",
        },
        "private_cluster_config": {"enable_private_nodes": True},
    }


@pytest.fixture
def sql_resource():
    return {
        "type": "google_sql_database_instance",
        "labels": {
            "env": "prod",
            "project": "nmi-payments",
            "team": "platform",
            "cost-center": "eng-001",
        },
        "ip_configuration": {"ipv4_enabled": False},
        "disk_encryption_configuration": {
            "kms_key_name": "projects/nmi/locations/eur/keyRings/kr/cryptoKeys/key"
        },
    }


# ─────────────────────────────────────────
# TerraformRunner init
# ─────────────────────────────────────────

class TestTerraformRunnerInit:
    def test_init_sets_working_dir(self, tmp_dir):
        r = TerraformRunner(working_dir=tmp_dir)
        assert r.working_dir == tmp_dir

    def test_init_dry_run_default(self, tmp_dir):
        r = TerraformRunner(working_dir=tmp_dir)
        assert r.dry_run is True

    def test_init_auto_approve_false_default(self, tmp_dir):
        r = TerraformRunner(working_dir=tmp_dir)
        assert r.auto_approve is False

    def test_init_with_remote_state(self, runner_with_remote_state):
        assert runner_with_remote_state.remote_state is not None

    def test_opa_engine_initialized(self, runner):
        assert runner.opa is not None

    def test_operation_log_empty_on_init(self, runner):
        assert runner.get_operation_log() == []


# ─────────────────────────────────────────
# Terraform init
# ─────────────────────────────────────────

class TestTerraformInit:
    def test_init_dry_run_returns_status(self, runner):
        result = runner.init()
        assert result["status"] == "DRY_RUN"

    def test_init_logs_operation(self, runner):
        runner.init()
        log = runner.get_operation_log()
        assert any(op["operation"] == "init" for op in log)


# ─────────────────────────────────────────
# Terraform plan
# ─────────────────────────────────────────

class TestTerraformPlan:
    def test_plan_returns_plan_result(self, runner):
        result = runner.plan()
        assert isinstance(result, TerraformPlanResult)

    def test_plan_dry_run_has_changes(self, runner):
        result = runner.plan()
        assert result.has_changes is True

    def test_plan_dry_run_status_success(self, runner):
        result = runner.plan()
        assert result.status == TerraformOperationStatus.SUCCESS

    def test_plan_dry_run_changes_add(self, runner):
        result = runner.plan()
        assert result.changes_add >= 0

    def test_plan_dry_run_no_destructions(self, runner):
        result = runner.plan()
        assert result.changes_destroy == 0

    def test_plan_summary_format(self, runner):
        result = runner.plan()
        summary = result.summary()
        assert "to add" in summary
        assert "to change" in summary
        assert "to destroy" in summary

    def test_plan_logs_operation(self, runner):
        runner.plan()
        log = runner.get_operation_log()
        assert any(op["operation"] == "plan" for op in log)

    def test_plan_with_out_file(self, runner, tmp_dir):
        out_file = os.path.join(tmp_dir, "tfplan")
        result = runner.plan(out=out_file)
        assert result.plan_file == out_file


# ─────────────────────────────────────────
# Terraform apply
# ─────────────────────────────────────────

class TestTerraformApply:
    def test_apply_dry_run_returns_result(self, runner):
        result = runner.apply()
        assert isinstance(result, TerraformApplyResult)

    def test_apply_dry_run_status_success(self, runner):
        result = runner.apply()
        assert result.status == TerraformOperationStatus.SUCCESS

    def test_apply_dry_run_resources_added(self, runner):
        result = runner.apply()
        assert result.resources_added >= 0

    def test_apply_dry_run_outputs(self, runner):
        result = runner.apply()
        assert "cluster_name" in result.outputs

    def test_apply_summary_format(self, runner):
        result = runner.apply()
        summary = result.summary()
        assert "added" in summary
        assert "changed" in summary
        assert "destroyed" in summary

    def test_apply_without_approval_raises(self, tmp_dir):
        r = TerraformRunner(working_dir=tmp_dir, dry_run=False, auto_approve=False)
        with pytest.raises(RuntimeError, match="auto_approve"):
            r.apply()

    def test_apply_logs_operation(self, runner):
        runner.apply()
        log = runner.get_operation_log()
        assert any(op["operation"] == "apply" for op in log)


# ─────────────────────────────────────────
# Terraform destroy
# ─────────────────────────────────────────

class TestTerraformDestroy:
    def test_destroy_dry_run_returns_result(self, runner):
        result = runner.destroy()
        assert isinstance(result, TerraformApplyResult)

    def test_destroy_dry_run_status_success(self, runner):
        result = runner.destroy()
        assert result.status == TerraformOperationStatus.SUCCESS

    def test_destroy_dry_run_resources_destroyed(self, runner):
        result = runner.destroy()
        assert result.resources_destroyed >= 0

    def test_destroy_without_approval_raises(self, tmp_dir):
        r = TerraformRunner(working_dir=tmp_dir, dry_run=False, auto_approve=False)
        with pytest.raises(RuntimeError, match="auto_approve"):
            r.destroy()

    def test_destroy_with_target(self, runner):
        result = runner.destroy(target="google_container_cluster.payments")
        assert result.status == TerraformOperationStatus.SUCCESS

    def test_destroy_logs_operation(self, runner):
        runner.destroy()
        log = runner.get_operation_log()
        assert any(op["operation"] == "destroy" for op in log)


# ─────────────────────────────────────────
# Remote state configuration
# ─────────────────────────────────────────

class TestRemoteStateConfig:
    def test_gcs_backend_validation_passes(self):
        state = RemoteStateConfig(
            backend_type=TerraformBackendType.GCS,
            bucket="my-bucket",
            prefix="prod/payments",
        )
        assert state.validate() == []

    def test_missing_bucket_invalid(self):
        state = RemoteStateConfig(TerraformBackendType.GCS, bucket="", prefix="pref")
        errors = state.validate()
        assert any("bucket" in e for e in errors)

    def test_missing_prefix_invalid(self):
        state = RemoteStateConfig(TerraformBackendType.GCS, bucket="bucket", prefix="")
        errors = state.validate()
        assert any("prefix" in e for e in errors)

    def test_gcs_to_hcl_contains_bucket(self):
        state = RemoteStateConfig(
            TerraformBackendType.GCS, "my-bucket", "prod/payments", "my-proj"
        )
        hcl = state.to_hcl()
        assert "my-bucket" in hcl

    def test_gcs_to_hcl_contains_prefix(self):
        state = RemoteStateConfig(
            TerraformBackendType.GCS, "my-bucket", "prod/payments"
        )
        hcl = state.to_hcl()
        assert "prod/payments" in hcl

    def test_gcs_to_hcl_contains_project(self):
        state = RemoteStateConfig(
            TerraformBackendType.GCS, "bucket", "prefix", project="my-proj"
        )
        hcl = state.to_hcl()
        assert "my-proj" in hcl

    def test_validate_remote_state_no_config(self, runner):
        warnings = runner.validate_remote_state_config()
        assert any("local state" in w for w in warnings)

    def test_validate_remote_state_with_config(self, runner_with_remote_state):
        errors = runner_with_remote_state.validate_remote_state_config()
        assert errors == []


# ─────────────────────────────────────────
# OPA policy validation
# ─────────────────────────────────────────

class TestOPAPolicyValidation:
    def test_required_tags_passes(self, opa, gke_resource):
        result = opa.validate_required_tags(gke_resource)
        assert result.passed is True
        assert result.violations == []

    def test_required_tags_fails_missing_labels(self, opa):
        resource = {"type": "google_container_cluster", "labels": {"env": "prod"}}
        result = opa.validate_required_tags(resource)
        assert result.passed is False
        assert len(result.violations) > 0

    def test_required_tags_lists_missing_fields(self, opa):
        resource = {"type": "some_resource", "labels": {}}
        result = opa.validate_required_tags(resource)
        assert any("project" in v for v in result.violations)

    def test_private_networking_gke_passes(self, opa, gke_resource):
        result = opa.validate_private_networking(gke_resource)
        assert result.passed is True

    def test_private_networking_gke_fails_public_nodes(self, opa):
        resource = {
            "type": "google_container_cluster",
            "private_cluster_config": {"enable_private_nodes": False},
            "labels": {},
        }
        result = opa.validate_private_networking(resource)
        assert result.passed is False

    def test_private_networking_sql_passes_no_public_ip(self, opa, sql_resource):
        result = opa.validate_private_networking(sql_resource)
        assert result.passed is True

    def test_private_networking_sql_fails_public_ip(self, opa):
        resource = {
            "type": "google_sql_database_instance",
            "ip_configuration": {"ipv4_enabled": True},
            "labels": {},
        }
        result = opa.validate_private_networking(resource)
        assert result.passed is False

    def test_encryption_at_rest_sql_passes(self, opa, sql_resource):
        result = opa.validate_encryption_at_rest(sql_resource)
        assert result.passed is True

    def test_encryption_at_rest_sql_fails_no_kms(self, opa):
        resource = {
            "type": "google_sql_database_instance",
            "disk_encryption_configuration": {},
            "labels": {},
        }
        result = opa.validate_encryption_at_rest(resource)
        assert result.passed is False

    def test_encryption_at_rest_gcs_fails_no_kms(self, opa):
        resource = {
            "type": "google_storage_bucket",
            "encryption": {},
            "labels": {},
        }
        result = opa.validate_encryption_at_rest(resource)
        assert result.passed is False

    def test_audit_logging_passes(self, opa):
        resource = {
            "type": "google_project_iam_audit_config",
            "audit_log_config": [
                {"log_type": "ADMIN_READ"},
                {"log_type": "DATA_READ"},
                {"log_type": "DATA_WRITE"},
            ],
            "labels": {},
        }
        result = opa.validate_audit_logging(resource)
        assert result.passed is True

    def test_audit_logging_fails_missing_type(self, opa):
        resource = {
            "type": "google_project_iam_audit_config",
            "audit_log_config": [{"log_type": "ADMIN_READ"}],
            "labels": {},
        }
        result = opa.validate_audit_logging(resource)
        assert result.passed is False

    def test_opa_policy_result_to_dict(self):
        result = OPAPolicyResult(
            policy_name="test_policy",
            passed=True,
            violations=[],
            warnings=["minor warning"],
        )
        d = result.to_dict()
        assert d["policy"] == "test_policy"
        assert d["passed"] is True

    def test_validate_plan_returns_list(self, opa):
        plan = {
            "resource_changes": [
                {
                    "type": "google_container_cluster",
                    "change": {
                        "after": {
                            "labels": {
                                "env": "prod",
                                "project": "nmi",
                                "team": "platform",
                                "cost-center": "eng",
                            },
                            "private_cluster_config": {"enable_private_nodes": True},
                        }
                    }
                }
            ]
        }
        results = opa.validate_plan(plan)
        assert isinstance(results, list)
        assert len(results) > 0

    def test_custom_policy_registered_and_executed(self, opa):
        def custom_policy(resource):
            return OPAPolicyResult(
                policy_name="custom_test",
                passed=True,
                violations=[],
            )

        opa.add_policy(custom_policy)
        plan = {
            "resource_changes": [
                {
                    "type": "google_container_cluster",
                    "change": {"after": {"labels": {}}}
                }
            ]
        }
        results = opa.validate_plan(plan)
        custom_results = [r for r in results if r.policy_name == "custom_test"]
        assert len(custom_results) == 1


# ─────────────────────────────────────────
# Drift detection
# ─────────────────────────────────────────

class TestDriftDetection:
    def test_detect_drift_returns_report(self, runner):
        report = runner.detect_drift()
        assert isinstance(report, DriftReport)

    def test_detect_drift_dry_run_no_drift(self, runner):
        report = runner.detect_drift()
        assert report.has_drift is False

    def test_drift_report_to_dict(self):
        report = DriftReport(
            drifted_resources=["resource_a"],
            missing_resources=[],
            extra_resources=["resource_b"],
        )
        d = report.to_dict()
        assert d["has_drift"] is True
        assert d["total_issues"] == 2

    def test_empty_drift_report(self):
        report = DriftReport()
        assert report.has_drift is False

    def test_drift_report_missing_resources(self):
        report = DriftReport(missing_resources=["gke-cluster"])
        assert report.has_drift is True
        assert "gke-cluster" in report.missing_resources


# ─────────────────────────────────────────
# Terraform outputs
# ─────────────────────────────────────────

class TestTerraformOutputs:
    def test_get_outputs_dry_run(self, runner):
        outputs = runner.get_outputs()
        assert isinstance(outputs, dict)

    def test_get_outputs_contains_cluster_name(self, runner):
        outputs = runner.get_outputs()
        assert "cluster_name" in outputs

    def test_get_outputs_contains_project_id(self, runner):
        outputs = runner.get_outputs()
        assert "project_id" in outputs


# ─────────────────────────────────────────
# TerraformPlanResult helpers
# ─────────────────────────────────────────

class TestTerraformPlanResultHelpers:
    def test_has_changes_true(self):
        result = TerraformPlanResult(changes_add=1)
        assert result.has_changes is True

    def test_has_changes_false(self):
        result = TerraformPlanResult()
        assert result.has_changes is False

    def test_has_destructions_true(self):
        result = TerraformPlanResult(changes_destroy=2)
        assert result.has_destructions is True

    def test_has_destructions_false(self):
        result = TerraformPlanResult(changes_add=3)
        assert result.has_destructions is False


# ─────────────────────────────────────────
# Operation log
# ─────────────────────────────────────────

class TestOperationLog:
    def test_multiple_operations_all_logged(self, runner):
        runner.init()
        runner.plan()
        runner.apply()
        log = runner.get_operation_log()
        ops = [entry["operation"] for entry in log]
        assert "init" in ops
        assert "plan" in ops
        assert "apply" in ops

    def test_operation_log_returns_copy(self, runner):
        runner.plan()
        log1 = runner.get_operation_log()
        log1.clear()
        log2 = runner.get_operation_log()
        assert len(log2) == 1
