"""Tests for PCI-DSS Compliance Checker — NMI Payments Platform."""
import pytest
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from pci_compliance import (
    PCIDSSComplianceChecker, AuditTrailManager, InfrastructureResource,
    ComplianceStatus, Severity
)


def make_resource(name="nmi-payments-db", rtype="cloud_sql",
                  enc="projects/nmi/keys/db", public=False, audit=True,
                  ssl=True, private=True,
                  labels=None):
    if labels is None:
        labels = {"env": "prod", "team": "payments", "data-classification": "pci", "cost-centre": "eng"}
    return InfrastructureResource(
        resource_type=rtype, name=name, project="nmi-prod",
        labels=labels, encryption_key=enc, public_access_enabled=public,
        audit_log_enabled=audit, ssl_required=ssl, private_only=private,
    )


# Compliance checker tests
class TestPCIComplianceChecker:
    def test_fully_compliant_resource(self):
        checker = PCIDSSComplianceChecker()
        resource = make_resource()
        findings = checker.check_resource(resource)
        failed = [f for f in findings if f.status == "FAIL"]
        assert len(failed) == 0

    def test_missing_encryption_fails(self):
        checker = PCIDSSComplianceChecker()
        resource = make_resource(enc="")
        findings = checker.check_resource(resource)
        failed_rules = [f.rule.rule_id for f in findings if f.status == "FAIL"]
        assert "PCI-3.4" in failed_rules

    def test_public_access_fails(self):
        checker = PCIDSSComplianceChecker()
        resource = make_resource(public=True, private=False)
        findings = checker.check_resource(resource)
        failed_rules = [f.rule.rule_id for f in findings if f.status == "FAIL"]
        assert "PCI-1.3" in failed_rules

    def test_no_audit_log_fails(self):
        checker = PCIDSSComplianceChecker()
        resource = make_resource(audit=False)
        findings = checker.check_resource(resource)
        failed_rules = [f.rule.rule_id for f in findings if f.status == "FAIL"]
        assert "PCI-10.1" in failed_rules

    def test_missing_labels_fails(self):
        checker = PCIDSSComplianceChecker()
        resource = make_resource(labels={"env": "prod"})  # missing team, data-classification, cost-centre
        findings = checker.check_resource(resource)
        failed_rules = [f.rule.rule_id for f in findings if f.status == "FAIL"]
        assert "PCI-2.2" in failed_rules

    def test_ssl_required_for_cloud_sql(self):
        checker = PCIDSSComplianceChecker()
        resource = make_resource(rtype="cloud_sql", ssl=False)
        findings = checker.check_resource(resource)
        failed_rules = [f.rule.rule_id for f in findings if f.status == "FAIL"]
        assert "PCI-4.1" in failed_rules

    def test_compliance_report_compliant(self):
        checker = PCIDSSComplianceChecker()
        resources = [make_resource("db"), make_resource("bucket", "gcs_bucket")]
        report = checker.generate_compliance_report(resources)
        assert report["status"] == ComplianceStatus.COMPLIANT.value
        assert report["pass_rate"] == 100.0

    def test_compliance_report_non_compliant(self):
        checker = PCIDSSComplianceChecker()
        resources = [make_resource(enc="", public=True, private=False)]
        report = checker.generate_compliance_report(resources)
        assert report["status"] == ComplianceStatus.NON_COMPLIANT.value
        assert report["blocking_findings"] > 0

    def test_compliance_report_resource_count(self):
        checker = PCIDSSComplianceChecker()
        resources = [make_resource(f"res-{i}") for i in range(4)]
        report = checker.generate_compliance_report(resources)
        assert report["resources_checked"] == 4


# OPA/Rego policy generation tests
class TestOPARegoPolicy:
    def test_rego_policy_generated(self):
        checker = PCIDSSComplianceChecker()
        policy = checker.generate_opa_rego_policy()
        assert "package nmi.pci_dss" in policy
        assert "deny[msg]" in policy
        assert "kms_key_name" in policy
        assert "public_access_enabled" in policy
        assert "audit_log_enabled" in policy
        assert "required_labels" in policy

    def test_rego_has_all_pci_requirements(self):
        checker = PCIDSSComplianceChecker()
        policy = checker.generate_opa_rego_policy()
        # Check for all major PCI requirements
        assert "PCI-3.4" in policy
        assert "PCI-4.1" in policy
        assert "PCI-1.3" in policy
        assert "PCI-10.1" in policy
        assert "PCI-2.2" in policy


# Binary Authorization tests
class TestBinaryAuthorization:
    def test_allowed_registry_passes(self):
        checker = PCIDSSComplianceChecker()
        allowed = ["europe-west2-docker.pkg.dev"]
        images = ["europe-west2-docker.pkg.dev/nmi-prod/payments/gateway@sha256:abc123"]
        results = checker.check_binary_authorization(images, allowed)
        assert results[0]["allowed"] is True
        assert results[0]["policy"] == "ENFORCE"

    def test_unknown_registry_blocked(self):
        checker = PCIDSSComplianceChecker()
        allowed = ["europe-west2-docker.pkg.dev"]
        images = ["docker.io/someimage:latest"]
        results = checker.check_binary_authorization(images, allowed)
        assert results[0]["allowed"] is False
        assert results[0]["policy"] == "BLOCK"

    def test_mixed_registries(self):
        checker = PCIDSSComplianceChecker()
        allowed = ["europe-west2-docker.pkg.dev"]
        images = [
            "europe-west2-docker.pkg.dev/nmi-prod/gateway:v1.0",
            "docker.io/malicious/image:latest",
        ]
        results = checker.check_binary_authorization(images, allowed)
        assert results[0]["allowed"] is True
        assert results[1]["allowed"] is False


# Audit trail tests
class TestAuditTrail:
    def test_record_pci_relevant_event(self):
        mgr = AuditTrailManager()
        event = mgr.record_event("config_change", "nmi-payments-db", "devops@nmi.com", {"change": "ssl enabled"})
        assert event["pci_relevant"] is True
        assert event["event_type"] == "config_change"

    def test_non_pci_event_not_relevant(self):
        mgr = AuditTrailManager()
        event = mgr.record_event("deployment", "payment-gateway", "ci-bot", {"version": "v1.2"})
        assert event["pci_relevant"] is False

    def test_get_pci_events_filtered(self):
        mgr = AuditTrailManager()
        mgr.record_event("config_change", "db", "admin", {})
        mgr.record_event("deployment", "svc", "bot", {})
        mgr.record_event("data_access", "db", "app", {})
        pci_events = mgr.get_pci_relevant_events()
        assert len(pci_events) == 2

    def test_audit_completeness_pass(self):
        mgr = AuditTrailManager()
        mgr.record_event("config_change", "db", "admin", {})
        mgr.record_event("access_granted", "kms", "iam", {})
        mgr.record_event("data_access", "db", "app", {})
        result = mgr.check_audit_completeness()
        assert result["complete"] is True
        assert result["missing_event_types"] == []

    def test_audit_completeness_missing(self):
        mgr = AuditTrailManager()
        mgr.record_event("deployment", "svc", "bot", {})
        result = mgr.check_audit_completeness()
        assert result["complete"] is False
        assert len(result["missing_event_types"]) > 0
