"""Tests for Cloud SQL Manager — NMI Payments Platform."""
import pytest
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

import time
from cloud_sql_manager import (
    CloudSQLManager, CloudSQLInstance, DatabaseBackup, ReadReplica,
    InstanceTier, BackupStatus, ReplicationStatus
)


def make_instance(name="nmi-payments-db", ssl=True, kms="key", private="vpc-main",
                  del_protect=True, pitr=True, ha=True):
    return CloudSQLInstance(
        name=name, project="nmi-prod", region="europe-west2",
        tier=InstanceTier.DB_N1_STANDARD_4, require_ssl=ssl,
        kms_key=kms, private_network=private, deletion_protection=del_protect,
        point_in_time_recovery=pitr, ha_enabled=ha,
    )


def make_backup(backup_id="bkp-001", age_hours=12, size_bytes=1024*1024*100, btype="AUTOMATED"):
    backup_time = time.time() - (age_hours * 3600)
    return DatabaseBackup(
        backup_id=backup_id, instance="nmi-payments-db",
        backup_time=backup_time, size_bytes=size_bytes, backup_type=btype,
    )


# PCI-DSS control tests
class TestPCIDSSControls:
    def test_fully_compliant_instance(self):
        instance = make_instance()
        mgr = CloudSQLManager(instance)
        result = mgr.check_pci_dss_controls()
        assert result["compliant"] is True
        assert len(result["blocking_findings"]) == 0
        assert result["passed_count"] == 6

    def test_no_ssl_blocks(self):
        instance = make_instance(ssl=False)
        mgr = CloudSQLManager(instance)
        result = mgr.check_pci_dss_controls()
        assert result["compliant"] is False
        rules = [f["rule"] for f in result["blocking_findings"]]
        assert "require_ssl" in rules

    def test_no_kms_blocks(self):
        instance = make_instance(kms="")
        mgr = CloudSQLManager(instance)
        result = mgr.check_pci_dss_controls()
        assert result["compliant"] is False
        rules = [f["rule"] for f in result["blocking_findings"]]
        assert "kms_encryption" in rules

    def test_no_private_network_blocks(self):
        instance = make_instance(private="")
        mgr = CloudSQLManager(instance)
        result = mgr.check_pci_dss_controls()
        assert result["compliant"] is False
        rules = [f["rule"] for f in result["blocking_findings"]]
        assert "private_network" in rules

    def test_no_deletion_protection_fails(self):
        instance = make_instance(del_protect=False)
        mgr = CloudSQLManager(instance)
        result = mgr.check_pci_dss_controls()
        findings = [f["rule"] for f in result["findings"]]
        assert "deletion_protection" in findings

    def test_no_pitr_fails(self):
        instance = make_instance(pitr=False)
        mgr = CloudSQLManager(instance)
        result = mgr.check_pci_dss_controls()
        findings = [f["rule"] for f in result["findings"]]
        assert "pitr_enabled" in findings


# Backup validation tests
class TestBackupValidation:
    def test_fresh_backup_valid(self):
        instance = make_instance()
        mgr = CloudSQLManager(instance)
        backup = make_backup(age_hours=6)
        result = mgr.validate_backup(backup)
        assert result["status"] == BackupStatus.VALID.value
        assert result["rpo_compliant"] is True

    def test_old_backup_stale(self):
        instance = make_instance()
        mgr = CloudSQLManager(instance)
        backup = make_backup(age_hours=50)
        result = mgr.validate_backup(backup)
        assert result["status"] == BackupStatus.STALE.value
        assert result["rpo_compliant"] is False

    def test_tiny_backup_invalid(self):
        instance = make_instance()
        mgr = CloudSQLManager(instance)
        backup = make_backup(size_bytes=100)
        result = mgr.validate_backup(backup)
        assert result["status"] == BackupStatus.INVALID.value

    def test_no_backups_missing(self):
        instance = make_instance()
        mgr = CloudSQLManager(instance)
        result = mgr.validate_all_backups()
        assert result["status"] == BackupStatus.MISSING.value
        assert result["backup_count"] == 0

    def test_multiple_backups_validated(self):
        instance = make_instance()
        mgr = CloudSQLManager(instance)
        mgr.backups = [make_backup("b1", 6), make_backup("b2", 12)]
        result = mgr.validate_all_backups()
        assert result["valid_count"] == 2
        assert result["backup_count"] == 2


# Replication health tests
class TestReplicationHealth:
    def test_healthy_replica(self):
        instance = make_instance()
        mgr = CloudSQLManager(instance)
        mgr.replicas = [ReadReplica("replica-1", "nmi-payments-db", "europe-west1", replication_lag_seconds=2.0)]
        results = mgr.check_replication_health()
        assert results[0]["status"] == ReplicationStatus.HEALTHY.value

    def test_lag_warning(self):
        instance = make_instance()
        mgr = CloudSQLManager(instance)
        mgr.replicas = [ReadReplica("replica-1", "nmi-payments-db", "europe-west1", replication_lag_seconds=20.0)]
        results = mgr.check_replication_health()
        assert results[0]["status"] == ReplicationStatus.LAG_WARNING.value

    def test_lag_critical(self):
        instance = make_instance()
        mgr = CloudSQLManager(instance)
        mgr.replicas = [ReadReplica("replica-1", "nmi-payments-db", "europe-west1", replication_lag_seconds=120.0)]
        results = mgr.check_replication_health()
        assert results[0]["status"] == ReplicationStatus.LAG_CRITICAL.value

    def test_unavailable_replica_broken(self):
        instance = make_instance()
        mgr = CloudSQLManager(instance)
        mgr.replicas = [ReadReplica("replica-1", "nmi-payments-db", "europe-west1", available=False)]
        results = mgr.check_replication_health()
        assert results[0]["status"] == ReplicationStatus.REPLICATION_BROKEN.value

    def test_no_replicas_empty_list(self):
        instance = make_instance()
        mgr = CloudSQLManager(instance)
        results = mgr.check_replication_health()
        assert results == []


# Connection pool tests
class TestConnectionPool:
    def test_saturated_pool(self):
        instance = make_instance()
        mgr = CloudSQLManager(instance)
        result = mgr.get_connection_pool_recommendation(current_connections=95, max_connections=100)
        assert result["classification"] == "SATURATED"

    def test_optimal_pool(self):
        instance = make_instance()
        mgr = CloudSQLManager(instance)
        result = mgr.get_connection_pool_recommendation(current_connections=75, max_connections=100)
        assert result["classification"] == "OPTIMAL"

    def test_over_provisioned_pool(self):
        instance = make_instance()
        mgr = CloudSQLManager(instance)
        result = mgr.get_connection_pool_recommendation(current_connections=20, max_connections=100)
        assert result["classification"] == "OVER_PROVISIONED"

    def test_healthy_pool(self):
        instance = make_instance()
        mgr = CloudSQLManager(instance)
        result = mgr.get_connection_pool_recommendation(current_connections=50, max_connections=100)
        assert result["classification"] == "HEALTHY"


# Terraform HCL tests
class TestTerraformHCL:
    def test_generates_valid_hcl(self):
        instance = make_instance()
        mgr = CloudSQLManager(instance)
        hcl = mgr.generate_terraform_hcl()
        assert "google_sql_database_instance" in hcl
        assert "REGIONAL" in hcl
        assert "point_in_time_recovery_enabled = true" in hcl
        assert "require_ssl     = true" in hcl
        assert "ipv4_enabled    = false" in hcl

    def test_kms_key_in_hcl(self):
        instance = make_instance(kms="projects/nmi-prod/locations/europe-west2/keyRings/payments/cryptoKeys/db-key")
        mgr = CloudSQLManager(instance)
        hcl = mgr.generate_terraform_hcl()
        assert "disk_encryption" in hcl
        assert "payments" in hcl
