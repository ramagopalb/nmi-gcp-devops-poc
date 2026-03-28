"""
Cloud SQL Manager for NMI Payments Platform.
Manages Cloud SQL PostgreSQL HA REGIONAL, backup validation, and health monitoring.
"""
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from enum import Enum
import time


class InstanceTier(Enum):
    DB_N1_STANDARD_2 = "db-n1-standard-2"
    DB_N1_STANDARD_4 = "db-n1-standard-4"
    DB_N1_STANDARD_8 = "db-n1-standard-8"
    DB_CUSTOM_4_15360 = "db-custom-4-15360"


class BackupStatus(Enum):
    VALID = "VALID"
    STALE = "STALE"
    INVALID = "INVALID"
    MISSING = "MISSING"


class ReplicationStatus(Enum):
    HEALTHY = "healthy"
    LAG_WARNING = "lag_warning"
    LAG_CRITICAL = "lag_critical"
    REPLICATION_BROKEN = "replication_broken"


@dataclass
class CloudSQLInstance:
    name: str
    project: str
    region: str
    tier: InstanceTier
    database_version: str = "POSTGRES_15"
    ha_enabled: bool = True
    point_in_time_recovery: bool = True
    backup_retention_days: int = 14
    deletion_protection: bool = True
    require_ssl: bool = True
    private_network: str = ""
    kms_key: str = ""
    query_insights_enabled: bool = True


@dataclass
class DatabaseBackup:
    backup_id: str
    instance: str
    backup_time: float  # unix timestamp
    size_bytes: int
    backup_type: str  # "AUTOMATED" or "ON_DEMAND"
    location: str = "europe-west2"


@dataclass
class ReadReplica:
    name: str
    primary: str
    region: str
    replication_lag_seconds: float = 0.0
    available: bool = True


class CloudSQLManager:
    """Manages Cloud SQL for NMI's PCI-DSS compliant payments database."""

    def __init__(self, instance: CloudSQLInstance):
        self.instance = instance
        self.backups: List[DatabaseBackup] = []
        self.replicas: List[ReadReplica] = []

    def check_pci_dss_controls(self) -> Dict:
        """Verify PCI-DSS required Cloud SQL controls."""
        findings = []
        passed = []

        if self.instance.require_ssl:
            passed.append("require_ssl: PASS")
        else:
            findings.append({"rule": "require_ssl", "severity": "CRITICAL", "msg": "SSL required for all database connections (PCI-DSS req 4.1)"})

        if self.instance.kms_key:
            passed.append("kms_encryption: PASS")
        else:
            findings.append({"rule": "kms_encryption", "severity": "CRITICAL", "msg": "Cloud KMS encryption required for data at rest (PCI-DSS req 3.4)"})

        if self.instance.private_network:
            passed.append("private_network: PASS")
        else:
            findings.append({"rule": "private_network", "severity": "CRITICAL", "msg": "Private IP only — no public IP for payments DB (PCI-DSS req 1.3)"})

        if self.instance.deletion_protection:
            passed.append("deletion_protection: PASS")
        else:
            findings.append({"rule": "deletion_protection", "severity": "HIGH", "msg": "Deletion protection required for production payments DB"})

        if self.instance.point_in_time_recovery:
            passed.append("pitr_enabled: PASS")
        else:
            findings.append({"rule": "pitr_enabled", "severity": "HIGH", "msg": "PITR required for RPO compliance in payments data"})

        if self.instance.ha_enabled:
            passed.append("ha_regional: PASS")
        else:
            findings.append({"rule": "ha_regional", "severity": "HIGH", "msg": "HA REGIONAL required for payment availability SLO"})

        blocking = [f for f in findings if f["severity"] == "CRITICAL"]
        return {
            "compliant": len(blocking) == 0,
            "passed_count": len(passed),
            "findings": findings,
            "blocking_findings": blocking,
            "passed": passed,
        }

    def validate_backup(self, backup: DatabaseBackup) -> Dict:
        """Validate a database backup for freshness and integrity."""
        now = time.time()
        age_hours = (now - backup.backup_time) / 3600

        if age_hours > 48:
            status = BackupStatus.STALE
            msg = f"Backup is {age_hours:.1f}h old — exceeds 48h threshold"
        elif backup.size_bytes < 1024:
            status = BackupStatus.INVALID
            msg = f"Backup size {backup.size_bytes} bytes is suspiciously small"
        else:
            status = BackupStatus.VALID
            msg = "Backup valid"

        return {
            "backup_id": backup.backup_id,
            "status": status.value,
            "age_hours": age_hours,
            "size_bytes": backup.size_bytes,
            "message": msg,
            "rpo_compliant": age_hours <= 24,
        }

    def validate_all_backups(self) -> Dict:
        """Validate all backups and return summary."""
        if not self.backups:
            return {
                "status": BackupStatus.MISSING.value,
                "backup_count": 0,
                "valid_count": 0,
                "message": "No backups found",
            }
        results = [self.validate_backup(b) for b in self.backups]
        valid = [r for r in results if r["status"] == BackupStatus.VALID.value]
        return {
            "status": BackupStatus.VALID.value if valid else BackupStatus.INVALID.value,
            "backup_count": len(self.backups),
            "valid_count": len(valid),
            "results": results,
        }

    def check_replication_health(self) -> List[Dict]:
        """Check read replica replication health."""
        results = []
        for replica in self.replicas:
            lag = replica.replication_lag_seconds
            if not replica.available:
                status = ReplicationStatus.REPLICATION_BROKEN
            elif lag > 60:
                status = ReplicationStatus.LAG_CRITICAL
            elif lag > 10:
                status = ReplicationStatus.LAG_WARNING
            else:
                status = ReplicationStatus.HEALTHY
            results.append({
                "replica": replica.name,
                "region": replica.region,
                "lag_seconds": lag,
                "status": status.value,
                "available": replica.available,
            })
        return results

    def get_connection_pool_recommendation(self, current_connections: int, max_connections: int) -> Dict:
        """Recommend connection pool settings based on current usage."""
        usage_ratio = current_connections / max_connections if max_connections > 0 else 0

        if usage_ratio > 0.9:
            classification = "SATURATED"
            recommendation = "Urgent: increase max_connections or add read replicas"
        elif usage_ratio > 0.7:
            classification = "OPTIMAL"
            recommendation = "Monitor — approaching saturation threshold"
        elif usage_ratio < 0.3:
            classification = "OVER_PROVISIONED"
            recommendation = "Consider downsizing instance tier to reduce cost"
        else:
            classification = "HEALTHY"
            recommendation = "Connection pool healthy"

        return {
            "current_connections": current_connections,
            "max_connections": max_connections,
            "usage_ratio": usage_ratio,
            "classification": classification,
            "recommendation": recommendation,
        }

    def generate_terraform_hcl(self) -> str:
        """Generate Terraform HCL for Cloud SQL instance."""
        hcl = f'''resource "google_sql_database_instance" "{self.instance.name}" {{
  name             = "{self.instance.name}"
  project          = "{self.instance.project}"
  region           = "{self.instance.region}"
  database_version = "{self.instance.database_version}"
  deletion_protection = {str(self.instance.deletion_protection).lower()}

  settings {{
    tier = "{self.instance.tier.value}"

    availability_type = "REGIONAL"

    backup_configuration {{
      enabled                        = true
      point_in_time_recovery_enabled = {str(self.instance.point_in_time_recovery).lower()}
      backup_retention_settings {{
        retained_backups = {self.instance.backup_retention_days}
        retention_unit   = "COUNT"
      }}
    }}

    ip_configuration {{
      ipv4_enabled    = false
      private_network = "{self.instance.private_network}"
      require_ssl     = {str(self.instance.require_ssl).lower()}
    }}

    insights_config {{
      query_insights_enabled = {str(self.instance.query_insights_enabled).lower()}
      query_string_length    = 1024
      record_application_tags = true
      record_client_address   = false
    }}
'''
        if self.instance.kms_key:
            hcl += f'''
    disk_encryption {{
      kms_key_name = "{self.instance.kms_key}"
    }}
'''
        hcl += "  }\n}\n"
        return hcl
