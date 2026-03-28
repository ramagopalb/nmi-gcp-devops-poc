# NMI GCP DevOps POC

**Proof-of-concept demonstrating Senior DevOps Engineer (GCP) capabilities for NMI — a global payments enablement platform.**

This POC simulates the GCP-based infrastructure, CI/CD, PCI-DSS compliance automation, and observability stack required for NMI's payments platform.

## What This Demonstrates

- **GCP Infrastructure (Terraform):** GKE private cluster (Workload Identity, Cloud KMS, VPC Service Controls), Cloud SQL PostgreSQL (HA REGIONAL, PITR), Pub/Sub payment event pipelines, Artifact Registry, Cloud Run microservices
- **PCI-DSS Compliance Automation:** OPA/Rego policy-as-code (encryption-at-rest, no-public-endpoints, audit-log-enabled, required-labels), Binary Authorization config, Cloud KMS key management
- **CI/CD Pipeline (GitHub Actions):** Security gates (Trivy container scan, Checkov IaC scan, OPA conftest), Docker BuildKit GCS cache, canary GKE deployment with Prometheus payment success-rate rollback gate, DORA metrics
- **Payments Observability:** Prometheus alert rules (transaction success rate SLO, P99 payment latency, GKE NodeNotReady, Cloud SQL replication lag, Pub/Sub subscription backlog), multi-window SLO burn-rate alerting, Grafana dashboard builder
- **Payment Platform Automation:** Pub/Sub event processor (payment submitted/authorised/settled/failed states), GKE cluster health manager, Cloud SQL backup validator, incident runbook executor
- **80+ pytest tests** validating all components

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Cloud | GCP (GKE, Cloud SQL, Pub/Sub, Cloud Run, Cloud Build, Cloud Armor, Secret Manager, Cloud KMS) |
| IaC | Terraform, OPA/Rego policy-as-code |
| CI/CD | GitHub Actions, Trivy, Checkov, Binary Authorization |
| Containers | Kubernetes (GKE), Helm, Docker |
| Observability | Prometheus, Grafana, OpenTelemetry |
| Security | PCI-DSS, Cloud KMS, VPC Service Controls, Binary Authorization |
| Languages | Python, HCL, YAML |

## Repository Structure

```
nmi-gcp-devops-poc/
├── README.md
├── requirements.txt
├── .gitignore
├── terraform/
│   ├── gke_cluster.tf          # GKE private cluster with Workload Identity
│   ├── cloud_sql.tf            # Cloud SQL PostgreSQL HA REGIONAL
│   ├── pubsub.tf               # Pub/Sub topics and subscriptions
│   ├── cloud_run.tf            # Cloud Run payment microservice
│   ├── iam.tf                  # IAM, Workload Identity, service accounts
│   └── variables.tf
├── opa/
│   └── pci_dss_policy.rego     # OPA/Rego PCI-DSS compliance policies
├── .github/
│   └── workflows/
│       └── ci_cd.yml           # GitHub Actions CI/CD pipeline
├── src/
│   ├── gke_manager.py          # GKE cluster health & operations manager
│   ├── pubsub_processor.py     # Pub/Sub payment event processor
│   ├── cloud_sql_manager.py    # Cloud SQL health, backup validation
│   ├── pci_compliance.py       # PCI-DSS compliance checker
│   ├── prometheus_rules.py     # Prometheus alert rules generator
│   ├── grafana_dashboards.py   # Grafana dashboard builder
│   ├── cicd_pipeline.py        # CI/CD pipeline config generator
│   └── incident_runbook.py     # Incident response automation
└── tests/
    ├── test_gke_manager.py
    ├── test_pubsub_processor.py
    ├── test_cloud_sql_manager.py
    ├── test_pci_compliance.py
    ├── test_prometheus_rules.py
    ├── test_grafana_dashboards.py
    ├── test_cicd_pipeline.py
    └── test_incident_runbook.py
```

## Running Tests

```bash
pip install -r requirements.txt
pytest tests/ -v
```

## Key Highlights

- **GKE Private Cluster:** Workload Identity (SA-per-pod), Cloud KMS encryption, VPC Service Controls, private endpoint only — PCI-DSS compliant
- **Cloud SQL HA:** PostgreSQL REGIONAL HA, automated PITR backups, read replica, query insights — payments data durability
- **Pub/Sub Payments Pipeline:** Payment event routing (submitted → authorised → settled/failed), dead-letter queues, message ordering, retry policies
- **OPA/Rego PCI-DSS:** 8 policy rules covering encryption, network, logging, access — automated in CI/CD gating
- **SLO Alerting:** 3 SLOs (payment success rate 99.9%, gateway latency P99, API error rate) × 3 windows = 9 burn-rate alerts following Google SRE workbook
- **DORA Metrics:** Deployment frequency, lead time, MTTR, change failure rate — all tracked in CI/CD

## Author

Ram Gopal Reddy Basireddy | [LinkedIn](https://www.linkedin.com/in/ram-ba-29b110261/) | [GitHub](https://github.com/ramagopalb)
