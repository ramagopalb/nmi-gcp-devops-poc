"""
CI/CD Pipeline Config Generator for NMI Payments Platform.
GitHub Actions with security gates, canary GKE deployments, DORA metrics.
"""
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from enum import Enum


class DeploymentStrategy(Enum):
    ROLLING = "rolling"
    CANARY = "canary"
    BLUE_GREEN = "blue_green"


class SecurityScanStatus(Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    SKIP = "SKIP"


class DeploymentStage(Enum):
    CANARY_10 = "canary_10_percent"
    CANARY_50 = "canary_50_percent"
    FULL = "full_100_percent"
    ROLLBACK = "rollback"


@dataclass
class SecurityScanResult:
    tool: str
    status: SecurityScanStatus
    critical_count: int = 0
    high_count: int = 0
    findings_url: str = ""


@dataclass
class DeploymentEvent:
    service: str
    version: str
    environment: str
    strategy: DeploymentStrategy
    stage: DeploymentStage
    success: bool
    error_rate_at_deploy: float = 0.0
    lead_time_minutes: float = 0.0
    triggered_rollback: bool = False


@dataclass
class DORAMetrics:
    deployment_frequency_per_day: float
    lead_time_minutes: float
    mttr_minutes: float
    change_failure_rate: float


class CICDPipelineGenerator:
    """Generates CI/CD pipeline configs for NMI's payments platform."""

    def __init__(self):
        self.deployments: List[DeploymentEvent] = []
        self.scan_results: List[SecurityScanResult] = []

    def generate_github_actions_workflow(self, service_name: str, gcp_project: str, cluster: str) -> str:
        """Generate GitHub Actions CI/CD workflow for a NMI payment service."""
        return f'''name: NMI {service_name} CI/CD Pipeline

on:
  push:
    branches: [main, staging]
  pull_request:
    branches: [main]

env:
  GCP_PROJECT: {gcp_project}
  GKE_CLUSTER: {cluster}
  GKE_REGION: europe-west2
  SERVICE_NAME: {service_name}
  ARTIFACT_REGISTRY: europe-west2-docker.pkg.dev/{gcp_project}/nmi-payments

jobs:
  security-gates:
    name: Security Gates
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Trivy Container Scan
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: ${{{{ env.ARTIFACT_REGISTRY }}}}/${{{{ env.SERVICE_NAME }}}}:${{{{ github.sha }}}}
          format: sarif
          output: trivy-results.sarif
          severity: CRITICAL,HIGH
          exit-code: 1

      - name: Checkov IaC Scan
        uses: bridgecrewio/checkov-action@master
        with:
          directory: terraform/
          framework: terraform
          output_format: sarif
          output_file_path: checkov-results.sarif

      - name: OPA PCI-DSS Policy Check
        run: |
          docker run --rm -v $(pwd):/workspace openpolicyagent/opa:latest \\
            eval --data /workspace/opa/pci_dss_policy.rego \\
            --input /workspace/terraform/plan.json \\
            "data.nmi.pci_dss.deny" \\
            --fail-defined

      - name: Binary Authorization Check
        run: |
          gcloud container binauthz attestations list \\
            --artifact-url="${{{{ env.ARTIFACT_REGISTRY }}}}/${{{{ env.SERVICE_NAME }}}}@${{{{ steps.build.outputs.digest }}}}"

  build-and-push:
    name: Build & Push
    runs-on: ubuntu-latest
    needs: security-gates
    outputs:
      image-digest: ${{{{ steps.build.outputs.digest }}}}
    steps:
      - uses: actions/checkout@v4

      - name: Authenticate to GCP
        uses: google-github-actions/auth@v2
        with:
          workload_identity_provider: projects/${{{{ env.GCP_PROJECT }}}}/locations/global/workloadIdentityPools/github-pool/providers/github-provider
          service_account: github-actions@{gcp_project}.iam.gserviceaccount.com

      - name: Configure Docker for Artifact Registry
        run: gcloud auth configure-docker europe-west2-docker.pkg.dev

      - name: Build with BuildKit (GCS cache)
        id: build
        uses: docker/build-push-action@v5
        with:
          context: .
          push: true
          tags: ${{{{ env.ARTIFACT_REGISTRY }}}}/${{{{ env.SERVICE_NAME }}}}:${{{{ github.sha }}}}
          cache-from: type=gcs,bucket={gcp_project}-buildcache,prefix=${{{{ env.SERVICE_NAME }}}}/
          cache-to: type=gcs,bucket={gcp_project}-buildcache,prefix=${{{{ env.SERVICE_NAME }}}}/,mode=max

  deploy-canary:
    name: Deploy Canary (10%)
    runs-on: ubuntu-latest
    needs: build-and-push
    if: github.ref == \'refs/heads/main\'
    steps:
      - uses: actions/checkout@v4

      - name: Authenticate to GCP
        uses: google-github-actions/auth@v2
        with:
          workload_identity_provider: projects/${{{{ env.GCP_PROJECT }}}}/locations/global/workloadIdentityPools/github-pool/providers/github-provider
          service_account: github-actions@{gcp_project}.iam.gserviceaccount.com

      - name: Get GKE credentials
        uses: google-github-actions/get-gke-credentials@v2
        with:
          cluster_name: ${{{{ env.GKE_CLUSTER }}}}
          location: ${{{{ env.GKE_REGION }}}}

      - name: Deploy canary 10%
        run: |
          kubectl set image deployment/${{{{ env.SERVICE_NAME }}}}-canary \\
            ${{{{ env.SERVICE_NAME }}}}=${{{{ env.ARTIFACT_REGISTRY }}}}/${{{{ env.SERVICE_NAME }}}}:${{{{ github.sha }}}}
          kubectl scale deployment/${{{{ env.SERVICE_NAME }}}}-canary --replicas=1

      - name: Wait 5 minutes and check payment success rate
        run: |
          sleep 300
          CANARY_ERROR_RATE=$(kubectl exec -n monitoring deploy/prometheus -- \\
            curl -s "localhost:9090/api/v1/query?query=rate(nmi_payment_transactions_total{{status='error',version='canary'}}[5m])/rate(nmi_payment_transactions_total{{version='canary'}}[5m])" \\
            | jq -r '.data.result[0].value[1]')
          echo "Canary error rate: $CANARY_ERROR_RATE"
          if (( $(echo "$CANARY_ERROR_RATE > 0.01" | bc -l) )); then
            echo "ERROR: Canary error rate exceeds 1% — rolling back"
            kubectl rollout undo deployment/${{{{ env.SERVICE_NAME }}}}-canary
            exit 1
          fi

  deploy-full:
    name: Deploy Full (100%)
    runs-on: ubuntu-latest
    needs: deploy-canary
    environment:
      name: production
      url: https://payments.nmi.com
    steps:
      - name: Promote canary to full rollout
        run: |
          kubectl set image deployment/${{{{ env.SERVICE_NAME }}}} \\
            ${{{{ env.SERVICE_NAME }}}}=${{{{ env.ARTIFACT_REGISTRY }}}}/${{{{ env.SERVICE_NAME }}}}:${{{{ github.sha }}}}
          kubectl rollout status deployment/${{{{ env.SERVICE_NAME }}}} --timeout=10m

      - name: Record DORA deployment frequency
        run: |
          curl -X POST http://pushgateway:9091/metrics/job/dora \\
            --data-binary "deployment_lead_time_seconds ${{{{ steps.timer.outputs.seconds }}}}"
'''

    def evaluate_canary_gate(self, deployment: DeploymentEvent, error_rate_threshold: float = 0.01) -> Dict:
        """Evaluate whether a canary deployment should proceed or rollback."""
        if deployment.error_rate_at_deploy > error_rate_threshold:
            action = "ROLLBACK"
            reason = f"Error rate {deployment.error_rate_at_deploy:.3f} exceeds threshold {error_rate_threshold}"
            passed = False
        else:
            action = "PROMOTE"
            reason = f"Error rate {deployment.error_rate_at_deploy:.3f} within threshold {error_rate_threshold}"
            passed = True

        return {
            "service": deployment.service,
            "version": deployment.version,
            "stage": deployment.stage.value,
            "action": action,
            "passed": passed,
            "error_rate": deployment.error_rate_at_deploy,
            "threshold": error_rate_threshold,
            "reason": reason,
        }

    def calculate_dora_metrics(self, deployments: List[DeploymentEvent]) -> DORAMetrics:
        """Calculate DORA metrics from deployment history."""
        if not deployments:
            return DORAMetrics(0, 0, 0, 0)

        # Deployment frequency (per day — assume 30 day window)
        successful = [d for d in deployments if d.success and not d.triggered_rollback]
        freq = len(successful) / 30.0

        # Lead time (average)
        lead_times = [d.lead_time_minutes for d in successful if d.lead_time_minutes > 0]
        avg_lead = sum(lead_times) / len(lead_times) if lead_times else 0

        # Change failure rate
        failures = [d for d in deployments if d.triggered_rollback or not d.success]
        cfr = len(failures) / len(deployments) if deployments else 0

        # MTTR (not in deployments — simulate)
        mttr = 15.0  # minutes

        return DORAMetrics(
            deployment_frequency_per_day=freq,
            lead_time_minutes=avg_lead,
            mttr_minutes=mttr,
            change_failure_rate=cfr,
        )

    def classify_dora_performance(self, metrics: DORAMetrics) -> Dict:
        """Classify DORA performance as Elite/High/Medium/Low."""
        # Deployment frequency
        if metrics.deployment_frequency_per_day >= 1:
            df_class = "Elite"
        elif metrics.deployment_frequency_per_day >= 1/7:
            df_class = "High"
        elif metrics.deployment_frequency_per_day >= 1/30:
            df_class = "Medium"
        else:
            df_class = "Low"

        # Lead time
        if metrics.lead_time_minutes < 60:
            lt_class = "Elite"
        elif metrics.lead_time_minutes < 7 * 24 * 60:
            lt_class = "High"
        elif metrics.lead_time_minutes < 30 * 24 * 60:
            lt_class = "Medium"
        else:
            lt_class = "Low"

        # Change failure rate
        if metrics.change_failure_rate <= 0.05:
            cfr_class = "Elite"
        elif metrics.change_failure_rate <= 0.10:
            cfr_class = "High"
        elif metrics.change_failure_rate <= 0.15:
            cfr_class = "Medium"
        else:
            cfr_class = "Low"

        return {
            "deployment_frequency": {"value": metrics.deployment_frequency_per_day, "class": df_class},
            "lead_time_minutes": {"value": metrics.lead_time_minutes, "class": lt_class},
            "change_failure_rate": {"value": metrics.change_failure_rate, "class": cfr_class},
            "mttr_minutes": {"value": metrics.mttr_minutes},
            "overall": df_class if df_class == lt_class == cfr_class else "High",
        }

    def run_security_gate(self, scan_results: List[SecurityScanResult]) -> Dict:
        """Evaluate security gate pass/fail based on scan results."""
        blocking = [r for r in scan_results if r.status == SecurityScanStatus.FAIL and r.critical_count > 0]
        warnings = [r for r in scan_results if r.status == SecurityScanStatus.FAIL and r.critical_count == 0]
        return {
            "passed": len(blocking) == 0,
            "blocking_scans": [r.tool for r in blocking],
            "warning_scans": [r.tool for r in warnings],
            "total_scans": len(scan_results),
            "total_critical": sum(r.critical_count for r in scan_results),
            "total_high": sum(r.high_count for r in scan_results),
        }
