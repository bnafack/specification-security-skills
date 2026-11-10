# Docker Security Specification

This document defines the security requirements that all Docker containers, Docker Compose services, and AWS ECS task definitions must satisfy before deployment to any environment.

This is a living document — review it when adding new containers or upgrading base images.

---

## Setup Declaration

Before applying this specification, declare which setup applies to your project by checking one or more boxes below. Rules marked with your setup letter are mandatory.

| Setup | Description |
|---|---|
| **A** | Local / VPS — Docker or Docker Compose, no CI/CD pipeline |
| **B** | CI/CD pipeline (GitHub Actions, GitLab CI, etc.) deploying to VPS or self-hosted registry |
| **C** | AWS ECS / Fargate with ECR — manual deploy (no CI/CD pipeline) |
| **D** | CI/CD pipeline deploying to AWS ECS / Fargate with ECR |

> **This project uses Setup:** [ ] A &nbsp;&nbsp; [ ] B &nbsp;&nbsp; [ ] C &nbsp;&nbsp; [ ] D

Multiple setups can apply (e.g. Setup B + C if you use a pipeline to deploy to ECS).

---

## 1. Filesystem

| Requirement | A | B | C | D | Docker Run | Docker Compose | ECS Task Definition |
|---|---|---|---|---|---|---|---|
| Root filesystem must be read-only | ✅ | ✅ | ✅ | ✅ | `--read-only` | `read_only: true` | `"ReadonlyRootFilesystem": true` |
| Writable paths must use explicit tmpfs mounts | ✅ | ✅ | ✅ | ✅ | `--tmpfs /path` | `tmpfs: - /path` | `"Volumes"` + `MountPoints` |
| No sensitive data written to container filesystem | ✅ | ✅ | ✅ | ✅ | verified at runtime | verified at runtime | verified at runtime |

### Allowed writable paths

| Path | Purpose |
|---|---|
| `/tmp` | Temporary runtime files (auto-mounted in Fargate) |
| `/var/run/<service>` | PID files and Unix sockets |

Any other writable path requires justification in the [Exceptions](#exceptions) section.

---

## 2. User and Privileges

| Requirement | A | B | C | D | Docker Run | Docker Compose | ECS Task Definition |
|---|---|---|---|---|---|---|---|
| Container must not run as root | ✅ | ✅ | ✅ | ✅ | `--user 1000:1000` | `user: "1000:1000"` | `"User": "1000:1000"` |
| No privilege escalation | ✅ | ✅ | ✅ | ✅ | `--security-opt no-new-privileges` | `security_opt: - no-new-privileges:true` | use IAM role scoping |
| No privileged mode | ✅ | ✅ | ✅ | ✅ | never use `--privileged` | `privileged: false` | `"Privileged": false` |

---

## 3. Capabilities

| Requirement | A | B | C | D | Docker Run | Docker Compose | ECS Task Definition |
|---|---|---|---|---|---|---|---|
| Drop all Linux capabilities | ✅ | ✅ | ✅ | ✅ | `--cap-drop ALL` | `cap_drop: - ALL` | `"Drop": ["ALL"]` |
| Add back only what is needed | ✅ | ✅ | ✅ | ✅ | `--cap-add <CAP>` | `cap_add: - <CAP>` | `"Add": ["<CAP>"]` |

### Commonly approved capabilities

| Capability | Justification |
|---|---|
| `NET_BIND_SERVICE` | Required to bind to ports below 1024 |

Any other capability requires justification in the [Exceptions](#exceptions) section.

---

## 4. Network

| Requirement | A | B | C | D | Docker Run | Docker Compose | ECS Task Definition |
|---|---|---|---|---|---|---|---|
| No host network mode | ✅ | ✅ | ✅ | ✅ | never use `--network host` | `network_mode` must not be `host` | `"NetworkMode"` must be `awsvpc` |
| Expose only required ports | ✅ | ✅ | ✅ | ✅ | `--publish` only needed ports | `ports` only needed ports | `PortMappings` only needed ports |
| Inter-service traffic via internal network only | ✅ | ✅ | ✅ | ✅ | use named networks | use named networks | use VPC security groups |

---

## 5. Secrets and Environment Variables

| Requirement | A | B | C | D | Notes |
|---|---|---|---|---|---|
| No secrets in environment variables | ✅ | ✅ | ✅ | ✅ | Use a secrets manager |
| No secrets in image layers | ✅ | ✅ | ✅ | ✅ | Never `COPY` credential files in Dockerfile |
| No secrets in Docker Compose files | ✅ | ✅ | n/a | n/a | Use `secrets` block or external references |
| No secrets in source control | ✅ | ✅ | ✅ | ✅ | `.env` files must be in `.gitignore` |
| No secrets in CI/CD pipeline logs | n/a | ✅ | n/a | ✅ | Mask secrets in pipeline output |
| Secrets must be rotated regularly | ✅ | ✅ | ✅ | ✅ | Follow your organisation's rotation policy |

### Recommended secrets managers by setup

| Setup | Recommended Tool |
|---|---|
| A | Docker secrets, `.env` file outside source control, or a self-hosted Vault |
| B | CI/CD platform secrets store (GitHub Secrets, GitLab CI Variables) |
| C | AWS Secrets Manager or AWS SSM Parameter Store |
| D | AWS Secrets Manager or AWS SSM Parameter Store injected via pipeline |

---

## 6. Image

| Requirement | A | B | C | D | Notes |
|---|---|---|---|---|---|
| Use specific image tags | ✅ | ✅ | ✅ | ✅ | Never use `:latest` in production |
| Images must be stored in a private registry | ✅ | ✅ | ✅ | ✅ | No public registry images in production |
| Vulnerability scanning must be enabled | ✅ | ✅ | ✅ | ✅ | See Section 11 |
| Base image must be minimal | ✅ | ✅ | ✅ | ✅ | Prefer `alpine` or `distroless` |
| No unnecessary packages installed | ✅ | ✅ | ✅ | ✅ | Remove build tools in final stage |
| Use multi-stage builds | ✅ | ✅ | ✅ | ✅ | Separate build and runtime stages |
| Base images must be kept up to date | ✅ | ✅ | ✅ | ✅ | Rebuild regularly to pick up OS patches |

### Recommended private registries by setup

| Setup | Recommended Registry |
|---|---|
| A | Self-hosted registry (e.g. Harbor, Gitea) or Docker Hub private repo |
| B | CI/CD platform registry (GitHub Container Registry, GitLab Registry) |
| C | AWS ECR |
| D | AWS ECR |

---

## 7. Resource Limits

| Requirement | A | B | C | D | Docker Run | Docker Compose | ECS Task Definition |
|---|---|---|---|---|---|---|---|
| Memory limit must be set | ✅ | ✅ | ✅ | ✅ | `--memory` | `mem_limit` | `"Memory"` at task and container level |
| CPU limit must be set | ✅ | ✅ | ✅ | ✅ | `--cpus` | `cpus` | `"Cpu"` at task level |
| No unlimited resource consumption | ✅ | ✅ | ✅ | ✅ | required | required | required |

---

## 8. Logging

| Requirement | A | B | C | D | Notes |
|---|---|---|---|---|---|
| Logs must go to stdout/stderr | ✅ | ✅ | ✅ | ✅ | Configure app to log to stdout |
| No logging to container filesystem | ✅ | ✅ | ✅ | ✅ | Prevents data loss on container restart |
| Log retention must be configured | ✅ | ✅ | ✅ | ✅ | Use log driver rotation or CloudWatch retention |
| Logs must not contain secrets or PII | ✅ | ✅ | ✅ | ✅ | Sanitise log output in application code |

### Recommended log drivers by setup

| Setup | Recommended Log Driver |
|---|---|
| A | `json-file` with `max-size` and `max-file` rotation |
| B | CI/CD platform logging + `json-file` on VPS |
| C | `awslogs` (CloudWatch Logs) |
| D | `awslogs` (CloudWatch Logs) |

---

## 9. Health Checks

| Requirement | A | B | C | D | Docker Run | Docker Compose | ECS Task Definition |
|---|---|---|---|---|---|---|---|
| Health check must be defined | ✅ | ✅ | ✅ | ✅ | `--health-cmd` | `healthcheck` block | `"HealthCheck"` block |
| Unhealthy containers must restart | ✅ | ✅ | ✅ | ✅ | `--restart` policy | `restart` policy | `DeploymentCircuitBreaker` |
| Health check interval must be reasonable | ✅ | ✅ | ✅ | ✅ | `--health-interval` | `interval` | `"Interval"` |

---

## 10. ECS / Fargate Specific

These requirements apply only to **Setup C and D**.

| Requirement | C | D | Notes |
|---|---|---|---|
| `NetworkMode` must be `awsvpc` | ✅ | ✅ | Required for Fargate and security group isolation |
| `RequiresCompatibilities` must include `FARGATE` | ✅ | ✅ | Unless EC2 launch type is explicitly justified |
| `ExecutionRoleArn` must be scoped | ✅ | ✅ | Only ECR pull and CloudWatch Logs permissions |
| `TaskRoleArn` must follow least privilege | ✅ | ✅ | Only permissions the container actually needs |
| No `AssignPublicIp: ENABLED` on private services | ✅ | ✅ | Only public-facing services may have public IPs |
| `DeploymentCircuitBreaker` must be enabled | ✅ | ✅ | Prevents bad deployments from staying active |
| Log group must be pre-created with retention | ✅ | ✅ | Do not rely on `awslogs-create-group: true` in production |
| ECR scan on push must be enabled | ✅ | ✅ | `"ScanOnPush": true` in ECR repository definition |

---

## 11. Image Scanning

### Severity Thresholds

These thresholds apply to all setups:

| Severity | Action | Deadline |
|---|---|---|
| `CRITICAL` | Block deployment immediately | Must be fixed before any deploy |
| `HIGH` | Block deployment | Must be fixed within 3 days |
| `MEDIUM` | Warn, do not block | Must be fixed within 30 days |
| `LOW` | Log only | Fix in next scheduled maintenance |
| `NEGLIGIBLE` | Ignore | No action required |

---

### Setup A — Local / VPS, No CI/CD

**Recommended tool:** [Trivy](https://github.com/aquasecurity/trivy) (free, open source)

**Install Trivy on VPS:**
```bash
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
```

**Scan a local image:**
```bash
trivy image --severity CRITICAL,HIGH --exit-code 1 your-image:tag
```

**Scan before running with Docker Compose:**
```bash
trivy image --severity CRITICAL,HIGH --exit-code 1 your-image:tag && docker compose up -d
```

**Schedule a weekly scan via cron:**
```bash
0 2 * * 1 trivy image --severity CRITICAL,HIGH your-image:tag >> /var/log/trivy-scan.log 2>&1
```

**Requirements:**
- [ ] Trivy installed on VPS
- [ ] Images scanned before every deployment
- [ ] Weekly scheduled scan configured
- [ ] Scan results logged to `/var/log/trivy-scan.log`
- [ ] `CRITICAL` and `HIGH` findings block deployment (`--exit-code 1`)

---

### Setup B — CI/CD Pipeline, VPS or Self-Hosted Registry

**Recommended tool:** [Trivy](https://github.com/aquasecurity/trivy) as a pipeline step

**GitHub Actions example:**
```yaml
- name: Scan image with Trivy
  uses: aquasecurity/trivy-action@master
  with:
    image-ref: your-image:${{ github.sha }}
    format: table
    exit-code: 1
    severity: CRITICAL,HIGH
```

**GitLab CI example:**
```yaml
trivy-scan:
  image: aquasec/trivy:latest
  script:
    - trivy image --severity CRITICAL,HIGH --exit-code 1 your-image:$CI_COMMIT_SHA
```

**Requirements:**
- [ ] Trivy scan step added to pipeline after image build
- [ ] Pipeline fails on `CRITICAL` or `HIGH` findings (`exit-code: 1`)
- [ ] Scan results published as pipeline artifact
- [ ] `MEDIUM` findings generate a warning but do not fail the pipeline
- [ ] Scan runs on every push to main and on every pull request

---

### Setup C — AWS ECS / Fargate with ECR, Manual Deploy

**Primary tool:** AWS ECR native scanning (powered by Snyk)

**Enable scan on push in CloudFormation:**
```json
"ImageScanningConfiguration": {
  "ScanOnPush": true
}
```

**Check scan results before deploying:**
```bash
aws ecr describe-image-scan-findings \
  --repository-name your-repo \
  --image-id imageTag=your-tag \
  --query "imageScanFindings.findingSeverityCounts"
```

**Block deploy if CRITICAL or HIGH findings exist:**
```bash
CRITICAL=$(aws ecr describe-image-scan-findings \
  --repository-name your-repo \
  --image-id imageTag=your-tag \
  --query "imageScanFindings.findingSeverityCounts.CRITICAL" \
  --output text)

HIGH=$(aws ecr describe-image-scan-findings \
  --repository-name your-repo \
  --image-id imageTag=your-tag \
  --query "imageScanFindings.findingSeverityCounts.HIGH" \
  --output text)

if [ "$CRITICAL" != "None" ] || [ "$HIGH" != "None" ]; then
  echo "Blocking deploy: CRITICAL=$CRITICAL HIGH=$HIGH"
  exit 1
fi
```

**Requirements:**
- [ ] ECR `ScanOnPush` enabled on all repositories
- [ ] Scan results checked manually before every deploy
- [ ] `CRITICAL` or `HIGH` findings block deployment
- [ ] AWS Inspector enabled for continuous scanning of images at rest
- [ ] ECR scan findings reviewed weekly

---

### Setup D — CI/CD Pipeline deploying to AWS ECS / Fargate with ECR

**Primary tool:** AWS ECR native scanning + Trivy in pipeline for early feedback

**Pipeline flow:**
1. Build image
2. Trivy scan (fast feedback before push)
3. Push to ECR
4. ECR scan on push (second scan with Snyk engine)
5. Check ECR scan results
6. Deploy to ECS only if both scans pass

**GitHub Actions example:**
```yaml
- name: Scan image with Trivy before push
  uses: aquasecurity/trivy-action@master
  with:
    image-ref: ${{ env.ECR_REGISTRY }}/${{ env.ECR_REPOSITORY }}:${{ github.sha }}
    format: table
    exit-code: 1
    severity: CRITICAL,HIGH

- name: Push to ECR
  run: docker push $ECR_REGISTRY/$ECR_REPOSITORY:${{ github.sha }}

- name: Wait for ECR scan to complete
  run: |
    aws ecr wait image-scan-complete \
      --repository-name $ECR_REPOSITORY \
      --image-id imageTag=${{ github.sha }}

- name: Check ECR scan results
  run: |
    CRITICAL=$(aws ecr describe-image-scan-findings \
      --repository-name $ECR_REPOSITORY \
      --image-id imageTag=${{ github.sha }} \
      --query "imageScanFindings.findingSeverityCounts.CRITICAL" \
      --output text)
    HIGH=$(aws ecr describe-image-scan-findings \
      --repository-name $ECR_REPOSITORY \
      --image-id imageTag=${{ github.sha }} \
      --query "imageScanFindings.findingSeverityCounts.HIGH" \
      --output text)
    if [ "$CRITICAL" != "None" ] || [ "$HIGH" != "None" ]; then
      echo "Blocking deploy: CRITICAL=$CRITICAL HIGH=$HIGH"
      exit 1
    fi
```

**Requirements:**
- [ ] Trivy scan step added to pipeline after image build, before push
- [ ] ECR `ScanOnPush` enabled on all repositories
- [ ] Pipeline waits for ECR scan to complete before deploying
- [ ] Pipeline fails on `CRITICAL` or `HIGH` findings from both Trivy and ECR
- [ ] Scan results published as pipeline artifact
- [ ] AWS Inspector enabled for continuous scanning of images at rest
- [ ] `MEDIUM` findings generate a warning but do not fail the pipeline

---

## Checklist

Use this checklist when adding or modifying any container. Mark N/A for items that do not apply to your setup.

### Filesystem & Runtime
- [ ] Root filesystem is read-only
- [ ] Writable tmpfs mounts defined for any paths the app writes to
- [ ] No sensitive data written to container filesystem

### User & Privileges
- [ ] Container does not run as root
- [ ] No privileged mode
- [ ] No privilege escalation
- [ ] All capabilities dropped, only required ones added back

### Network
- [ ] No host network mode
- [ ] Only required ports exposed
- [ ] Inter-service traffic uses internal networks or security groups

### Secrets
- [ ] No secrets in environment variables
- [ ] No secrets in image layers or Dockerfile
- [ ] No `.env` files committed to source control
- [ ] No secrets in CI/CD pipeline logs (Setup B, D)

### Image
- [ ] Specific image tag used (no `:latest` in production)
- [ ] Image stored in private registry
- [ ] Vulnerability scanning enabled and passing
- [ ] Multi-stage build used
- [ ] Minimal base image used

### Resources & Observability
- [ ] Memory and CPU limits set
- [ ] Logs go to stdout/stderr only
- [ ] Log retention configured
- [ ] Health check defined

### ECS Only (Setup C, D)
- [ ] IAM roles follow least privilege
- [ ] `DeploymentCircuitBreaker` enabled
- [ ] Log group pre-created with retention policy
- [ ] `awsvpc` network mode used
- [ ] ECR `ScanOnPush` enabled

---

## Exceptions

Any deviation from the above requirements must be documented here with justification and owner.

| Container | Setup | Requirement Skipped | Justification | Owner | Review Date |
|---|---|---|---|---|---|
| | | | | | |
