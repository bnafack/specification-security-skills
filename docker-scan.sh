#!/bin/bash
# =============================================================================
# docker-scan.sh — Docker Security Scanner
# Covers Setup A (VPS/Local), B (CI/CD), C (ECS/ECR manual), D (CI/CD + ECS)
#
# Usage:
#   ./docker-scan.sh --setup <A|B|C|D> --image <image:tag> [OPTIONS]
#
# Options:
#   --setup       <A|B|C|D>        Required. Deployment setup type
#   --image       <image:tag>      Required. Docker image to scan
#   --compose     <file>           Optional. Path to docker-compose.yml
#   --output      <file>           Optional. Write report to file
#   --exit-on-fail                 Optional. Exit with code 1 on CRITICAL/HIGH
#   --region      <aws-region>     Required for Setup C and D
#   --repo        <ecr-repo-name>  Required for Setup C and D
#   --profile     <aws-profile>    Optional. AWS CLI named profile
#
# Examples:
#   ./docker-scan.sh --setup A --image myapp:1.0.0
#   ./docker-scan.sh --setup B --image myapp:1.0.0 --exit-on-fail
#   ./docker-scan.sh --setup C --image 123456789.dkr.ecr.eu-west-1.amazonaws.com/myrepo:1.0.0 --region eu-west-1 --repo myrepo --exit-on-fail
#   ./docker-scan.sh --setup C --image 123456789.dkr.ecr.eu-west-1.amazonaws.com/myrepo:1.0.0 --region eu-west-1 --repo myrepo --profile myprofile --exit-on-fail
#   ./docker-scan.sh --setup D --image 123456789.dkr.ecr.eu-west-1.amazonaws.com/myrepo:1.0.0 --region eu-west-1 --repo myrepo --output report.txt --exit-on-fail
#   ./docker-scan.sh --setup A --image myapp:1.0.0 --compose docker-compose.yml --output report.txt
# =============================================================================

set -euo pipefail

# -----------------------------------------------------------------------------
# Colours
# -----------------------------------------------------------------------------
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# -----------------------------------------------------------------------------
# Defaults
# -----------------------------------------------------------------------------
SETUP=""
IMAGE=""
COMPOSE_FILE=""
OUTPUT_FILE=""
EXIT_ON_FAIL=false
AWS_REGION=""
ECR_REPO=""
AWS_PROFILE=""
REPORT=""
FAIL=false

# -----------------------------------------------------------------------------
# Parse arguments
# -----------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --setup)        SETUP="$2";        shift 2 ;;
    --image)        IMAGE="$2";        shift 2 ;;
    --compose)      COMPOSE_FILE="$2"; shift 2 ;;
    --output)       OUTPUT_FILE="$2";  shift 2 ;;
    --exit-on-fail) EXIT_ON_FAIL=true; shift ;;
    --region)       AWS_REGION="$2";   shift 2 ;;
    --repo)         ECR_REPO="$2";     shift 2 ;;
    --profile)      AWS_PROFILE="$2";  shift 2 ;;
    *)
      echo -e "${RED}Unknown argument: $1${NC}"
      exit 1
      ;;
  esac
done

# -----------------------------------------------------------------------------
# Validate required arguments
# -----------------------------------------------------------------------------
if [[ -z "$SETUP" ]]; then
  echo -e "${RED}ERROR: --setup is required (A, B, C or D)${NC}"
  exit 1
fi

if [[ -z "$IMAGE" ]]; then
  echo -e "${RED}ERROR: --image is required${NC}"
  exit 1
fi

if [[ "$SETUP" == "C" || "$SETUP" == "D" ]]; then
  if [[ -z "$AWS_REGION" || -z "$ECR_REPO" ]]; then
    echo -e "${RED}ERROR: --region and --repo are required for Setup $SETUP${NC}"
    exit 1
  fi
fi

# -----------------------------------------------------------------------------
# Output helpers
# -----------------------------------------------------------------------------
log() {
  local msg="$1"
  echo -e "$msg"
  REPORT+="$msg\n"
}

log_section() {
  local title="$1"
  log ""
  log "${CYAN}============================================================${NC}"
  log "${CYAN}  $title${NC}"
  log "${CYAN}============================================================${NC}"
}

log_pass() { log "${GREEN}  [PASS]${NC} $1"; }
log_fail() { log "${RED}  [FAIL]${NC} $1"; FAIL=true; }
log_warn() { log "${YELLOW}  [WARN]${NC} $1"; }
log_info() { log "${BLUE}  [INFO]${NC} $1"; }

# -----------------------------------------------------------------------------
# Dependency checks
# -----------------------------------------------------------------------------
check_dependency() {
  local cmd="$1"
  if ! command -v "$cmd" &>/dev/null; then
    echo -e "${RED}ERROR: '$cmd' is not installed or not in PATH${NC}"
    exit 1
  fi
}

check_dependency docker

if [[ "$SETUP" == "A" || "$SETUP" == "B" || "$SETUP" == "D" ]]; then
  check_dependency trivy
fi

if [[ "$SETUP" == "C" || "$SETUP" == "D" ]]; then
  check_dependency aws
fi

# -----------------------------------------------------------------------------
# Header
# -----------------------------------------------------------------------------
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
log "${CYAN}Docker Security Scanner${NC}"
log "Setup:     $SETUP"
log "Image:     $IMAGE"
log "Timestamp: $TIMESTAMP"
[[ -n "$COMPOSE_FILE"  ]] && log "Compose:   $COMPOSE_FILE"
[[ -n "$OUTPUT_FILE"   ]] && log "Output:    $OUTPUT_FILE"
[[ -n "$AWS_PROFILE"   ]] && log "Profile:   $AWS_PROFILE"

# =============================================================================
# SECTION 1 — IMAGE INSPECT (all setups)
# =============================================================================
log_section "1. Image Inspect"

log_info "Running: docker image inspect $IMAGE"

IMAGE_JSON=$(docker image inspect "$IMAGE" 2>/dev/null || true)

if [[ -z "$IMAGE_JSON" ]]; then
  log_fail "Image '$IMAGE' not found locally. Pull or build it first."
else
  # User
  IMG_USER=$(echo "$IMAGE_JSON" | grep -o '"User": *"[^"]*"' | head -1 | sed 's/"User": *"//' | tr -d '"')
  if [[ -z "$IMG_USER" || "$IMG_USER" == "root" || "$IMG_USER" == "0" ]]; then
    log_fail "Image runs as root (User: '${IMG_USER:-not set}')"
  else
    log_pass "Image user: $IMG_USER"
  fi

  # Exposed ports
  EXPOSED=$(echo "$IMAGE_JSON" | grep -o '"ExposedPorts":{[^}]*}' | head -1)
  if [[ -n "$EXPOSED" ]]; then
    log_info "Exposed ports in image: $EXPOSED"
  else
    log_info "No ports exposed in image"
  fi

  # Environment variables — check for secrets
  ENV_VARS=$(echo "$IMAGE_JSON" | grep -o '"Env":\[[^]]*\]' | head -1)
  SECRET_PATTERNS="PASSWORD\|SECRET\|TOKEN\|KEY\|CREDENTIAL\|API_KEY\|PRIVATE"
  if echo "$ENV_VARS" | grep -qi "$SECRET_PATTERNS"; then
    log_fail "Potential secret found in image ENV vars: $ENV_VARS"
  else
    log_pass "No obvious secrets found in image ENV vars"
  fi
fi

# =============================================================================
# SECTION 2 — RUNNING CONTAINER INSPECT (all setups)
# =============================================================================
log_section "2. Running Container Inspect"

CONTAINER_ID=$(docker ps --filter "ancestor=$IMAGE" --format "{{.ID}}" | head -1)

if [[ -z "$CONTAINER_ID" ]]; then
  log_warn "No running container found for image '$IMAGE'. Skipping runtime checks."
  log_info "Start the container and re-run to include runtime checks."
else
  log_info "Inspecting container: $CONTAINER_ID"
  CONTAINER_JSON=$(docker inspect "$CONTAINER_ID")

  # Read-only root filesystem
  READONLY=$(echo "$CONTAINER_JSON" | grep -o '"ReadonlyRootfs": *[a-z]*' | head -1 | awk '{print $2}')
  if [[ "$READONLY" == "true" ]]; then
    log_pass "ReadonlyRootFilesystem: true"
  else
    log_fail "ReadonlyRootFilesystem: false — root filesystem is writable"
  fi

  # Privileged mode
  PRIVILEGED=$(echo "$CONTAINER_JSON" | grep -o '"Privileged": *[a-z]*' | head -1 | awk '{print $2}')
  if [[ "$PRIVILEGED" == "false" ]]; then
    log_pass "Privileged: false"
  else
    log_fail "Privileged: true — container is running in privileged mode"
  fi

  # No new privileges
  NO_NEW_PRIV=$(echo "$CONTAINER_JSON" | grep -o '"NoNewPrivileges": *[a-z]*' | head -1 | awk '{print $2}')
  if [[ "$NO_NEW_PRIV" == "true" ]]; then
    log_pass "NoNewPrivileges: true"
  else
    log_fail "NoNewPrivileges: false — privilege escalation is allowed"
  fi

  # Capabilities — CapAdd
  CAP_ADD=$(echo "$CONTAINER_JSON" | grep -o '"CapAdd": *\[[^]]*\]' | head -1)
  if echo "$CAP_ADD" | grep -q "null\|\[\]"; then
    log_pass "CapAdd: none"
  else
    log_warn "CapAdd: $CAP_ADD — verify these are justified in DockerSecuritySpec.md"
  fi

  # Capabilities — CapDrop
  CAP_DROP=$(echo "$CONTAINER_JSON" | grep -o '"CapDrop": *\[[^]]*\]' | head -1)
  if echo "$CAP_DROP" | grep -qi "ALL"; then
    log_pass "CapDrop: ALL"
  else
    log_fail "CapDrop does not include ALL: $CAP_DROP"
  fi

  # Network mode
  NET_MODE=$(echo "$CONTAINER_JSON" | grep -o '"NetworkMode": *"[^"]*"' | head -1 | sed 's/"NetworkMode": *"//' | tr -d '"')
  if [[ "$NET_MODE" == "host" ]]; then
    log_fail "NetworkMode: host — host network mode is not allowed"
  else
    log_pass "NetworkMode: $NET_MODE"
  fi

  # Memory limit
  MEM_LIMIT=$(echo "$CONTAINER_JSON" | grep -o '"Memory": *[0-9]*' | head -1 | awk '{print $2}')
  if [[ -z "$MEM_LIMIT" || "$MEM_LIMIT" == "0" ]]; then
    log_fail "Memory limit not set"
  else
    log_pass "Memory limit: $MEM_LIMIT bytes"
  fi

  # CPU limit
  CPU_QUOTA=$(echo "$CONTAINER_JSON" | grep -o '"CpuQuota": *[0-9]*' | head -1 | awk '{print $2}')
  if [[ -z "$CPU_QUOTA" || "$CPU_QUOTA" == "0" ]]; then
    log_fail "CPU limit not set (CpuQuota: 0)"
  else
    log_pass "CPU quota: $CPU_QUOTA"
  fi

  # User
  RUN_USER=$(echo "$CONTAINER_JSON" | grep -o '"User": *"[^"]*"' | head -1 | sed 's/"User": *"//' | tr -d '"')
  if [[ -z "$RUN_USER" || "$RUN_USER" == "root" || "$RUN_USER" == "0" ]]; then
    log_fail "Container running as root (User: '${RUN_USER:-not set}')"
  else
    log_pass "Container user: $RUN_USER"
  fi

  # Environment variables — check for secrets
  ENV_RT=$(echo "$CONTAINER_JSON" | grep -o '"Env":\[[^]]*\]' | head -1)
  if echo "$ENV_RT" | grep -qi "$SECRET_PATTERNS"; then
    log_fail "Potential secret found in container ENV vars"
  else
    log_pass "No obvious secrets found in container ENV vars"
  fi
fi

# =============================================================================
# SECTION 3 — DOCKER COMPOSE INSPECT (Setup A and B only)
# =============================================================================
if [[ "$SETUP" == "A" || "$SETUP" == "B" ]] && [[ -n "$COMPOSE_FILE" ]]; then
  log_section "3. Docker Compose File Checks"

  if [[ ! -f "$COMPOSE_FILE" ]]; then
    log_fail "Compose file not found: $COMPOSE_FILE"
  else
    log_info "Checking: $COMPOSE_FILE"

    # read_only
    if grep -q "read_only: true" "$COMPOSE_FILE"; then
      log_pass "read_only: true found in compose file"
    else
      log_fail "read_only: true not found — root filesystem may be writable"
    fi

    # privileged
    if grep -q "privileged: true" "$COMPOSE_FILE"; then
      log_fail "privileged: true found in compose file"
    else
      log_pass "No privileged: true found"
    fi

    # network_mode host
    if grep -q "network_mode: host" "$COMPOSE_FILE"; then
      log_fail "network_mode: host found in compose file"
    else
      log_pass "No network_mode: host found"
    fi

    # no-new-privileges
    if grep -q "no-new-privileges" "$COMPOSE_FILE"; then
      log_pass "no-new-privileges found in compose file"
    else
      log_fail "no-new-privileges not set in security_opt"
    fi

    # mem_limit
    if grep -q "mem_limit" "$COMPOSE_FILE"; then
      log_pass "mem_limit found in compose file"
    else
      log_fail "mem_limit not set"
    fi

    # cap_drop ALL
    if grep -q "ALL" "$COMPOSE_FILE"; then
      log_pass "cap_drop ALL found in compose file"
    else
      log_fail "cap_drop ALL not found"
    fi

    # secrets in env
    if grep -iE "PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE_KEY|CREDENTIAL" "$COMPOSE_FILE" | grep -v "secrets:" | grep -v "#" | grep -q "="; then
      log_fail "Potential hardcoded secret found in compose file env vars"
    else
      log_pass "No obvious hardcoded secrets in compose file"
    fi

    # latest tag
    if grep -q ":latest" "$COMPOSE_FILE"; then
      log_fail ":latest tag found in compose file — use specific tags in production"
    else
      log_pass "No :latest tags found"
    fi
  fi
fi

# =============================================================================
# SECTION 4 — TRIVY SCAN (Setup A, B, D)
# =============================================================================
if [[ "$SETUP" == "A" || "$SETUP" == "B" || "$SETUP" == "D" ]]; then
  log_section "4. Trivy Vulnerability Scan"

  log_info "Running Trivy scan on: $IMAGE"

  TRIVY_OUTPUT=$(trivy image \
    --severity CRITICAL,HIGH,MEDIUM,LOW \
    --format table \
    --no-progress \
    "$IMAGE" 2>&1 || true)

  log "$TRIVY_OUTPUT"

  CRITICAL_COUNT=$(echo "$TRIVY_OUTPUT" | grep -c "CRITICAL" || true)
  HIGH_COUNT=$(echo "$TRIVY_OUTPUT" | grep -c "HIGH" || true)
  MEDIUM_COUNT=$(echo "$TRIVY_OUTPUT" | grep -c "MEDIUM" || true)
  LOW_COUNT=$(echo "$TRIVY_OUTPUT" | grep -c "LOW" || true)

  log ""
  log_info "Trivy Summary:"
  log_info "  CRITICAL : $CRITICAL_COUNT"
  log_info "  HIGH     : $HIGH_COUNT"
  log_info "  MEDIUM   : $MEDIUM_COUNT"
  log_info "  LOW      : $LOW_COUNT"

  if [[ "$CRITICAL_COUNT" -gt 0 ]]; then
    log_fail "CRITICAL vulnerabilities found — deployment must be blocked"
  fi
  if [[ "$HIGH_COUNT" -gt 0 ]]; then
    log_fail "HIGH vulnerabilities found — must be fixed within 3 days"
  fi
  if [[ "$MEDIUM_COUNT" -gt 0 ]]; then
    log_warn "MEDIUM vulnerabilities found — must be fixed within 30 days"
  fi
  if [[ "$LOW_COUNT" -gt 0 ]]; then
    log_warn "LOW vulnerabilities found — fix in next scheduled maintenance"
  fi
  if [[ "$CRITICAL_COUNT" -eq 0 && "$HIGH_COUNT" -eq 0 ]]; then
    log_pass "No CRITICAL or HIGH vulnerabilities found"
  fi
fi

# =============================================================================
# SECTION 5 — ECR SCAN (Setup C, D)
# =============================================================================
if [[ "$SETUP" == "C" || "$SETUP" == "D" ]]; then
  log_section "5. ECR Scan Results"

  IMAGE_TAG=$(echo "$IMAGE" | awk -F: '{print $2}')
  if [[ -z "$IMAGE_TAG" ]]; then
    IMAGE_TAG="latest"
  fi

  AWS_PROFILE_ARG=""
  [[ -n "$AWS_PROFILE" ]] && AWS_PROFILE_ARG="--profile $AWS_PROFILE"

  log_info "Waiting for ECR scan to complete..."
  aws ecr wait image-scan-complete \
    --repository-name "$ECR_REPO" \
    --image-id imageTag="$IMAGE_TAG" \
    --region "$AWS_REGION" \
    $AWS_PROFILE_ARG 2>/dev/null || true

  log_info "Fetching ECR scan findings for $ECR_REPO:$IMAGE_TAG"

  ECR_FINDINGS=$(aws ecr describe-image-scan-findings \
    --repository-name "$ECR_REPO" \
    --image-id imageTag="$IMAGE_TAG" \
    --region "$AWS_REGION" \
    $AWS_PROFILE_ARG \
    --query "imageScanFindings.findingSeverityCounts" \
    --output json 2>/dev/null || echo "{}")

  log_info "ECR Scan Results: $ECR_FINDINGS"

  ECR_CRITICAL=$(echo "$ECR_FINDINGS" | grep -o '"CRITICAL": *[0-9]*' | awk '{print $2}')
  ECR_HIGH=$(echo "$ECR_FINDINGS"     | grep -o '"HIGH": *[0-9]*'     | awk '{print $2}')
  ECR_MEDIUM=$(echo "$ECR_FINDINGS"   | grep -o '"MEDIUM": *[0-9]*'   | awk '{print $2}')
  ECR_LOW=$(echo "$ECR_FINDINGS"      | grep -o '"LOW": *[0-9]*'      | awk '{print $2}')

  ECR_CRITICAL=${ECR_CRITICAL:-0}
  ECR_HIGH=${ECR_HIGH:-0}
  ECR_MEDIUM=${ECR_MEDIUM:-0}
  ECR_LOW=${ECR_LOW:-0}

  log_info "ECR Summary:"
  log_info "  CRITICAL : $ECR_CRITICAL"
  log_info "  HIGH     : $ECR_HIGH"
  log_info "  MEDIUM   : $ECR_MEDIUM"
  log_info "  LOW      : $ECR_LOW"

  if [[ "$ECR_CRITICAL" -gt 0 ]]; then
    log_fail "ECR: CRITICAL vulnerabilities found — deployment must be blocked"
  fi
  if [[ "$ECR_HIGH" -gt 0 ]]; then
    log_fail "ECR: HIGH vulnerabilities found — must be fixed within 3 days"
  fi
  if [[ "$ECR_MEDIUM" -gt 0 ]]; then
    log_warn "ECR: MEDIUM vulnerabilities found — must be fixed within 30 days"
  fi
  if [[ "$ECR_LOW" -gt 0 ]]; then
    log_warn "ECR: LOW vulnerabilities found — fix in next scheduled maintenance"
  fi
  if [[ "$ECR_CRITICAL" -eq 0 && "$ECR_HIGH" -eq 0 ]]; then
    log_pass "ECR: No CRITICAL or HIGH vulnerabilities found"
  fi
fi

# =============================================================================
# SUMMARY
# =============================================================================
log_section "Summary"

if [[ "$FAIL" == true ]]; then
  log "${RED}RESULT: FAILED — one or more checks did not pass${NC}"
else
  log "${GREEN}RESULT: PASSED — all checks passed${NC}"
fi

# -----------------------------------------------------------------------------
# Write output file if requested
# -----------------------------------------------------------------------------
if [[ -n "$OUTPUT_FILE" ]]; then
  echo -e "$REPORT" > "$OUTPUT_FILE"
  echo -e "${BLUE}Report written to: $OUTPUT_FILE${NC}"
fi

# -----------------------------------------------------------------------------
# Exit code
# -----------------------------------------------------------------------------
if [[ "$EXIT_ON_FAIL" == true && "$FAIL" == true ]]; then
  exit 1
fi

exit 0
