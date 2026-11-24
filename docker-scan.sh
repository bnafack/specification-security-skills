#!/usr/bin/env bash
# =============================================================================
# docker-scan.sh — Docker Security Scanner
# Covers Setup A (VPS/Local), B (CI/CD), C (ECS/ECR manual), D (CI/CD + ECS)
# Specification: DockerSecuritySpec.md
#
# Usage:
#   ./docker-scan.sh --setup <A|B|C|D> (--image <image:tag>... | --images-file <file> | --all | --semgrep <path>) [OPTIONS]
#
# Options:
#   --setup       <A|B|C|D>        Required. Deployment setup type
#   --image       <image:tag>      Image to scan (repeatable)
#   --images-file <file>           File with one image per line (# comments allowed)
#   --all                          Scan every local image (docker images, no <none>)
#   --compose     <file>           Optional. Path to docker-compose.yml (Setup A/B)
#   --output      <file>           Optional. Copy the plain-text report to this file
#   --report-dir  <dir>            Report directory (default: ./scan-reports/<timestamp>)
#                                  Contains summary.json, summary.csv, summary.md,
#                                  scan-report.txt and per-image Trivy JSON/table files
#   --jobs        <n>              Parallel scans (default: min(4, CPUs))
#   --force                        Ignore cached results, rescan every image
#   --skip-db-update               Do not refresh the Trivy vulnerability DB
#   --secrets                      Also run Trivy secret scanning (much slower)
#   --remediation                  Show the remediation section (fixable packages, base image
#                                  advice). Default: on; it only reads the Trivy JSON already
#                                  written, so it is cheap. Writes <report-dir>/remediation.json
#                                  (all images) and <report-dir>/images/<image>.remediation.json
#                                  ("highest fixed version" is a numeric-aware heuristic, not a
#                                  dpkg/apk/semver comparison: check the Trivy JSON when in doubt)
#   --no-remediation               Skip the remediation section
#   --exit-on-fail                 Exit 1 on CRITICAL/HIGH or failed checks
#   --region      <aws-region>     Required for Setup C and D
#   --repo        <ecr-repo-name>  Required for Setup C and D (single image only)
#   --profile     <aws-profile>    Optional. AWS CLI named profile
#   --semgrep     <path>           Run Semgrep (open-source SAST) on a source directory or file
#                                  (repeatable). Works alone, without any image. Run it BEFORE
#                                  docker build: it finds flaws in your own code, Trivy finds
#                                  them in dependencies/OS packages. Uses the 'semgrep' CLI, or
#                                  the semgrep/semgrep Docker image (mounted read-only) if the
#                                  CLI is missing. Writes <report-dir>/semgrep/<path>.json/.txt
#                                  and a "semgrep" section in summary.json/summary.md plus
#                                  semgrep-summary.csv. Honours .semgrepignore in the scanned path;
#                                  node_modules, .git, venv, .venv, dist, build, __pycache__ and
#                                  vendor are always excluded. Always runs with --metrics off
#   --semgrep-config <cfg>         Semgrep rules (repeatable, default: auto). Examples: p/owasp-top-ten,
#                                  p/python, p/docker, p/dockerfile, or a local rules file/directory.
#                                  'auto' fetches rules from the Semgrep registry (needs network);
#                                  local rule files work offline
#   --semgrep-severity <ERROR|WARNING|INFO>
#                                  Minimum severity to report and to fail on with --exit-on-fail
#                                  (default: report INFO and above, fail on ERROR)
#
# Exit codes: 0 ok, 1 findings (only with --exit-on-fail; includes Semgrep findings at/above the
#             gate severity), 2 a scan/tool error (including Semgrep missing or failing)
#
# Examples:
#   ./docker-scan.sh --setup A --image myapp:1.0.0
#   ./docker-scan.sh --setup A --all --jobs 6
#   ./docker-scan.sh --setup B --image myapp:1.0.0 --exit-on-fail
#   ./docker-scan.sh --setup C --image 123456789.dkr.ecr.eu-west-1.amazonaws.com/myrepo:1.0.0 --region eu-west-1 --repo myrepo --exit-on-fail
#   ./docker-scan.sh --setup D --image 123456789.dkr.ecr.eu-west-1.amazonaws.com/myrepo:1.0.0 --region eu-west-1 --repo myrepo --profile myprofile --output report.txt --exit-on-fail
#   ./docker-scan.sh --setup A --image myapp:1.0.0 --compose docker-compose.yml --output report.txt
#
# More examples (one per kind of check):
#
#   # 1. Full scan of every local image, with a text copy and a report folder
#   #    (what was run in this session; results in report/ and test.txt)
#   ./docker-scan.sh --setup A --all --output test.txt --report-dir report
#
#   # 2. Scan one image: vulnerabilities by severity + package count
#   #    (e.g. postgres:18.1 -> CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN + packages)
#   ./docker-scan.sh --setup A --image postgres:18.1 --report-dir report-pg
#
#   # 3. Scan several chosen images at once
#   ./docker-scan.sh --setup A --image redis:7-alpine --image caddy:2.10.2-alpine --image python:3.13-slim
#
#   # 4. Scan a list of images from a file (one per line, # comments allowed)
#   printf '%s\n' '# my images' postgres:16 redis:7-alpine > images.txt
#   ./docker-scan.sh --setup A --images-file images.txt
#
#   # 5. Image config checks only matter per image: user (root or not),
#   #    exposed ports, secrets in ENV var names. They run for every image.
#   ./docker-scan.sh --setup A --image ml-backend:latest
#
#   # 6. Runtime hardening checks (read-only rootfs, privileged, no-new-privileges,
#   #    cap_add/cap_drop, network mode, memory/CPU limits, container user).
#   #    They run on a RUNNING container of the image; start one first:
#   docker run -d --name test-redis redis:7-alpine
#   ./docker-scan.sh --setup A --image redis:7-alpine
#   docker rm -f test-redis
#
#   # 7. Add docker-compose checks (Setup A/B)
#   ./docker-scan.sh --setup A --image myapp:1.0.0 --compose docker-compose.yml
#
#   # 8. Faster reruns: reuse cached results, offline DB, more parallel jobs
#   ./docker-scan.sh --setup A --all --skip-db-update --jobs 8
#
#   # 9. Ignore the cache and rescan everything from scratch
#   ./docker-scan.sh --setup A --all --force
#
#   # 10. Also look for secrets inside image files (much slower)
#   ./docker-scan.sh --setup A --image myapp:1.0.0 --secrets
#
#   # 11. CI gate: exit code 1 on CRITICAL/HIGH or failed checks
#   ./docker-scan.sh --setup B --image myapp:1.0.0 --exit-on-fail; echo "exit=$?"
#
#   # 12. Read the results afterwards
#   cat report/summary.md                       # summary table
#   column -s, -t < report/summary.csv | less -S # same data as CSV
#   jq . report/summary.json                    # machine-readable
#   ls report/images/                           # per-image Trivy JSON/table files
#   jq '[.Results[]?.Packages[]?] | length' report/images/postgres_18.1.json  # package count
#
#   # 13. Remediation: which packages to upgrade (OS vs application), to which version,
#   #     plus unfixable findings and base image advice. Shown at the end of the scan,
#   #     in scan-report.txt, summary.md, report/remediation.json and one
#   #     report/images/<image>.remediation.json per image (disable: --no-remediation)
#   ./docker-scan.sh --setup A --image postgres:16 --report-dir report
#   jq '.images[] | {image, os_fixes: (.os_packages|length), app_fixes: (.app_dependencies|length), unfixable}' report/remediation.json
#   jq '{os_packages, app_dependencies, unfixable}' report/images/postgres_16.remediation.json
#
#   # 14. List fixable CRITICAL/HIGH findings of one image with jq (package, installed -> fixed)
#   jq -r '.Results[]?.Vulnerabilities[]? | select(.Severity=="CRITICAL" or .Severity=="HIGH") | select(.FixedVersion!=null) | "\(.Severity) \(.PkgName) \(.InstalledVersion) -> \(.FixedVersion)"' report/images/postgres_16.json | sort -u
#
#   # 15. Semgrep only: static analysis of your source code (no image needed)
#   ./docker-scan.sh --setup A --semgrep ./src
#
#   # 16. Semgrep with rule packs (registry rules need network; --metrics off is always set)
#   ./docker-scan.sh --setup A --semgrep ./src --semgrep-config p/owasp-top-ten --semgrep-config p/python
#
#   # 17. Dockerfile / compose focused rules on the whole project
#   ./docker-scan.sh --setup A --semgrep . --semgrep-config p/dockerfile
#
#   # 18. Semgrep + image scan with an exit gate (exit 1 on ERROR findings, CRITICAL/HIGH CVEs...)
#   ./docker-scan.sh --setup B --semgrep ./src --image myapp:1.0.0 --exit-on-fail
#
#   # 19. Recommended pipeline order: semgrep -> docker build -> trivy/image checks -> runtime checks
#   ./docker-scan.sh --setup B --semgrep ./src --exit-on-fail       # 1. SAST on the source
#   docker build -t myapp:1.0.0 .                                   # 2. build
#   ./docker-scan.sh --setup B --image myapp:1.0.0 --exit-on-fail   # 3. Trivy + image checks
#   docker run -d --name myapp myapp:1.0.0                          # 4. start, then re-run step 3
#                                                                   #    for the runtime checks
#   # Suppress a false positive in code: add "# nosemgrep: <rule-id>" and a comment why
#
#   # 20. Show this help
#   ./docker-scan.sh --help
# =============================================================================

set -Eeuo pipefail

# -----------------------------------------------------------------------------
# Colours (disabled when stdout is not a terminal)
# -----------------------------------------------------------------------------
if [[ -t 1 ]]; then
  RED=$'\033[0;31m'; YELLOW=$'\033[1;33m'; GREEN=$'\033[0;32m'
  BLUE=$'\033[0;34m'; CYAN=$'\033[0;36m'; NC=$'\033[0m'
else
  RED=''; YELLOW=''; GREEN=''; BLUE=''; CYAN=''; NC=''
fi

# -----------------------------------------------------------------------------
# Defaults
# -----------------------------------------------------------------------------
SETUP=""
IMAGES=()
IMAGES_FILE=""
SCAN_ALL=false
COMPOSE_FILE=""
OUTPUT_FILE=""
REPORT_DIR=""
JOBS=""
FORCE=false
SKIP_DB_UPDATE=false
SCAN_SECRETS=false
EXIT_ON_FAIL=false
SEMGREP_PATHS=()
SEMGREP_CONFIGS=()
SEMGREP_SEVERITY=""
REMEDIATION=true
AWS_REGION=""
ECR_REPO=""
AWS_PROFILE=""
FAIL=false
SCAN_ERRORS=0
TRIVY_CACHE_DIR="${TRIVY_CACHE_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/trivy}"
RESULT_CACHE="${XDG_CACHE_HOME:-$HOME/.cache}/docker-scan/results"

die() { printf '%sERROR: %s%s\n' "$RED" "$1" "$NC" >&2; exit 2; }

need_arg() { [[ $# -ge 2 && -n "${2:-}" ]] || die "$1 requires a value"; }

# -----------------------------------------------------------------------------
# Parse arguments
# -----------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --setup)          need_arg "$@"; SETUP="$2";        shift 2 ;;
    --image)          need_arg "$@"; IMAGES+=("$2");    shift 2 ;;
    --images-file)    need_arg "$@"; IMAGES_FILE="$2";  shift 2 ;;
    --all)            SCAN_ALL=true;                    shift ;;
    --compose)        need_arg "$@"; COMPOSE_FILE="$2"; shift 2 ;;
    --output)         need_arg "$@"; OUTPUT_FILE="$2";  shift 2 ;;
    --report-dir)     need_arg "$@"; REPORT_DIR="$2";   shift 2 ;;
    --jobs)           need_arg "$@"; JOBS="$2";         shift 2 ;;
    --force)          FORCE=true;                       shift ;;
    --skip-db-update) SKIP_DB_UPDATE=true;              shift ;;
    --secrets)        SCAN_SECRETS=true;                shift ;;
    --no-remediation) REMEDIATION=false;                shift ;;
    --remediation)    REMEDIATION=true;                 shift ;;
    --exit-on-fail)   EXIT_ON_FAIL=true;                shift ;;
    --region)         need_arg "$@"; AWS_REGION="$2";   shift 2 ;;
    --repo)           need_arg "$@"; ECR_REPO="$2";     shift 2 ;;
    --profile)        need_arg "$@"; AWS_PROFILE="$2";  shift 2 ;;
    --semgrep)        need_arg "$@"; SEMGREP_PATHS+=("$2");   shift 2 ;;
    --semgrep-config) need_arg "$@"; SEMGREP_CONFIGS+=("$2"); shift 2 ;;
    --semgrep-severity) need_arg "$@"; SEMGREP_SEVERITY="${2^^}"; shift 2 ;;
    -h|--help)        sed -n '2,/^set -E/{/^set -E/!p}' "$0"; exit 0 ;;
    *) die "Unknown argument: $1" ;;
  esac
done

# -----------------------------------------------------------------------------
# Validate arguments
# -----------------------------------------------------------------------------
[[ -n "$SETUP" ]] || die "--setup is required (A, B, C or D)"
[[ "$SETUP" =~ ^[ABCD]$ ]] || die "--setup must be A, B, C or D (got '$SETUP')"

if [[ -n "$IMAGES_FILE" ]]; then
  [[ -f "$IMAGES_FILE" ]] || die "Images file not found: $IMAGES_FILE"
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%%#*}"; line="${line//[[:space:]]/}"
    [[ -n "$line" ]] && IMAGES+=("$line")
  done < "$IMAGES_FILE"
fi

if [[ "$SCAN_ALL" == true ]]; then
  command -v docker &>/dev/null || die "'docker' is not installed or not in PATH"
  while IFS= read -r line; do
    [[ -n "$line" && "$line" != *"<none>"* ]] && IMAGES+=("$line")
  done < <(docker images --format '{{.Repository}}:{{.Tag}}')
fi

[[ ${#IMAGES[@]} -gt 0 || ${#SEMGREP_PATHS[@]} -gt 0 ]] \
  || die "Nothing to scan: use --image, --images-file, --all or --semgrep <path>"

HAVE_IMAGES=false
if [[ ${#IMAGES[@]} -gt 0 ]]; then
  HAVE_IMAGES=true
  # De-duplicate while preserving order
  mapfile -t IMAGES < <(printf '%s\n' "${IMAGES[@]}" | awk '!seen[$0]++')

  if [[ "$SETUP" == "C" || "$SETUP" == "D" ]]; then
    [[ -n "$AWS_REGION" && -n "$ECR_REPO" ]] || die "--region and --repo are required for Setup $SETUP"
    [[ ${#IMAGES[@]} -eq 1 ]] || die "Setup $SETUP ECR checks support exactly one image"
  fi
fi

if [[ ${#SEMGREP_PATHS[@]} -gt 0 ]]; then
  [[ -z "$SEMGREP_SEVERITY" || "$SEMGREP_SEVERITY" =~ ^(ERROR|WARNING|INFO)$ ]] \
    || die "--semgrep-severity must be ERROR, WARNING or INFO (got '$SEMGREP_SEVERITY')"
  for p in "${SEMGREP_PATHS[@]}"; do
    [[ -e "$p" ]] || die "Semgrep path not found: $p"
  done
  mapfile -t SEMGREP_PATHS < <(printf '%s\n' "${SEMGREP_PATHS[@]}" | awk '!seen[$0]++')
  [[ ${#SEMGREP_CONFIGS[@]} -gt 0 ]] || SEMGREP_CONFIGS=(auto)
elif [[ ${#SEMGREP_CONFIGS[@]} -gt 0 || -n "$SEMGREP_SEVERITY" ]]; then
  die "--semgrep-config and --semgrep-severity need --semgrep <path>"
fi

if [[ -z "$JOBS" ]]; then
  JOBS=$(nproc 2>/dev/null || echo 2)
  (( JOBS > 4 )) && JOBS=4
fi
[[ "$JOBS" =~ ^[1-9][0-9]*$ ]] || die "--jobs must be a positive integer"

# -----------------------------------------------------------------------------
# Dependency checks
# -----------------------------------------------------------------------------
check_dependency() {
  command -v "$1" &>/dev/null || die "'$1' is not installed or not in PATH"
}

check_dependency jq
if [[ "$HAVE_IMAGES" == true ]]; then
  check_dependency docker
  docker info &>/dev/null || die "Cannot talk to the Docker daemon (is it running? permissions?)"
  [[ "$SETUP" == "C" ]] || check_dependency trivy
  if [[ "$SETUP" == "C" || "$SETUP" == "D" ]]; then check_dependency aws; fi
fi

# Semgrep engine: local CLI first, else the semgrep/semgrep Docker image (path mounted read-only)
SEMGREP_ENGINE=""
SEMGREP_IMAGE="semgrep/semgrep"
if [[ ${#SEMGREP_PATHS[@]} -gt 0 ]]; then
  if command -v semgrep &>/dev/null; then
    SEMGREP_ENGINE="cli"
  elif command -v docker &>/dev/null && docker info &>/dev/null; then
    SEMGREP_ENGINE="docker"
  else
    die "'semgrep' is not installed and Docker is not available as a fallback.
  Install it with:  pipx install semgrep   (or: pip install semgrep)
  Or run it with Docker:  docker run --rm -v \"\$PWD:/src\" semgrep/semgrep semgrep scan --config auto /src"
  fi
fi

# -----------------------------------------------------------------------------
# Report directory and output helpers
# -----------------------------------------------------------------------------
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
[[ -n "$REPORT_DIR" ]] || REPORT_DIR="./scan-reports/$(date '+%Y%m%d-%H%M%S')"
RAW_DIR="$REPORT_DIR/images"
mkdir -p "$RAW_DIR" "$RESULT_CACHE"
REPORT_TXT="$REPORT_DIR/scan-report.txt"
: > "$REPORT_TXT"

# log: print message to the terminal and a colour-free copy to the report file
log() {
  printf '%s\n' "$1"
  printf '%s\n' "$1" | sed $'s/\x1b\\[[0-9;]*m//g' >> "$REPORT_TXT"
}

log_section() {
  log ""
  log "${CYAN}============================================================${NC}"
  log "${CYAN}  $1${NC}"
  log "${CYAN}============================================================${NC}"
}

log_pass() { log "${GREEN}  [PASS]${NC} $1"; }
log_fail() { log "${RED}  [FAIL]${NC} $1"; FAIL=true; CFG_FAILS=$((CFG_FAILS + 1)); }
log_warn() { log "${YELLOW}  [WARN]${NC} $1"; }
log_info() { log "${BLUE}  [INFO]${NC} $1"; }
CFG_FAILS=0

log "${CYAN}Docker Security Scanner${NC}"
log "Setup:      $SETUP"
log "Images:     ${#IMAGES[@]}"
log "Timestamp:  $TIMESTAMP"
log "Report dir: $REPORT_DIR"
[[ -n "$COMPOSE_FILE" ]] && log "Compose:    $COMPOSE_FILE"
[[ -n "$OUTPUT_FILE"  ]] && log "Output:     $OUTPUT_FILE"
[[ -n "$AWS_PROFILE"  ]] && log "Profile:    $AWS_PROFILE"
[[ ${#SEMGREP_PATHS[@]} -gt 0 ]] && log "Semgrep:    ${SEMGREP_PATHS[*]} (engine: $SEMGREP_ENGINE)"

SECRET_PATTERNS='PASSWORD|SECRET|TOKEN|KEY|CREDENTIAL|PRIVATE'

# Env var names that match SECRET_PATTERNS but are public identifiers, not secrets:
# GPG_KEY (public key ID in python/postgres bases), *_KEY_ID and *PUBLIC_KEY, unless the
# name also contains a strong secret word (PASSWORD, SECRET, TOKEN, PRIVATE, CREDENTIAL).
filter_secret_env() {
  local name up
  while IFS= read -r name; do
    [[ -n "$name" ]] || continue
    up="${name^^}"
    if [[ "$up" == "GPG_KEY" ]]; then continue; fi
    if [[ "$up" =~ (_KEY_ID|PUBLIC_KEY)$ && ! "$up" =~ PASSWORD|SECRET|TOKEN|PRIVATE|CREDENTIAL ]]; then continue; fi
    printf '%s\n' "$name"
  done
}
safe_name() { printf '%s' "${1//[^A-Za-z0-9._-]/_}"; }

# =============================================================================
# SECTION 0 — SEMGREP STATIC ANALYSIS (source code, before the image is built)
# Finds flaws in your own code; Trivy (section 4) covers dependencies/OS packages.
# semgrep exits 0 on findings unless --error is passed, so rc 0/1 = scan done,
# anything else (or an unreadable JSON) = tool failure (exit 2).
# =============================================================================
SG_DIR="$REPORT_DIR/semgrep"
SG_ITEMS="$REPORT_DIR/.semgrep.jsonl"
: > "$SG_ITEMS"
SG_GATE_SEV="${SEMGREP_SEVERITY:-ERROR}"
SG_FINDINGS=0
SG_EXCLUDES=(node_modules .git venv .venv dist build __pycache__ vendor)

# jq: one summary object from a Semgrep JSON report (findings sorted by severity)
SG_JQ='
def sev: (.extra.severity // "INFO" | ascii_upcase
          | if . == "CRITICAL" or . == "HIGH" then "ERROR" elif . == "MEDIUM" then "WARNING"
            elif . == "ERROR" or . == "WARNING" or . == "INFO" then . else "INFO" end);
def rank: {"ERROR": 3, "WARNING": 2, "INFO": 1}[.];
. as $d | [$d.results[]? | { severity: sev, check_id: .check_id, rule: (.check_id | split(".") | last),
    file: (.path | ltrimstr("/src/")), line: .start.line,
    message: ((.extra.message // "") | gsub("\\s+"; " ") | if length > 120 then .[:117] + "..." else . end) }]
| sort_by([-(.severity | rank), .file, .line]) as $f
| { path: $path, engine: $engine, configs: $configs, report: $report,
    files_scanned: (($d.paths.scanned // []) | length),
    scan_errors: [$d.errors[]? | ((.level // "error") + ": " + ((.message // .long_msg // "unknown error") | gsub("\\s+"; " ") | .[:200]))],
    counts: { error: ([$f[] | select(.severity == "ERROR")] | length),
              warning: ([$f[] | select(.severity == "WARNING")] | length),
              info: ([$f[] | select(.severity == "INFO")] | length) },
    gate_severity: $gate,
    gate_findings: ([$f[] | select((.severity | rank) >= ($gate | rank))] | length),
    status: "OK", findings: $f }'

# render_semgrep <summary-json> <max-per-severity-or-0-for-all>: findings grouped by severity
render_semgrep() {
  jq -r --argjson max "$2" '
    . as $s
    | "  \(.path): \(.findings|length) finding(s)  ERROR=\(.counts.error) WARNING=\(.counts.warning) INFO=\(.counts.info)  files scanned=\(.files_scanned)",
      ( ["ERROR","WARNING","INFO"][] as $sev
        | [$s.findings[] | select(.severity == $sev)] as $g
        | select(($g|length) > 0)
        | "    \($sev) (\($g|length))",
          (if $max > 0 then $g[:$max] else $g end | .[] | "      \(.rule)  \(.file):\(.line)  \(.message)"),
          (if $max > 0 and ($g|length) > $max then "      ... \(($g|length) - $max) more (see the JSON/TXT report)" else empty end) )' <<<"$1"
}

# run_semgrep <path>: scans one path, appends a summary object to $SG_ITEMS
run_semgrep() {
  local path="$1" abs safe out err rc=0 dir target item cfg n=0 summary_cfgs
  abs=$(realpath "$path"); safe=$(safe_name "$abs")
  out="$SG_DIR/$safe.json"; err="$SG_DIR/$safe.err"
  log_info "Semgrep: $path (rules: ${SEMGREP_CONFIGS[*]})"
  [[ -f "$abs/.semgrepignore" || -f "$(dirname "$abs")/.semgrepignore" ]] && log_info "Using .semgrepignore"

  local sev_args=() exc_args=() cfg_args=() mounts=()
  [[ -n "$SEMGREP_SEVERITY" ]] && sev_args=(--severity "$SEMGREP_SEVERITY")
  for e in "${SG_EXCLUDES[@]}"; do exc_args+=(--exclude "$e"); done

  if [[ "$SEMGREP_ENGINE" == "cli" ]]; then
    for cfg in "${SEMGREP_CONFIGS[@]}"; do cfg_args+=(--config "$cfg"); done
    semgrep scan "${cfg_args[@]}" --json --output "$out.tmp" --metrics off --quiet \
      --disable-version-check "${sev_args[@]}" "${exc_args[@]}" "$path" >/dev/null 2>"$err" || rc=$?
  else
    log_warn "semgrep CLI not found: running Semgrep through Docker ($SEMGREP_IMAGE, path mounted read-only)"
    if [[ -d "$abs" ]]; then dir="$abs"; target="/src"; else dir="$(dirname "$abs")"; target="/src/$(basename "$abs")"; fi
    mounts=(-v "$dir:/src:ro")
    for cfg in "${SEMGREP_CONFIGS[@]}"; do
      if [[ -e "$cfg" ]]; then
        n=$((n + 1)); mounts+=(-v "$(realpath "$cfg"):/cfg/$n:ro"); cfg_args+=(--config "/cfg/$n")
      else
        cfg_args+=(--config "$cfg")
      fi
    done
    docker run --rm "${mounts[@]}" "$SEMGREP_IMAGE" semgrep scan "${cfg_args[@]}" --json --metrics off \
      --quiet --disable-version-check "${sev_args[@]}" "${exc_args[@]}" "$target" >"$out.tmp" 2>"$err" || rc=$?
  fi

  if (( rc > 1 )) || ! jq -e '.results' "$out.tmp" >/dev/null 2>&1; then
    rm -f "$out.tmp"
    log_fail "Semgrep failed on $path (exit $rc) — see $err"
    tail -5 "$err" | while IFS= read -r l; do log "         $l"; done
    SCAN_ERRORS=$((SCAN_ERRORS + 1))
    jq -n --arg path "$path" --arg engine "$SEMGREP_ENGINE" --arg gate "$SG_GATE_SEV" \
      '{ path: $path, engine: $engine, status: "TOOL_ERROR", gate_severity: $gate, gate_findings: 0,
         counts: {error: 0, warning: 0, info: 0}, files_scanned: 0, scan_errors: [], findings: [] }' >> "$SG_ITEMS"
    return 0
  fi
  mv "$out.tmp" "$out"

  summary_cfgs=$(printf '%s\n' "${SEMGREP_CONFIGS[@]}" | jq -R . | jq -s .)
  item=$(jq -c --arg path "$path" --arg engine "$SEMGREP_ENGINE" --arg gate "$SG_GATE_SEV" \
          --arg report "$out" --argjson configs "$summary_cfgs" "$SG_JQ" "$out")
  printf '%s\n' "$item" >> "$SG_ITEMS"
  render_semgrep "$item" 0 > "$SG_DIR/$safe.txt"

  while IFS= read -r l; do log "$l"; done < <(render_semgrep "$item" 20)
  while IFS= read -r l; do log_warn "Semgrep scan error: $l"; done < <(jq -r '.scan_errors[:5][]' <<<"$item")
  local gate_n total
  gate_n=$(jq -r '.gate_findings' <<<"$item"); total=$(jq -r '.findings | length' <<<"$item")
  SG_FINDINGS=$((SG_FINDINGS + total))
  if (( gate_n > 0 )); then
    log_fail "Semgrep: $gate_n finding(s) at severity $SG_GATE_SEV or above in $path"
  else
    log_pass "Semgrep: no finding at severity $SG_GATE_SEV or above in $path"
  fi
  log_info "Semgrep reports: $out and $SG_DIR/$safe.txt"
}

if [[ ${#SEMGREP_PATHS[@]} -gt 0 ]]; then
  log_section "Semgrep Static Analysis (SAST)"
  mkdir -p "$SG_DIR"
  if [[ " ${SEMGREP_CONFIGS[*]} " == *" auto "* ]]; then
    log_info "--config auto fetches rules from the Semgrep registry (network needed); local rule files work offline"
  fi
  for sp in "${SEMGREP_PATHS[@]}"; do run_semgrep "$sp"; done
fi

# =============================================================================
# SECTION 1/2 — IMAGE INSPECT + RUNNING CONTAINER INSPECT (all setups)
# Uses docker's own --format templates (no fragile grep on JSON).
# =============================================================================
declare -A IMG_ID IMG_PRESENT IMG_CFG_FAILS

check_image_config() {
  local img="$1" user ports envnames cid cj
  CFG_FAILS=0
  log_section "Image checks: $img"

  if ! docker image inspect "$img" &>/dev/null; then
    log_fail "Image '$img' not found locally. Pull or build it first."
    IMG_PRESENT[$img]=false
    IMG_CFG_FAILS[$img]=$CFG_FAILS
    return 0
  fi
  IMG_PRESENT[$img]=true
  IMG_ID[$img]=$(docker image inspect -f '{{.Id}}' "$img")

  user=$(docker image inspect -f '{{.Config.User}}' "$img")
  if [[ -z "$user" || "$user" == "root" || "$user" == "0" || "$user" == "0:0" || "$user" == root:* ]]; then
    log_fail "Image runs as root (User: '${user:-not set}')"
  else
    log_pass "Image user: $user"
  fi

  ports=$(docker image inspect -f '{{json .Config.ExposedPorts}}' "$img")
  if [[ -n "$ports" && "$ports" != "null" && "$ports" != "{}" ]]; then
    log_info "Exposed ports in image: $ports"
  else
    log_info "No ports exposed in image"
  fi

  # Only variable NAMES are inspected so secret values never reach the report
  envnames=$(docker image inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$img" | cut -d= -f1 | grep -Ei "$SECRET_PATTERNS" | filter_secret_env || true)
  if [[ -n "$envnames" ]]; then
    log_fail "Potential secret in image ENV vars (names): $(echo "$envnames" | paste -sd, -)"
  else
    log_pass "No obvious secrets found in image ENV vars"
  fi

  cid=$(docker ps --filter "ancestor=$img" --format '{{.ID}}' | head -1)
  if [[ -z "$cid" ]]; then
    log_warn "No running container found for '$img'. Skipping runtime checks."
  else
    log_info "Inspecting container: $cid"
    local ro priv sec capadd capdrop net mem quota nano ruser
    ro=$(docker inspect -f '{{.HostConfig.ReadonlyRootfs}}' "$cid")
    priv=$(docker inspect -f '{{.HostConfig.Privileged}}' "$cid")
    sec=$(docker inspect -f '{{json .HostConfig.SecurityOpt}}' "$cid")
    capadd=$(docker inspect -f '{{json .HostConfig.CapAdd}}' "$cid")
    capdrop=$(docker inspect -f '{{json .HostConfig.CapDrop}}' "$cid")
    net=$(docker inspect -f '{{.HostConfig.NetworkMode}}' "$cid")
    mem=$(docker inspect -f '{{.HostConfig.Memory}}' "$cid")
    quota=$(docker inspect -f '{{.HostConfig.CpuQuota}}' "$cid")
    nano=$(docker inspect -f '{{.HostConfig.NanoCpus}}' "$cid")
    ruser=$(docker inspect -f '{{.Config.User}}' "$cid")

    [[ "$ro" == "true" ]] && log_pass "ReadonlyRootFilesystem: true" \
      || log_fail "ReadonlyRootFilesystem: false — root filesystem is writable"
    [[ "$priv" == "false" ]] && log_pass "Privileged: false" \
      || log_fail "Privileged: true — container is running in privileged mode"
    if grep -q 'no-new-privileges' <<<"$sec"; then
      log_pass "no-new-privileges: set"
    else
      log_fail "no-new-privileges not set — privilege escalation is allowed"
    fi
    if [[ "$capadd" == "null" || "$capadd" == "[]" ]]; then
      log_pass "CapAdd: none"
    else
      log_warn "CapAdd: $capadd — verify these are justified in DockerSecuritySpec.md"
    fi
    if grep -qi 'ALL' <<<"$capdrop"; then
      log_pass "CapDrop: ALL"
    else
      log_fail "CapDrop does not include ALL: $capdrop"
    fi
    [[ "$net" == "host" ]] && log_fail "NetworkMode: host — host network mode is not allowed" \
      || log_pass "NetworkMode: $net"
    if [[ "$mem" == "0" ]]; then log_fail "Memory limit not set"; else log_pass "Memory limit: $mem bytes"; fi
    if [[ "$quota" == "0" && "$nano" == "0" ]]; then
      log_fail "CPU limit not set (CpuQuota: 0, NanoCpus: 0)"
    else
      log_pass "CPU limit: quota=$quota nanocpus=$nano"
    fi
    if [[ -z "$ruser" || "$ruser" == "root" || "$ruser" == "0" ]]; then
      log_fail "Container running as root (User: '${ruser:-not set}')"
    else
      log_pass "Container user: $ruser"
    fi
  fi
  IMG_CFG_FAILS[$img]=$CFG_FAILS
}

if [[ "$HAVE_IMAGES" == true ]]; then
  for img in "${IMAGES[@]}"; do
    check_image_config "$img"
  done
fi

# =============================================================================
# SECTION 3 — DOCKER COMPOSE INSPECT (Setup A and B only)
# =============================================================================
if [[ "$SETUP" == "A" || "$SETUP" == "B" ]] && [[ -n "$COMPOSE_FILE" ]]; then
  log_section "Docker Compose File Checks"
  CFG_FAILS=0

  if [[ ! -f "$COMPOSE_FILE" ]]; then
    log_fail "Compose file not found: $COMPOSE_FILE"
  else
    log_info "Checking: $COMPOSE_FILE"

    grep -q "read_only: true" "$COMPOSE_FILE" && log_pass "read_only: true found in compose file" \
      || log_fail "read_only: true not found — root filesystem may be writable"
    grep -q "privileged: true" "$COMPOSE_FILE" && log_fail "privileged: true found in compose file" \
      || log_pass "No privileged: true found"
    grep -q "network_mode: host" "$COMPOSE_FILE" && log_fail "network_mode: host found in compose file" \
      || log_pass "No network_mode: host found"
    grep -q "no-new-privileges" "$COMPOSE_FILE" && log_pass "no-new-privileges found in compose file" \
      || log_fail "no-new-privileges not set in security_opt"
    grep -q "mem_limit" "$COMPOSE_FILE" && log_pass "mem_limit found in compose file" \
      || log_fail "mem_limit not set"
    grep -q "cap_drop" "$COMPOSE_FILE" && grep -qw "ALL" "$COMPOSE_FILE" && log_pass "cap_drop ALL found in compose file" \
      || log_fail "cap_drop ALL not found"

    if grep -iE "PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE_KEY|CREDENTIAL" "$COMPOSE_FILE" | grep -v "secrets:" | grep -v "#" | grep -q "="; then
      log_fail "Potential hardcoded secret found in compose file env vars"
    else
      log_pass "No obvious hardcoded secrets in compose file"
    fi

    grep -q ":latest" "$COMPOSE_FILE" && log_fail ":latest tag found in compose file — use specific tags in production" \
      || log_pass "No :latest tags found"
  fi
fi

# =============================================================================
# SECTION 4 — TRIVY SCAN (Setup A, B, D)
# One JSON report per image; counts come from the JSON, not from grepping
# the table output (the old grep counted lines, not vulnerabilities).
# =============================================================================
ROWS_TSV="$REPORT_DIR/.rows.tsv"
: > "$ROWS_TSV"

if [[ "$SETUP" != "C" && "$HAVE_IMAGES" == true ]]; then
  log_section "Trivy Vulnerability Scan"

  # Refresh the DB once, before the parallel workers start (avoids download races)
  if [[ "$SKIP_DB_UPDATE" == true ]]; then
    log_info "Skipping Trivy DB update (--skip-db-update)"
  else
    log_info "Updating Trivy vulnerability DB (cache: $TRIVY_CACHE_DIR)"
    if ! trivy image --download-db-only --quiet --cache-dir "$TRIVY_CACHE_DIR" 2>"$REPORT_DIR/db-update.err"; then
      if [[ -s "$TRIVY_CACHE_DIR/db/trivy.db" ]]; then
        log_warn "DB update failed, using existing (possibly stale) DB. See $REPORT_DIR/db-update.err"
      else
        die "Trivy DB update failed and no local DB exists. See $REPORT_DIR/db-update.err"
      fi
    fi
  fi
  [[ -s "$TRIVY_CACHE_DIR/db/trivy.db" ]] || die "No Trivy DB at $TRIVY_CACHE_DIR/db"
  DB_STAMP=$(jq -r '.UpdatedAt // "unknown"' "$TRIVY_CACHE_DIR/db/metadata.json" 2>/dev/null | tr -c 'A-Za-z0-9\n' '_')
  log_info "Trivy DB updated at: ${DB_STAMP}"

  TRIVY_SCANNERS="vuln"
  [[ "$SCAN_SECRETS" == true ]] && TRIVY_SCANNERS="vuln,secret"

  # scan_one <image> <safe-name> <image-id>; runs in a background subshell
  scan_one() {
    local img="$1" safe="$2" id="$3"
    local out="$RAW_DIR/$safe.json" err="$RAW_DIR/$safe.err"
    local cached="$RESULT_CACHE/${id#sha256:}_${DB_STAMP}_${TRIVY_SCANNERS//,/-}.json"

    if [[ "$FORCE" != true && -s "$cached" ]]; then
      cp "$cached" "$out"; echo cached > "$RAW_DIR/$safe.status"; return 0
    fi
    # --image-src docker: scan exactly the local image, never a same-named registry image
    # --cache-backend memory: no shared fanal.db lock, so parallel scans do not collide
    if trivy image \
        --image-src docker \
        --scanners "$TRIVY_SCANNERS" \
        --severity CRITICAL,HIGH,MEDIUM,LOW,UNKNOWN \
        --list-all-pkgs \
        --format json \
        --skip-db-update \
        --cache-backend memory \
        --cache-dir "$TRIVY_CACHE_DIR" \
        --no-progress \
        --output "$out.tmp" \
        "$img" 2>"$err" && jq -e . "$out.tmp" >/dev/null 2>>"$err"; then
      mv "$out.tmp" "$out"
      cp "$out" "$cached"
      echo scanned > "$RAW_DIR/$safe.status"
    else
      rm -f "$out.tmp"
      echo error > "$RAW_DIR/$safe.status"
    fi
  }

  PRESENT=()
  for img in "${IMAGES[@]}"; do
    [[ "${IMG_PRESENT[$img]}" == true ]] && PRESENT+=("$img")
  done

  log_info "Scanning ${#PRESENT[@]} image(s) with $JOBS parallel job(s)"
  n=0
  for img in "${PRESENT[@]}"; do
    n=$((n + 1))
    while (( $(jobs -rp | wc -l) >= JOBS )); do wait -n || true; done
    log_info "[$n/${#PRESENT[@]}] $img"
    scan_one "$img" "$(safe_name "$img")" "${IMG_ID[$img]}" &
  done
  wait || true

  # ---- collect results into one TSV row per image ----
  # columns: image, id, os, pkgs, os_pkgs, lang_pkgs, crit, high, med, low, unk, fixable, cfg_fails, status
  for img in "${IMAGES[@]}"; do
    safe=$(safe_name "$img")
    if [[ "${IMG_PRESENT[$img]}" != true ]]; then
      printf '%s\t-\t-\t0\t0\t0\t0\t0\t0\t0\t0\t0\t%s\tNOT_FOUND\n' "$img" "${IMG_CFG_FAILS[$img]}" >> "$ROWS_TSV"
      SCAN_ERRORS=$((SCAN_ERRORS + 1)); FAIL=true
      continue
    fi
    status=$(cat "$RAW_DIR/$safe.status" 2>/dev/null || echo error)
    short_id="${IMG_ID[$img]#sha256:}"; short_id="${short_id:0:12}"
    if [[ "$status" == "error" ]]; then
      log_fail "Trivy scan failed for $img — see $RAW_DIR/$safe.err"
      tail -5 "$RAW_DIR/$safe.err" | while IFS= read -r l; do log "         $l"; done
      printf '%s\t%s\t-\t0\t0\t0\t0\t0\t0\t0\t0\t0\t%s\tSCAN_ERROR\n' "$img" "$short_id" "${IMG_CFG_FAILS[$img]}" >> "$ROWS_TSV"
      SCAN_ERRORS=$((SCAN_ERRORS + 1))
      continue
    fi

    row=$(jq -r --arg img "$img" --arg id "$short_id" --arg cfg "${IMG_CFG_FAILS[$img]}" '
      ([.Results[]? | (.Vulnerabilities // [])[]]) as $v
      | ([.Results[]? | select(.Class == "os-pkgs")   | (.Packages // [])[]] | length) as $os
      | ([.Results[]? | select(.Class == "lang-pkgs") | (.Packages // [])[]] | length) as $lang
      | [ $img, $id,
          (if .Metadata.OS.Family then "\(.Metadata.OS.Family) \(.Metadata.OS.Name)" else "-" end),
          ($os + $lang), $os, $lang,
          ([$v[] | select(.Severity == "CRITICAL")] | length),
          ([$v[] | select(.Severity == "HIGH")]     | length),
          ([$v[] | select(.Severity == "MEDIUM")]   | length),
          ([$v[] | select(.Severity == "LOW")]      | length),
          ([$v[] | select(.Severity == "UNKNOWN")]  | length),
          ([$v[] | select((.FixedVersion // "") != "")] | length),
          $cfg, "OK" ] | @tsv' "$RAW_DIR/$safe.json")
    printf '%s\n' "$row" >> "$ROWS_TSV"

    # human-readable table for CRITICAL/HIGH, derived from the same JSON (no rescan)
    if ! trivy convert --format table --severity CRITICAL,HIGH \
          --output "$RAW_DIR/$safe.table.txt" "$RAW_DIR/$safe.json" 2>>"$RAW_DIR/$safe.err"; then
      log_warn "Could not render table for $img (JSON is still available)"
    fi
  done
fi

# =============================================================================
# SECTION 5 — ECR SCAN (Setup C, D)
# =============================================================================
if [[ "$HAVE_IMAGES" == true && ( "$SETUP" == "C" || "$SETUP" == "D" ) ]]; then
  log_section "ECR Scan Results"
  CFG_FAILS=0
  IMAGE="${IMAGES[0]}"

  # Tag = text after the last ':' only if it comes after the last '/' (registry ports contain ':')
  last="${IMAGE##*/}"
  if [[ "$last" == *:* ]]; then IMAGE_TAG="${last##*:}"; else IMAGE_TAG="latest"; fi

  AWS_ARGS=(--region "$AWS_REGION")
  [[ -n "$AWS_PROFILE" ]] && AWS_ARGS+=(--profile "$AWS_PROFILE")

  log_info "Waiting for ECR scan to complete..."
  if ! aws ecr wait image-scan-complete --repository-name "$ECR_REPO" \
        --image-id "imageTag=$IMAGE_TAG" "${AWS_ARGS[@]}" 2>"$REPORT_DIR/ecr-wait.err"; then
    log_warn "ECR wait did not confirm scan completion (see $REPORT_DIR/ecr-wait.err)"
  fi

  log_info "Fetching ECR scan findings for $ECR_REPO:$IMAGE_TAG"
  if ! ECR_FINDINGS=$(aws ecr describe-image-scan-findings \
        --repository-name "$ECR_REPO" --image-id "imageTag=$IMAGE_TAG" "${AWS_ARGS[@]}" \
        --query "imageScanFindings.findingSeverityCounts" --output json 2>"$REPORT_DIR/ecr-findings.err"); then
    log_fail "Could not fetch ECR scan findings (see $REPORT_DIR/ecr-findings.err)"
    SCAN_ERRORS=$((SCAN_ERRORS + 1))
    ECR_FINDINGS="{}"
  fi
  [[ -n "$ECR_FINDINGS" && "$ECR_FINDINGS" != "null" ]] || ECR_FINDINGS="{}"
  log_info "ECR Scan Results: $(jq -c . <<<"$ECR_FINDINGS")"

  ECR_CRITICAL=$(jq -r '.CRITICAL // 0' <<<"$ECR_FINDINGS")
  ECR_HIGH=$(jq -r '.HIGH // 0'         <<<"$ECR_FINDINGS")
  ECR_MEDIUM=$(jq -r '.MEDIUM // 0'     <<<"$ECR_FINDINGS")
  ECR_LOW=$(jq -r '.LOW // 0'           <<<"$ECR_FINDINGS")

  log_info "ECR Summary: CRITICAL=$ECR_CRITICAL HIGH=$ECR_HIGH MEDIUM=$ECR_MEDIUM LOW=$ECR_LOW"
  (( ECR_CRITICAL > 0 )) && log_fail "ECR: CRITICAL vulnerabilities found — deployment must be blocked"
  (( ECR_HIGH > 0 ))     && log_fail "ECR: HIGH vulnerabilities found — must be fixed within 3 days"
  (( ECR_MEDIUM > 0 ))   && log_warn "ECR: MEDIUM vulnerabilities found — must be fixed within 30 days"
  (( ECR_LOW > 0 ))      && log_warn "ECR: LOW vulnerabilities found — fix in next scheduled maintenance"
  if (( ECR_CRITICAL == 0 && ECR_HIGH == 0 )); then log_pass "ECR: No CRITICAL or HIGH vulnerabilities found"; fi
fi

# =============================================================================
# SUMMARY — table on screen + summary.csv / summary.json / summary.md
# =============================================================================
log_section "Summary"

if [[ "$SETUP" != "C" && -s "$ROWS_TSV" ]]; then
  # Result column from severity thresholds in DockerSecuritySpec.md section 11
  RESULTS_TSV="$REPORT_DIR/.results.tsv"
  awk -F'\t' 'BEGIN{OFS="\t"} {
      r = $14
      if (r == "OK") { r = ($7 > 0 || $8 > 0) ? "FAIL" : (($9 > 0) ? "WARN" : "PASS") }
      print $0, r
    }' "$ROWS_TSV" | sort -t$'\t' -k7,7nr -k8,8nr -k1,1 > "$RESULTS_TSV"
  # columns now: 1 image 2 id 3 os 4 pkgs 5 os_pkgs 6 lang_pkgs 7 C 8 H 9 M 10 L 11 U 12 fixable 13 cfg_fails 14 scan_status 15 result

  w=$(awk -F'\t' '{ if (length($1) > m) m = length($1) } END { print (m < 5 ? 5 : m) }' "$RESULTS_TSV")
  fmt="  %-${w}s  %-12s  %-18s  %5s  %4s  %4s  %5s  %4s  %4s  %5s  %-6s\n"
  # shellcheck disable=SC2059
  hdr=$(printf "$fmt" IMAGE ID OS PKGS CRIT HIGH MED LOW UNK FIXED RESULT)
  log "$hdr"
  log "  $(printf '%*s' $(( ${#hdr} - 3 )) '' | tr ' ' '-')"
  while IFS=$'\t' read -r i id os pk _ _ c h m l u fx _ _ res; do
    case "$res" in
      FAIL|SCAN_ERROR|NOT_FOUND) col="$RED" ;;
      WARN) col="$YELLOW" ;;
      *) col="$GREEN" ;;
    esac
    # shellcheck disable=SC2059
    line=$(printf "$fmt" "$i" "$id" "$os" "$pk" "$c" "$h" "$m" "$l" "$u" "$fx" "$res")
    log "${col}${line}${NC}"
  done < "$RESULTS_TSV"
  log ""
  log_info "PKGS = OS + language packages found by Trivy (list-all-pkgs); counts are per CVE finding."
  log_info "FIXED = findings that have a fixed version available. UNK = UNKNOWN severity."

  # --- CSV ---
  {
    echo "image,image_id,os,packages,os_packages,language_packages,critical,high,medium,low,unknown,fixable,config_check_failures,scan_status,result"
    awk -F'\t' 'BEGIN{OFS=","} { for (k = 1; k <= NF; k++) gsub(/"/, "\"\"", $k); $1 = "\"" $1 "\""; $3 = "\"" $3 "\""; print }' "$RESULTS_TSV"
  } > "$REPORT_DIR/summary.csv"

  # --- JSON ---
  jq -R -s --arg ts "$TIMESTAMP" --arg setup "$SETUP" '
    split("\n") | map(select(length > 0) | split("\t")) as $rows
    | { generated: $ts, setup: $setup,
        images: [ $rows[] | { image: .[0], image_id: .[1], os: .[2],
            packages: (.[3]|tonumber), os_packages: (.[4]|tonumber), language_packages: (.[5]|tonumber),
            vulnerabilities: { critical: (.[6]|tonumber), high: (.[7]|tonumber), medium: (.[8]|tonumber),
                               low: (.[9]|tonumber), unknown: (.[10]|tonumber), fixable: (.[11]|tonumber) },
            config_check_failures: (.[12]|tonumber), scan_status: .[13], result: .[14] } ] }' \
    "$RESULTS_TSV" > "$REPORT_DIR/summary.json"

  # --- Markdown ---
  {
    echo "# Docker Security Scan Summary"
    echo
    echo "Generated: $TIMESTAMP  |  Setup: $SETUP  |  Images: ${#IMAGES[@]}"
    echo
    echo "| Image | ID | OS | Packages | Critical | High | Medium | Low | Unknown | Fixable | Result |"
    echo "|---|---|---|---:|---:|---:|---:|---:|---:|---:|---|"
    awk -F'\t' '{ printf "| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n", $1,$2,$3,$4,$7,$8,$9,$10,$11,$12,$15 }' "$RESULTS_TSV"
  } > "$REPORT_DIR/summary.md"

  tot=$(awk -F'\t' '{c+=$7; h+=$8; m+=$9; l+=$10; p+=$4} END {printf "%d images, %d packages, CRITICAL=%d HIGH=%d MEDIUM=%d LOW=%d", NR, p, c, h, m, l}' "$RESULTS_TSV")
  log_info "Totals: $tot"
  log_info "Reports: $REPORT_DIR/summary.{csv,json,md}, per-image JSON in $RAW_DIR/"

  # Spec thresholds (section 11): CRITICAL/HIGH block, MEDIUM warns, LOW logged
  if awk -F'\t' '$7 > 0' "$RESULTS_TSV" | grep -q .; then
    log_fail "CRITICAL vulnerabilities found — deployment must be blocked"
  fi
  if awk -F'\t' '$8 > 0' "$RESULTS_TSV" | grep -q .; then
    log_fail "HIGH vulnerabilities found — must be fixed within 3 days"
  fi
  if awk -F'\t' '$9 > 0' "$RESULTS_TSV" | grep -q .; then
    log_warn "MEDIUM vulnerabilities found — must be fixed within 30 days"
  fi
  if awk -F'\t' '$10 > 0' "$RESULTS_TSV" | grep -q .; then
    log_info "LOW vulnerabilities found — fix in next scheduled maintenance"
  fi
  rm -f "$ROWS_TSV" "$RESULTS_TSV"
fi
rm -f "$ROWS_TSV"

# -----------------------------------------------------------------------------
# Semgrep summary: "semgrep" array in summary.json, section in summary.md, and a
# separate semgrep-summary.csv (its columns differ from the per-image summary.csv)
# -----------------------------------------------------------------------------
if [[ ${#SEMGREP_PATHS[@]} -gt 0 ]]; then
  SG_ARR=$(jq -s 'map(del(.findings[20:]))' "$SG_ITEMS")   # top 20 per path; full list in <report-dir>/semgrep/*.json
  if [[ -s "$REPORT_DIR/summary.json" ]]; then
    jq --argjson sg "$SG_ARR" '. + { semgrep: $sg }' "$REPORT_DIR/summary.json" > "$REPORT_DIR/summary.json.tmp" \
      && mv "$REPORT_DIR/summary.json.tmp" "$REPORT_DIR/summary.json"
  else
    jq -n --arg ts "$TIMESTAMP" --arg setup "$SETUP" --argjson sg "$SG_ARR" \
      '{ generated: $ts, setup: $setup, images: [], semgrep: $sg }' > "$REPORT_DIR/summary.json"
  fi
  {
    echo "path,engine,status,files_scanned,error,warning,info,gate_severity,gate_findings,scan_errors"
    jq -r '.[] | [.path, .engine, .status, .files_scanned, .counts.error, .counts.warning, .counts.info,
                  .gate_severity, .gate_findings, (.scan_errors | length)] | @csv' <<<"$SG_ARR"
  } > "$REPORT_DIR/semgrep-summary.csv"
  [[ -s "$REPORT_DIR/summary.md" ]] || {
    echo "# Docker Security Scan Summary"; echo
    echo "Generated: $TIMESTAMP  |  Setup: $SETUP  |  Images: ${#IMAGES[@]}"
  } > "$REPORT_DIR/summary.md"
  {
    echo; echo "## Semgrep (static analysis)"; echo
    echo "| Path | Engine | Files scanned | Error | Warning | Info | Gate (>=) | Gate findings | Status |"
    echo "|---|---|---:|---:|---:|---:|---|---:|---|"
    jq -r '.[] | "| \(.path) | \(.engine) | \(.files_scanned) | \(.counts.error) | \(.counts.warning) | \(.counts.info) | \(.gate_severity) | \(.gate_findings) | \(.status) |"' <<<"$SG_ARR"
    while IFS= read -r item; do
      echo; echo '```text'; render_semgrep "$item" 20; echo '```'
    done < <(jq -c '.[]' <<<"$SG_ARR")
  } >> "$REPORT_DIR/summary.md"
  log_info "Semgrep totals: $SG_FINDINGS finding(s) in ${#SEMGREP_PATHS[@]} path(s); see $REPORT_DIR/semgrep-summary.csv and the semgrep section of summary.json/md"
fi

# =============================================================================
# REMEDIATION — what to upgrade, per image (reads the Trivy JSON already written)
# =============================================================================
# jq: highest version among comma-separated FixedVersion lists (heuristic: numeric-aware key)
REM_JQ='
def vkey: [scan("[0-9]+|[A-Za-z]+") | (tonumber? // .)];
def fixes($cls):
  [ .Results[]? | select(.Class == $cls) | . as $r | (.Vulnerabilities // [])[]
    | select(.Severity == "CRITICAL" or .Severity == "HIGH")
    | select((.FixedVersion // "") != "")
    | { target: $r.Target, type: $r.Type, pkg: .PkgName, installed: .InstalledVersion,
        fixed: .FixedVersion, sev: .Severity, id: .VulnerabilityID } ]
  | group_by([.target, .pkg, .installed])
  | map({ package: .[0].pkg, installed: .[0].installed,
          fixed: ([.[].fixed | split(", ")[]] | max_by(vkey)),
          cves: ([.[].id] | unique | length),
          severity: (if any(.[]; .sev == "CRITICAL") then "CRITICAL" else "HIGH" end),
          target: .[0].target, type: .[0].type })
  | sort_by([(if .severity == "CRITICAL" then 0 else 1 end), .package]);
{ image: $img,
  os: (if .Metadata.OS.Family then "\(.Metadata.OS.Family) \(.Metadata.OS.Name)" else null end),
  os_packages: (fixes("os-pkgs") | map(del(.target, .type))),
  app_dependencies: fixes("lang-pkgs"),
  unfixable: ([.Results[]? | (.Vulnerabilities // [])[]
               | select(.Severity == "CRITICAL" or .Severity == "HIGH")
               | select((.FixedVersion // "") == "")] | length),
  base_image_advice: $advice }'

# base_advice <image> <os-family>: concise heuristic bullets (no network calls), one per line
base_advice() {
  local img="$1" fam="$2" name tag repo
  name="${img##*/}"; repo="${name%%:*}"
  tag=""; [[ "$name" == *:* ]] && tag="${name#*:}"
  if [[ "$fam" == "debian" || "$fam" == "ubuntu" ]] \
     && [[ " postgres python node redis nginx httpd php ruby golang memcached rabbitmq haproxy " == *" $repo "* ]] \
     && [[ "$tag" != *alpine* && "$tag" != *slim* ]]; then
    printf '%s\n' "Image is $fam-based: try the ${repo}:<version>-alpine or -slim tag (fewer packages, fewer CVEs); test your app first"
  fi
  printf '%s\n' "Rebuild with: docker build --pull --no-cache -t $img . (picks up patched base layers)"
  printf '%s\n' "Use a multi-stage build: compile in a builder stage, ship only the runtime in the final stage"
  printf '%s\n' "Add a non-root USER and pin dependencies with a lockfile (requirements.txt hashes, package-lock.json)"
}

# render_remediation <remediation-object-json>: plain text, capped lists (full data in remediation.json)
render_remediation() {
  jq -r --argjson max 15 '
    def cut($a): ($a[:$max][]), (if ($a|length) > $max then "    ... \(($a|length) - $max) more (see remediation.json)" else empty end);
    "  \(.image)  (\(.os // "OS unknown"))",
    "    a) OS package fixes (CRITICAL/HIGH with a fix): \(.os_packages|length)",
    cut(.os_packages | map("      [\(.severity)] \(.package) \(.installed) -> \(.fixed)  (\(.cves) CVE)")),
    (if (.os_packages|length) > 0 then "      => update/rebuild the base image, or: apt-get update && apt-get install --only-upgrade <pkg> (apk upgrade <pkg>)" else empty end),
    "    b) Application dependency fixes: \(.app_dependencies|length)",
    cut(.app_dependencies | map("      [\(.severity)] \(.package) \(.installed) -> \(.fixed)  (\(.cves) CVE; \(.type // "?"): \(.target))")),
    (if (.app_dependencies|length) > 0 then "      => bump these in the manifest/lockfile named above, then rebuild" else empty end),
    "    c) Unfixable CRITICAL/HIGH (no fixed version yet): \(.unfixable)",
    (if .unfixable > 0 then "      => change base image, remove the package, check reachability, or record an accepted risk in .trivyignore" else empty end),
    "    Base image advice:",
    (.base_image_advice[] | "      - \(.)")' <<<"$1"
}

if [[ "$REMEDIATION" == true && "$SETUP" != "C" && "$HAVE_IMAGES" == true ]]; then
  log_section "Remediation"
  REM_ITEMS=()
  for img in "${IMAGES[@]}"; do
    safe=$(safe_name "$img")
    [[ "${IMG_PRESENT[$img]}" == true && -s "$RAW_DIR/$safe.json" ]] || continue
    fam=$(jq -r '.Metadata.OS.Family // ""' "$RAW_DIR/$safe.json")
    advice=$(base_advice "$img" "$fam" | jq -R . | jq -s .)
    item=$(jq --arg img "$img" --argjson advice "$advice" "$REM_JQ" "$RAW_DIR/$safe.json") \
      || { log_warn "Could not build remediation for $img"; continue; }
    REM_ITEMS+=("$item")
    printf '%s\n' "$item" > "$RAW_DIR/$safe.remediation.json"
    while IFS= read -r l; do log "$l"; done < <(render_remediation "$item")
  done
  if (( ${#REM_ITEMS[@]} > 0 )); then
    printf '%s\n' "${REM_ITEMS[@]}" | jq -s --arg ts "$TIMESTAMP" '{ generated: $ts, images: . }' > "$REPORT_DIR/remediation.json"
    if [[ -f "$REPORT_DIR/summary.md" ]]; then
      {
        echo; echo "## Remediation"
        for item in "${REM_ITEMS[@]}"; do
          echo; echo '```text'; render_remediation "$item"; echo '```'
        done
      } >> "$REPORT_DIR/summary.md"
    fi
    log_info "Remediation details: $REPORT_DIR/remediation.json"
  fi
fi

if [[ "$REMEDIATION" == true && ${#SEMGREP_PATHS[@]} -gt 0 && $SG_FINDINGS -gt 0 ]]; then
  SG_ADVICE="Semgrep: fix the flagged code and run Semgrep before docker build. Suppress a false positive with '# nosemgrep: <rule-id>' plus a comment explaining why."
  log_section "Semgrep advice"
  log_info "$SG_ADVICE"
  [[ -f "$REPORT_DIR/summary.md" ]] && printf '\n%s\n' "$SG_ADVICE" >> "$REPORT_DIR/summary.md"
fi

log ""
if (( SCAN_ERRORS > 0 )); then
  log "${RED}RESULT: ERROR — $SCAN_ERRORS scan(s) could not be completed${NC}"
elif [[ "$FAIL" == true ]]; then
  log "${RED}RESULT: FAILED — one or more checks did not pass${NC}"
else
  log "${GREEN}RESULT: PASSED — all checks passed${NC}"
fi

# -----------------------------------------------------------------------------
# Write output file if requested
# -----------------------------------------------------------------------------
if [[ -n "$OUTPUT_FILE" ]]; then
  cp "$REPORT_TXT" "$OUTPUT_FILE"
  printf '%sReport written to: %s%s\n' "$BLUE" "$OUTPUT_FILE" "$NC"
fi

# -----------------------------------------------------------------------------
# Exit code: tool/scan errors are never hidden (2); findings fail only with the flag
# -----------------------------------------------------------------------------
(( SCAN_ERRORS > 0 )) && exit 2
[[ "$EXIT_ON_FAIL" == true && "$FAIL" == true ]] && exit 1
exit 0
