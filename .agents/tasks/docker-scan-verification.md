# docker-scan.sh verification

## Environment
trivy 0.76.2, docker (overlay2), jq present, bash 5.2. shellcheck NOT installed (not run). `bash -n docker-scan.sh` passes.

## Root causes (postgres:18.1 not reported / counts wrong)
Reproduced with the old command `trivy image --severity ... --format table --no-progress postgres:18.1 2>&1 || true`:
1. Counts were `grep -c CRITICAL|HIGH|...` on the human table text: counted lines (wrapped rows, headers, "Total:" lines, secret-scan output), not vulnerabilities. The default scanners also ran secret scanning, which dumped a private-key finding from the image and took 1m50s (vuln-only: 22s).
2. `2>&1 || true` merged Trivy logs into the output and hid any trivy failure (a failed scan looked like "0 vulnerabilities").
3. Default image source order is docker,containerd,podman,remote: a missing/unreadable local image silently falls back to a same-named registry image. Now `--image-src docker`.
4. No package count at all. Now from `--list-all-pkgs` JSON (os-pkgs + lang-pkgs).
5. Other bugs: `NoNewPrivileges` key does not exist in `docker inspect` (check always failed; now uses HostConfig.SecurityOpt); NanoCpus ignored for CPU limit; ECR tag parsing `awk -F:` breaks on registry ports; ECR errors swallowed with `|| true`; `echo -e` of report data.

## Runs
`./docker-scan.sh --setup A --image postgres:18.1 --image redis:7-alpine --image caddy:2.10.2-alpine --report-dir /tmp/rep1 --jobs 3` (11s, 3 parallel scans):

```
IMAGE                ID            OS                   PKGS  CRIT  HIGH    MED   LOW   UNK  FIXED  RESULT
postgres:18.1        ae1a6a12d1a7  debian 13.3           149    19   246    362   245    31    539  FAIL
caddy:2.10.2-alpine  aac61abc4024  alpine 3.22.3         162     6    99    121    50     2    275  FAIL
redis:7-alpine       9210b8dc25f1  alpine 3.21.7          21     4    63     88    21     1    177  FAIL
```
postgres:18.1 = 145 Debian pkgs + 4 gosu Go-module pkgs (matches Trivy log `pkg_num=145`); severity totals match the independent JSON scan (19/246/362/245/31).
summary.csv, summary.json, summary.md, per-image JSON and CRITICAL/HIGH table files were generated and inspected.

Second run `--image postgres:18.1 --image nope:1 --skip-db-update --exit-on-fail`: result cache hit (1.2s), missing image reported NOT_FOUND, exit code 2.

## Not verified
- Full `--all` run over the 40 images (intentionally not run).
- Setups C/D (needs AWS), `--compose`, `--secrets`, `--images-file` paths were not executed.
- shellcheck unavailable. docker-scan.bat was not changed (still the old single-image, grep-count logic).
- Package counts are Trivy's; Docker Desktop/Scout may differ slightly (different SBOM generator).

## Behaviour changes the user will notice
Secret scanning is off by default (`--secrets` enables it); scan errors exit 2 even without `--exit-on-fail`; multiple images (`--image` repeatable, `--images-file`, `--all`); reports are written to `./scan-reports/<timestamp>/`.
