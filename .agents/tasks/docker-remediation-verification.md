# docker-scan.sh remediation: verification notes

- `bash -n docker-scan.sh`: OK. shellcheck is not installed (not run).
- `./docker-scan.sh --help`: still prints from line 2 to the line before `set -E`; new `--no-remediation` option and examples 13-15 appear.
- `./docker-scan.sh --setup A --image postgres:16 --image python:3.13-slim --skip-db-update --report-dir /tmp/rem1 --output /tmp/rem1.txt`
  - postgres:16 (debian 13.7): OS fixes include `libgssapi-krb5-2 1.21.3-5+deb13u1 -> 1.21.3-5+deb13u2 (14 CVE)`, app deps (gobinary stdlib), 71 unfixable, advice suggests `-alpine`/`-slim`.
  - python:3.13-slim: OS fixes (apt, zlib1g), python-pkg fixes (msgpack, setuptools, urllib3), no alpine/slim suggestion (already slim).
  - redis:7-alpine (earlier run): no Debian advice, OS fixes via apk.
  - Section present in console, scan-report.txt, --output file, summary.md; `remediation.json` written.
- Throwaway image with `ENV GPG_KEY DB_PASSWORD SIGNING_KEY_ID APP_PUBLIC_KEY API_KEY`: only `DB_PASSWORD,API_KEY` flagged. `--no-remediation` produced no remediation.json. python:3.13-slim (has GPG_KEY): PASS. Image removed.
- /tmp dirs cleaned. docker-scan.bat untouched. Full --all scan not run.
- Limitation: highest FixedVersion uses a numeric-aware heuristic, not distro-specific version comparison.
