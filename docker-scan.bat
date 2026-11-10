@echo off
setlocal enabledelayedexpansion

:: =============================================================================
:: docker-scan.bat — Docker Security Scanner (Windows)
:: Covers Setup A (VPS/Local), B (CI/CD), C (ECS/ECR manual), D (CI/CD + ECS)
::
:: Usage:
::   docker-scan.bat --setup <A|B|C|D> --image <image:tag> [OPTIONS]
::
:: Options:
::   --setup       <A|B|C|D>        Required. Deployment setup type
::   --image       <image:tag>      Required. Docker image to scan
::   --compose     <file>           Optional. Path to docker-compose.yml
::   --output      <file>           Optional. Write report to file
::   --exit-on-fail                 Optional. Exit with code 1 on CRITICAL/HIGH
::   --region      <aws-region>     Required for Setup C and D
::   --repo        <ecr-repo-name>  Required for Setup C and D
::   --profile     <aws-profile>    Optional. AWS CLI named profile
::
:: Examples:
::   docker-scan.bat --setup A --image myapp:1.0.0
::   docker-scan.bat --setup B --image myapp:1.0.0 --exit-on-fail
::   docker-scan.bat --setup C --image 123456789.dkr.ecr.eu-west-1.amazonaws.com/myrepo:1.0.0 --region eu-west-1 --repo myrepo --exit-on-fail
::   docker-scan.bat --setup C --image 123456789.dkr.ecr.eu-west-1.amazonaws.com/myrepo:1.0.0 --region eu-west-1 --repo myrepo --profile myprofile --exit-on-fail
::   docker-scan.bat --setup D --image 123456789.dkr.ecr.eu-west-1.amazonaws.com/myrepo:1.0.0 --region eu-west-1 --repo myrepo --output report.txt --exit-on-fail
::   docker-scan.bat --setup A --image myapp:1.0.0 --compose docker-compose.yml --output report.txt
:: =============================================================================

:: -----------------------------------------------------------------------------
:: Defaults
:: -----------------------------------------------------------------------------
set SETUP=
set IMAGE=
set COMPOSE_FILE=
set OUTPUT_FILE=
set EXIT_ON_FAIL=false
set AWS_REGION=
set ECR_REPO=
set AWS_PROFILE=
set FAIL=false
set REPORT=

:: -----------------------------------------------------------------------------
:: Parse arguments
:: -----------------------------------------------------------------------------
:parse_args
if "%~1"=="" goto validate
if "%~1"=="--setup"        ( set SETUP=%~2        & shift & shift & goto parse_args )
if "%~1"=="--image"        ( set IMAGE=%~2        & shift & shift & goto parse_args )
if "%~1"=="--compose"      ( set COMPOSE_FILE=%~2 & shift & shift & goto parse_args )
if "%~1"=="--output"       ( set OUTPUT_FILE=%~2  & shift & shift & goto parse_args )
if "%~1"=="--exit-on-fail" ( set EXIT_ON_FAIL=true & shift & goto parse_args )
if "%~1"=="--region"       ( set AWS_REGION=%~2   & shift & shift & goto parse_args )
if "%~1"=="--repo"         ( set ECR_REPO=%~2     & shift & shift & goto parse_args )
if "%~1"=="--profile"      ( set AWS_PROFILE=%~2  & shift & shift & goto parse_args )
echo [ERROR] Unknown argument: %~1
exit /b 1

:: -----------------------------------------------------------------------------
:: Validate required arguments
:: -----------------------------------------------------------------------------
:validate
if "%SETUP%"=="" (
  echo [ERROR] --setup is required ^(A, B, C or D^)
  exit /b 1
)
if "%IMAGE%"=="" (
  echo [ERROR] --image is required
  exit /b 1
)
if "%SETUP%"=="C" goto check_aws
if "%SETUP%"=="D" goto check_aws
goto check_deps

:check_aws
if "%AWS_REGION%"=="" (
  echo [ERROR] --region is required for Setup %SETUP%
  exit /b 1
)
if "%ECR_REPO%"=="" (
  echo [ERROR] --repo is required for Setup %SETUP%
  exit /b 1
)

:: -----------------------------------------------------------------------------
:: Dependency checks
:: -----------------------------------------------------------------------------
:check_deps
where docker >nul 2>&1
if errorlevel 1 (
  echo [ERROR] docker is not installed or not in PATH
  exit /b 1
)

if "%SETUP%"=="A" goto check_trivy
if "%SETUP%"=="B" goto check_trivy
if "%SETUP%"=="D" goto check_trivy
goto check_aws_cli

:check_trivy
where trivy >nul 2>&1
if errorlevel 1 (
  echo [ERROR] trivy is not installed or not in PATH
  echo         Install from: https://github.com/aquasecurity/trivy/releases
  exit /b 1
)

:check_aws_cli
if "%SETUP%"=="C" goto check_aws_cli_install
if "%SETUP%"=="D" goto check_aws_cli_install
goto header

:check_aws_cli_install
where aws >nul 2>&1
if errorlevel 1 (
  echo [ERROR] aws CLI is not installed or not in PATH
  exit /b 1
)

:: -----------------------------------------------------------------------------
:: Header
:: -----------------------------------------------------------------------------
:header
set TIMESTAMP=%DATE% %TIME%
call :log "Docker Security Scanner"
call :log "Setup:     %SETUP%"
call :log "Image:     %IMAGE%"
call :log "Timestamp: %TIMESTAMP%"
if not "%COMPOSE_FILE%"=="" call :log "Compose:   %COMPOSE_FILE%"
if not "%OUTPUT_FILE%"==""  call :log "Output:    %OUTPUT_FILE%"
if not "%AWS_PROFILE%"==""  call :log "Profile:   %AWS_PROFILE%"

:: =============================================================================
:: SECTION 1 — IMAGE INSPECT
:: =============================================================================
call :log_section "1. Image Inspect"

call :log_info "Running: docker image inspect %IMAGE%"

docker image inspect "%IMAGE%" >nul 2>&1
if errorlevel 1 (
  call :log_fail "Image '%IMAGE%' not found locally. Pull or build it first."
  goto section2
)

:: User check
for /f "tokens=*" %%i in ('docker image inspect --format "{{.Config.User}}" "%IMAGE%" 2^>nul') do set IMG_USER=%%i
if "%IMG_USER%"=="" (
  call :log_fail "Image runs as root ^(User not set^)"
) else if "%IMG_USER%"=="root" (
  call :log_fail "Image runs as root"
) else if "%IMG_USER%"=="0" (
  call :log_fail "Image runs as root ^(User: 0^)"
) else (
  call :log_pass "Image user: %IMG_USER%"
)

:: Environment variables — check for secrets
for /f "tokens=*" %%i in ('docker image inspect --format "{{.Config.Env}}" "%IMAGE%" 2^>nul') do set IMG_ENV=%%i
echo %IMG_ENV% | findstr /i "PASSWORD SECRET TOKEN API_KEY PRIVATE CREDENTIAL" >nul 2>&1
if not errorlevel 1 (
  call :log_fail "Potential secret found in image ENV vars"
) else (
  call :log_pass "No obvious secrets found in image ENV vars"
)

:: =============================================================================
:: SECTION 2 — RUNNING CONTAINER INSPECT
:: =============================================================================
:section2
call :log_section "2. Running Container Inspect"

for /f "tokens=*" %%i in ('docker ps --filter "ancestor=%IMAGE%" --format "{{.ID}}" 2^>nul') do set CONTAINER_ID=%%i

if "%CONTAINER_ID%"=="" (
  call :log_warn "No running container found for image '%IMAGE%'. Skipping runtime checks."
  call :log_info "Start the container and re-run to include runtime checks."
  goto section3
)

call :log_info "Inspecting container: %CONTAINER_ID%"

:: Read-only root filesystem
for /f "tokens=*" %%i in ('docker inspect --format "{{.HostConfig.ReadonlyRootfs}}" "%CONTAINER_ID%" 2^>nul') do set READONLY=%%i
if "%READONLY%"=="true" (
  call :log_pass "ReadonlyRootFilesystem: true"
) else (
  call :log_fail "ReadonlyRootFilesystem: false — root filesystem is writable"
)

:: Privileged mode
for /f "tokens=*" %%i in ('docker inspect --format "{{.HostConfig.Privileged}}" "%CONTAINER_ID%" 2^>nul') do set PRIVILEGED=%%i
if "%PRIVILEGED%"=="false" (
  call :log_pass "Privileged: false"
) else (
  call :log_fail "Privileged: true — container is running in privileged mode"
)

:: No new privileges
for /f "tokens=*" %%i in ('docker inspect --format "{{.HostConfig.SecurityOpt}}" "%CONTAINER_ID%" 2^>nul') do set SEC_OPT=%%i
echo %SEC_OPT% | findstr /i "no-new-privileges" >nul 2>&1
if not errorlevel 1 (
  call :log_pass "NoNewPrivileges: true"
) else (
  call :log_fail "NoNewPrivileges not set — privilege escalation is allowed"
)

:: CapDrop ALL
for /f "tokens=*" %%i in ('docker inspect --format "{{.HostConfig.CapDrop}}" "%CONTAINER_ID%" 2^>nul') do set CAP_DROP=%%i
echo %CAP_DROP% | findstr /i "ALL" >nul 2>&1
if not errorlevel 1 (
  call :log_pass "CapDrop: ALL"
) else (
  call :log_fail "CapDrop does not include ALL: %CAP_DROP%"
)

:: CapAdd
for /f "tokens=*" %%i in ('docker inspect --format "{{.HostConfig.CapAdd}}" "%CONTAINER_ID%" 2^>nul') do set CAP_ADD=%%i
if "%CAP_ADD%"=="[]" (
  call :log_pass "CapAdd: none"
) else (
  call :log_warn "CapAdd: %CAP_ADD% — verify these are justified in DockerSecuritySpec.md"
)

:: Network mode
for /f "tokens=*" %%i in ('docker inspect --format "{{.HostConfig.NetworkMode}}" "%CONTAINER_ID%" 2^>nul') do set NET_MODE=%%i
if "%NET_MODE%"=="host" (
  call :log_fail "NetworkMode: host — host network mode is not allowed"
) else (
  call :log_pass "NetworkMode: %NET_MODE%"
)

:: Memory limit
for /f "tokens=*" %%i in ('docker inspect --format "{{.HostConfig.Memory}}" "%CONTAINER_ID%" 2^>nul') do set MEM_LIMIT=%%i
if "%MEM_LIMIT%"=="0" (
  call :log_fail "Memory limit not set"
) else (
  call :log_pass "Memory limit: %MEM_LIMIT% bytes"
)

:: CPU limit
for /f "tokens=*" %%i in ('docker inspect --format "{{.HostConfig.CpuQuota}}" "%CONTAINER_ID%" 2^>nul') do set CPU_QUOTA=%%i
if "%CPU_QUOTA%"=="0" (
  call :log_fail "CPU limit not set ^(CpuQuota: 0^)"
) else (
  call :log_pass "CPU quota: %CPU_QUOTA%"
)

:: User
for /f "tokens=*" %%i in ('docker inspect --format "{{.Config.User}}" "%CONTAINER_ID%" 2^>nul') do set RUN_USER=%%i
if "%RUN_USER%"=="" (
  call :log_fail "Container running as root ^(User not set^)"
) else if "%RUN_USER%"=="root" (
  call :log_fail "Container running as root"
) else (
  call :log_pass "Container user: %RUN_USER%"
)

:: =============================================================================
:: SECTION 3 — DOCKER COMPOSE CHECKS (Setup A and B only)
:: =============================================================================
:section3
if "%SETUP%"=="C" goto section4
if "%SETUP%"=="D" goto section4
if "%COMPOSE_FILE%"=="" goto section4

call :log_section "3. Docker Compose File Checks"

if not exist "%COMPOSE_FILE%" (
  call :log_fail "Compose file not found: %COMPOSE_FILE%"
  goto section4
)

call :log_info "Checking: %COMPOSE_FILE%"

findstr /i "read_only: true" "%COMPOSE_FILE%" >nul 2>&1
if not errorlevel 1 ( call :log_pass "read_only: true found" ) else ( call :log_fail "read_only: true not found" )

findstr /i "privileged: true" "%COMPOSE_FILE%" >nul 2>&1
if not errorlevel 1 ( call :log_fail "privileged: true found" ) else ( call :log_pass "No privileged: true found" )

findstr /i "network_mode: host" "%COMPOSE_FILE%" >nul 2>&1
if not errorlevel 1 ( call :log_fail "network_mode: host found" ) else ( call :log_pass "No network_mode: host found" )

findstr /i "no-new-privileges" "%COMPOSE_FILE%" >nul 2>&1
if not errorlevel 1 ( call :log_pass "no-new-privileges found" ) else ( call :log_fail "no-new-privileges not set" )

findstr /i "mem_limit" "%COMPOSE_FILE%" >nul 2>&1
if not errorlevel 1 ( call :log_pass "mem_limit found" ) else ( call :log_fail "mem_limit not set" )

findstr /i "ALL" "%COMPOSE_FILE%" >nul 2>&1
if not errorlevel 1 ( call :log_pass "cap_drop ALL found" ) else ( call :log_fail "cap_drop ALL not found" )

findstr /i ":latest" "%COMPOSE_FILE%" >nul 2>&1
if not errorlevel 1 ( call :log_fail ":latest tag found — use specific tags in production" ) else ( call :log_pass "No :latest tags found" )

:: =============================================================================
:: SECTION 4 — TRIVY SCAN (Setup A, B, D)
:: =============================================================================
:section4
if "%SETUP%"=="C" goto section5

call :log_section "4. Trivy Vulnerability Scan"
call :log_info "Running Trivy scan on: %IMAGE%"

trivy image --severity CRITICAL,HIGH,MEDIUM,LOW --format table --no-progress "%IMAGE%"

for /f %%i in ('trivy image --severity CRITICAL --format json --no-progress --quiet "%IMAGE%" 2^>nul ^| find /c "CRITICAL"') do set CRITICAL_COUNT=%%i
for /f %%i in ('trivy image --severity HIGH --format json --no-progress --quiet "%IMAGE%" 2^>nul ^| find /c "HIGH"') do set HIGH_COUNT=%%i

call :log_info "Trivy CRITICAL count: %CRITICAL_COUNT%"
call :log_info "Trivy HIGH count:     %HIGH_COUNT%"

if %CRITICAL_COUNT% GTR 0 ( call :log_fail "CRITICAL vulnerabilities found — deployment must be blocked" )
if %HIGH_COUNT% GTR 0     ( call :log_fail "HIGH vulnerabilities found — must be fixed within 3 days" )
if %CRITICAL_COUNT%==0 if %HIGH_COUNT%==0 ( call :log_pass "No CRITICAL or HIGH vulnerabilities found" )

:: =============================================================================
:: SECTION 5 — ECR SCAN (Setup C, D)
:: =============================================================================
:section5
if "%SETUP%"=="A" goto summary
if "%SETUP%"=="B" goto summary

call :log_section "5. ECR Scan Results"

for /f "tokens=2 delims=:" %%i in ("%IMAGE%") do set IMAGE_TAG=%%i
if "%IMAGE_TAG%"=="" set IMAGE_TAG=latest

call :log_info "Waiting for ECR scan to complete..."
set AWS_PROFILE_ARG=
if not "%AWS_PROFILE%"=="" set AWS_PROFILE_ARG=--profile %AWS_PROFILE%
aws ecr wait image-scan-complete --repository-name "%ECR_REPO%" --image-id imageTag="%IMAGE_TAG%" --region "%AWS_REGION%" %AWS_PROFILE_ARG% 2>nul

call :log_info "Fetching ECR scan findings for %ECR_REPO%:%IMAGE_TAG%"

for /f "tokens=*" %%i in ('aws ecr describe-image-scan-findings --repository-name "%ECR_REPO%" --image-id imageTag="%IMAGE_TAG%" --region "%AWS_REGION%" %AWS_PROFILE_ARG% --query "imageScanFindings.findingSeverityCounts" --output json 2^>nul') do set ECR_FINDINGS=%%i

call :log_info "ECR Findings: %ECR_FINDINGS%"

echo %ECR_FINDINGS% | findstr /i "CRITICAL" >nul 2>&1
if not errorlevel 1 ( call :log_fail "ECR: CRITICAL vulnerabilities found — deployment must be blocked" ) else ( call :log_pass "ECR: No CRITICAL vulnerabilities found" )

echo %ECR_FINDINGS% | findstr /i "HIGH" >nul 2>&1
if not errorlevel 1 ( call :log_fail "ECR: HIGH vulnerabilities found — must be fixed within 3 days" ) else ( call :log_pass "ECR: No HIGH vulnerabilities found" )

echo %ECR_FINDINGS% | findstr /i "MEDIUM" >nul 2>&1
if not errorlevel 1 ( call :log_warn "ECR: MEDIUM vulnerabilities found — must be fixed within 30 days" )

echo %ECR_FINDINGS% | findstr /i "LOW" >nul 2>&1
if not errorlevel 1 ( call :log_warn "ECR: LOW vulnerabilities found — fix in next scheduled maintenance" )

:: =============================================================================
:: SUMMARY
:: =============================================================================
:summary
call :log_section "Summary"

if "%FAIL%"=="true" (
  call :log "RESULT: FAILED — one or more checks did not pass"
) else (
  call :log "RESULT: PASSED — all checks passed"
)

if not "%OUTPUT_FILE%"=="" (
  echo %REPORT% > "%OUTPUT_FILE%"
  echo Report written to: %OUTPUT_FILE%
)

if "%EXIT_ON_FAIL%"=="true" if "%FAIL%"=="true" exit /b 1
exit /b 0

:: =============================================================================
:: Helper functions
:: =============================================================================
:log
echo %~1
set REPORT=%REPORT%%~1\n
goto :eof

:log_section
echo.
echo ============================================================
echo   %~1
echo ============================================================
set REPORT=%REPORT%\n============================================================\n  %~1\n============================================================\n
goto :eof

:log_pass
echo   [PASS] %~1
set REPORT=%REPORT%  [PASS] %~1\n
goto :eof

:log_fail
echo   [FAIL] %~1
set REPORT=%REPORT%  [FAIL] %~1\n
set FAIL=true
goto :eof

:log_warn
echo   [WARN] %~1
set REPORT=%REPORT%  [WARN] %~1\n
goto :eof

:log_info
echo   [INFO] %~1
set REPORT=%REPORT%  [INFO] %~1\n
goto :eof
