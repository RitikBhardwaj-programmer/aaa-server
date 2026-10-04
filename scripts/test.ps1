# Runs the end-to-end AAA test suite (tests/run-tests.sh) against the running stack.
$ErrorActionPreference = 'Stop'
Set-Location (Split-Path -Parent $PSScriptRoot)
docker compose --profile test build tests
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
docker compose --profile test run --rm tests
exit $LASTEXITCODE
