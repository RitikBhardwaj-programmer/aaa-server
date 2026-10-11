# Runs the test suites against the running stack:
#   1. tests/ldap-checks.sh inside the ldap container (password store: Argon2, NT hash, password change)
#   2. tests/run-tests.sh in the tests container (end-to-end 802.1X, accounting, limits)
# Exit codes are checked below. 'Continue' because docker writes progress to stderr, which
# Windows PowerShell 5.1 would otherwise turn into a fatal error.
$ErrorActionPreference = 'Continue'
Set-Location (Split-Path -Parent $PSScriptRoot)
# Copied, not piped: Windows PowerShell 5.1 would add a byte-order mark to piped text
docker compose cp tests/ldap-checks.sh ldap:/tmp/ldap-checks.sh
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
docker compose exec -T ldap sh /tmp/ldap-checks.sh
$ldap = $LASTEXITCODE
docker compose --profile test build tests
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
docker compose --profile test run --rm tests
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
exit $ldap
