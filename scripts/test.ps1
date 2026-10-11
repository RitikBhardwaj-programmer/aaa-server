# Runs the test suites against the running stack:
#   1. tests/ldap-checks.sh inside the ldap container (password store: Argon2, NT hash, password change)
#   2. portal/tests/test_portal.py in the portal-test container (self-service portal, with a temporary user)
#   3. tests/run-tests.sh in the tests container (end-to-end 802.1X, accounting, limits)
# Exit codes are checked below. 'Continue' because docker writes progress to stderr, which
# Windows PowerShell 5.1 would otherwise turn into a fatal error.
$ErrorActionPreference = 'Continue'
Set-Location (Split-Path -Parent $PSScriptRoot)
# Copied, not piped: Windows PowerShell 5.1 would add a byte-order mark to piped text
docker compose cp tests/ldap-checks.sh ldap:/tmp/ldap-checks.sh
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
docker compose exec -T ldap sh /tmp/ldap-checks.sh
$ldap = $LASTEXITCODE

# Portal tests: a temporary user with a random password, removed afterwards. Both values reach the
# containers through environment variables, not command lines.
docker compose cp tests/portal-test-user.sh ldap:/tmp/portal-test-user.sh
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
# Separate random bytes for the uid and the password: the uid is logged, the password must not be
$rng = [Security.Cryptography.RandomNumberGenerator]::Create()
$pwBytes = New-Object byte[] 12; $rng.GetBytes($pwBytes)
$idBytes = New-Object byte[] 4; $rng.GetBytes($idBytes)
$env:PORTAL_TEST_PASSWORD = -join ($pwBytes | ForEach-Object { $_.ToString('x2') })
$env:PORTAL_TEST_UID = 'ptest' + (-join ($idBytes | ForEach-Object { $_.ToString('x2') }))
$portal = 1
docker compose exec -T -e PORTAL_TEST_PASSWORD ldap sh /tmp/portal-test-user.sh create $env:PORTAL_TEST_UID
if ($LASTEXITCODE -eq 0) {
    docker compose --profile test build portal-test
    if ($LASTEXITCODE -eq 0) {
        docker compose --profile test run --rm -e PORTAL_TEST_UID -e PORTAL_TEST_PASSWORD portal-test
        $portal = $LASTEXITCODE
    }
}
docker compose exec -T ldap sh /tmp/portal-test-user.sh delete $env:PORTAL_TEST_UID
Remove-Item Env:PORTAL_TEST_PASSWORD, Env:PORTAL_TEST_UID

docker compose --profile test build tests
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
docker compose --profile test run --rm tests
$e2e = $LASTEXITCODE
if ($e2e -ne 0) { exit $e2e }
if ($portal -ne 0) { exit $portal }
exit $ldap
