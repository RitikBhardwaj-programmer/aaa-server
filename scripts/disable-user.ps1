# Blocks a user's Wi-Fi access:
#   1. adds the user to cn=disabled in LDAP (every new login and every re-check is rejected), then
#   2. sends a Disconnect-Request for each open session, so the device is dropped at once
#      on access points that support RFC 5176. Others drop it at the next re-check (REAUTH_INTERVAL).
#
#   .\scripts\disable-user.ps1 24IT001
param([Parameter(Mandatory = $true)][string]$Uid)
Set-Location (Split-Path -Parent $PSScriptRoot)
if ($Uid -notmatch '^[A-Za-z0-9._-]+$') { Write-Error "Invalid uid: $Uid"; exit 2 }

docker compose exec -T ldap set-disabled.sh $Uid on
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "Disconnecting open sessions of ${Uid}:"
docker compose --profile tools run --rm tools disconnect-user.sh $Uid
exit $LASTEXITCODE
