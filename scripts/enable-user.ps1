# Restores a user's Wi-Fi access by removing them from cn=disabled in LDAP.
# The next login (or re-check) is accepted again.
#
#   .\scripts\enable-user.ps1 24IT001
param([Parameter(Mandatory = $true)][string]$Uid)
Set-Location (Split-Path -Parent $PSScriptRoot)
if ($Uid -notmatch '^[A-Za-z0-9._-]+$') { Write-Error "Invalid uid: $Uid"; exit 2 }

docker compose exec -T ldap set-disabled.sh $Uid off
exit $LASTEXITCODE
