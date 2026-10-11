# Shows accounting data from the PostgreSQL database (read-only session).
#   .\scripts\acct.ps1             last 20 sessions
#   .\scripts\acct.ps1 -Auth       last 20 accept/reject events
#   .\scripts\acct.ps1 -Devices    users at or near the device limit, and recent limit events
#   .\scripts\acct.ps1 -Query "SELECT username, SUM(acctinputoctets+acctoutputoctets) FROM radacct GROUP BY username"
param([switch]$Auth, [switch]$Devices, [string[]]$Query)
Set-Location (Split-Path -Parent $PSScriptRoot)

# Same "live session" window as the device limit (STALE_SESSION_MINUTES in .env, default 25)
$stale = 25
$line = Get-Content .env -ErrorAction SilentlyContinue | Where-Object { $_ -match '^STALE_SESSION_MINUTES=(\d+)\s*$' } | Select-Object -First 1
if ($line -and $line -match '=(\d+)') { $stale = [int]$Matches[1] }

if (-not $Query) {
    if ($Auth) {
        $Query = 'SELECT authdate, username, reply, callingstationid AS device, class FROM radpostauth ORDER BY authdate DESC LIMIT 20'
    } elseif ($Devices) {
        $Query = @(("SELECT username, COUNT(DISTINCT callingstationid) AS live_devices FROM radacct WHERE acctstoptime IS NULL " +
                 "AND acctupdatetime > now() - interval '$stale minutes' GROUP BY username ORDER BY 2 DESC LIMIT 20"),
                 'SELECT eventtime, username, callingstationid AS device, live_devices, device_limit, mode FROM device_limit_events ORDER BY id DESC LIMIT 20')
    } else {
        $Query = 'SELECT username, class, callingstationid AS device, framedipaddress AS ip, ' +
                 'acctstarttime AS start, acctstoptime AS stop, ' +
                 'acctsessiontime AS seconds, acctinputoctets AS bytes_in, ' +
                 'acctoutputoctets AS bytes_out, acctterminatecause AS cause FROM radacct ORDER BY acctstarttime DESC LIMIT 20'
    }
}
# Local socket inside the postgres container; the session is read-only, so a typo cannot change data
docker compose exec -T -e PGOPTIONS='-c default_transaction_read_only=on' postgres psql -U radius -d radius @($Query | ForEach-Object { "-c"; $_ })
