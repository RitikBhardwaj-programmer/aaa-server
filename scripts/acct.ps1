# Shows accounting data from the SQLite database (read-only).
#   .\scripts\acct.ps1             last 20 sessions
#   .\scripts\acct.ps1 -Auth       last 20 accept/reject events
#   .\scripts\acct.ps1 -Query "SELECT username, SUM(acctinputoctets+acctoutputoctets) FROM radacct GROUP BY username"
param([switch]$Auth, [string]$Query)
Set-Location (Split-Path -Parent $PSScriptRoot)

if (-not $Query) {
    if ($Auth) {
        $Query = 'SELECT authdate, username, reply, class FROM radpostauth ORDER BY id DESC LIMIT 20'
    } else {
        $Query = 'SELECT username, class, callingstationid AS device, framedipaddress AS ip, ' +
                 "datetime(acctstarttime, 'unixepoch') AS start_utc, datetime(acctstoptime, 'unixepoch') AS stop_utc, " +
                 'acctsessiontime AS seconds, acctinputoctets AS bytes_in, ' +
                 'acctoutputoctets AS bytes_out, acctterminatecause AS cause FROM radacct ORDER BY radacctid DESC LIMIT 20'
    }
}
docker compose --profile test run --rm --no-deps --entrypoint sqlite3 tests -header -column `
    'file:/radius-acct/sqlite/radius.db?immutable=1' $Query
