# Who had this IP at this time? Looks in the accounting table (radacct) for sessions of an IPv4 address.
#   .\scripts\who-had-ip.ps1 -Ip 10.20.30.40 -At "2026-10-11 14:30"          (no offset = India time, +05:30)
#   .\scripts\who-had-ip.ps1 -Ip 10.20.30.40 -At "2026-10-11T09:00:00Z"
# Exit codes: 0 found, 1 nothing found, 2 bad input, 3 database error.
param([Parameter(Mandatory)][string]$Ip, [Parameter(Mandatory)][string]$At)
Set-Location (Split-Path -Parent $PSScriptRoot)

# IPv4 only (accounting stores Framed-IP-Address; IPv6 is future work)
$addr = $null
if (-not [System.Net.IPAddress]::TryParse($Ip, [ref]$addr) -or $addr.AddressFamily -ne 'InterNetwork' -or $Ip -notmatch '^\d{1,3}(\.\d{1,3}){3}$') {
    Write-Host "Bad IP '$Ip': give an IPv4 address such as 10.20.30.40." -ForegroundColor Red
    exit 2
}

# A time without an offset is India time (Asia/Kolkata, +05:30). ISO 8601 is the safe format.
$inv = [Globalization.CultureInfo]::InvariantCulture
$when = [DateTimeOffset]::MinValue
if ($At -match '\d:\d{2}(:\d{2}(\.\d+)?)?\s*(Z|[+-]\d{2}(:?\d{2})?)\s*$') {
    $ok = [DateTimeOffset]::TryParse($At, $inv, [Globalization.DateTimeStyles]::None, [ref]$when)
} else {
    $local = [DateTime]::MinValue
    $ok = [DateTime]::TryParse($At, $inv, [Globalization.DateTimeStyles]::None, [ref]$local)
    if ($ok) { $when = New-Object DateTimeOffset ([DateTime]::SpecifyKind($local, 'Unspecified')), ([TimeSpan]::FromMinutes(330)) }
}
if (-not $ok) {
    Write-Host "Bad time '$At': use for example `"2026-10-11 14:30`" or `"2026-10-11T14:30:00+05:30`"." -ForegroundColor Red
    exit 2
}
$utc = $when.UtcDateTime.ToString('yyyy-MM-dd HH:mm:ss', $inv) + '+00'
Write-Host ("Searching {0} at {1} (= {2} UTC)" -f $Ip, $when.ToString('yyyy-MM-dd HH:mm:ss zzz', $inv), $when.UtcDateTime.ToString('yyyy-MM-dd HH:mm:ss', $inv))

# Same "stale" window as the device limit and the reaper (STALE_SESSION_MINUTES in .env, default 25)
$stale = 25
$line = Get-Content .env -ErrorAction SilentlyContinue | Where-Object { $_ -match '^STALE_SESSION_MINUTES=(\d+)\s*$' } | Select-Object -First 1
if ($line -and $line -match '=(\d+)') { $stale = [int]$Matches[1] }

# The SQL is fixed text; the IP, the time and the window reach psql as variables (:'ip' is quoted by psql).
# The session is read-only, so the lookup cannot change data.
$sql = "SELECT * FROM who_had_ip(:'ip'::inet, :'at'::timestamptz, :stale);"
$csv = $sql | docker compose exec -T -e PGOPTIONS='-c default_transaction_read_only=on' postgres psql -U radius -d radius `
    -v ON_ERROR_STOP=1 -v "ip=$Ip" -v "at=$utc" -v "stale=$stale" --csv -f -
if ($LASTEXITCODE -ne 0) {
    Write-Host "Database error (is the stack up? is migration 003 applied?)." -ForegroundColor Red
    exit 3
}
$rows = @($csv | ConvertFrom-Csv)
if ($rows.Count -eq 0) {
    Write-Host "No session found for $Ip at that time." -ForegroundColor Yellow
    Write-Host "Accounting only covers devices whose AP sends Framed-IP-Address, so this does not prove that nobody had the IP."
    exit 1
}
$rows | Format-Table username, callingstationid, calledstationid, nas, acctsessionid, acctstarttime, effective_stop, acctterminatecause, status -AutoSize | Out-String -Width 250 | Write-Host
if ($rows | Where-Object { $_.status -eq 'stale-open' }) {
    Write-Host "stale-open: the session is still open but sent no update for over $stale minutes (the AP may have lost the Stop); effective_stop is its last update."
}
exit 0
