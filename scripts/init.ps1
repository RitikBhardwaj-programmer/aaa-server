# One-time setup: creates .env with random secrets and generates the lab CA + server certificate.
# Safe to re-run: existing .env and certificates are kept.
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

function New-Secret([int]$length = 32) {
    $chars = [char[]]'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789'
    $bytes = New-Object byte[] $length
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    -join ($bytes | ForEach-Object { $chars[$_ % $chars.Length] })
}

$envFile = Join-Path $root '.env'
$keyBytes = New-Object byte[] 32
[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($keyBytes)
$values = @{
    LDAP_ADMIN_PASSWORD      = New-Secret 24
    LDAP_RADIUS_PASSWORD     = New-Secret 24
    TEST_USER_PASSWORD       = New-Secret 12
    RADIUS_SECRET_LOCAL      = New-Secret 32
    RADIUS_SECRET_AP         = New-Secret 32
    POSTGRES_PASSWORD        = New-Secret 24
    POSTGRES_RADIUS_PASSWORD = New-Secret 24
    LDAP_PORTAL_PASSWORD     = New-Secret 24
    POSTGRES_PORTAL_PASSWORD = New-Secret 24
    PORTAL_SECRET_KEY        = New-Secret 48
    PLA_APP_KEY              = 'base64:' + [Convert]::ToBase64String($keyBytes)
}
if (Test-Path $envFile) {
    # Keep every existing value; append only settings added to .env.example since .env was made
    $have = @{}
    Get-Content $envFile | ForEach-Object { if ($_ -match '^([A-Z_]+)=') { $have[$Matches[1]] = $true } }
    $added = @(Get-Content (Join-Path $root '.env.example') | Where-Object { $_ -match '^([A-Z_]+)=' -and -not $have[$Matches[1]] } |
        ForEach-Object { $null = $_ -match '^([A-Z_]+)='; if ($values.ContainsKey($Matches[1])) { "$($Matches[1])=$($values[$Matches[1]])" } else { $_ } })
    if ($added.Count) {
        $text = [IO.File]::ReadAllText($envFile).TrimEnd("`n") + "`n" + ($added -join "`n") + "`n"
        [IO.File]::WriteAllText($envFile, $text, (New-Object Text.UTF8Encoding $false))
        Write-Host ".env already exists - kept it and added $($added.Count) new setting(s): $(($added | ForEach-Object { ($_ -split '=')[0] }) -join ', ')"
    } else {
        Write-Host '.env already exists - keeping it.'
    }
} else {
    $lines = Get-Content (Join-Path $root '.env.example') | ForEach-Object {
        if ($_ -match '^([A-Z_]+)=' -and $values.ContainsKey($Matches[1])) { "$($Matches[1])=$($values[$Matches[1]])" } else { $_ }
    }
    # UTF-8 without BOM and LF endings, so docker compose parses it cleanly
    [IO.File]::WriteAllText($envFile, (($lines -join "`n") + "`n"), (New-Object Text.UTF8Encoding $false))
    Write-Host 'Created .env with random secrets. Edit AP_IP to match your access point.'
}

if (Test-Path (Join-Path $root 'certs/server.pem')) {
    Write-Host 'Certificates already exist - keeping them.'
} else {
    Write-Host 'Generating lab CA and RADIUS server certificate...'
    docker run --rm -v "${root}/certs:/certs" --entrypoint sh freeradius/freeradius-server:3.2.10 /certs/make-certs.sh
    if ($LASTEXITCODE -ne 0) { throw 'Certificate generation failed.' }
}
Write-Host 'Done. Next: docker compose up -d --build'
