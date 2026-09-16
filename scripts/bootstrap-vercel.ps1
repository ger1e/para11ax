#Requires -Version 5.1
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ProjectName             = 'para11ax'
$ProjectId               = 'prj_ojUpOTw8x8KOj9CrTs8jih1mrPjo'
$TeamSlug                = 'geri6'
$OrgId                   = 'team_hXokufMlDFuhPPT5r8jPf4aH'
$RepoUrl                 = 'https://github.com/ger1e/para11ax.git'
$ProductionAlias         = 'para11ax.vercel.app'
$RequiredNodeMajor       = 24
$PinnedVercelCliVersion  = '58.4.4'
$GatewayTokenDir         = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'PARA11AX'
$GatewayTokenFile        = Join-Path $GatewayTokenDir 'gateway-token.dpapi'
$RepoRoot                = Split-Path -Parent $PSScriptRoot

$SecretNames = @(
    'PARA11AX_TOKEN',
    'ABUSECH_API_KEY',
    'ABUSEIPDB_API_KEY',
    'GREYNOISE_API_KEY',
    'VIRUSTOTAL_API_KEY',
    'HYBRID_ANALYSIS_API_KEY',
    'URLSCAN_API_KEY',
    'WEBAMON_API_KEY',
    'SENTRY_AUTH_TOKEN',
    'OTX_API_KEY',
    'SHODAN_API_KEY',
    'CENSYS_PAT',
    'PULSEDIVE_API_KEY',
    'IPINFO_TOKEN',
    'MALPEDIA_API_TOKEN',
    'NVD_API_KEY',
    'VULNCHECK_API_TOKEN',
    'CLOUDFLARE_RADAR_TOKEN',
    'RANSOMWARE_LIVE_API_KEY',
    'MODAT_API_KEY'
)

function Refresh-ProcessPath {
    $machine = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $user = [Environment]::GetEnvironmentVariable('Path', 'User')
    $env:Path = "$machine;$user"
}

function Invoke-NativeChecked {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments
    )

    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$FilePath failed with exit code $LASTEXITCODE"
    }
}

function Invoke-NativeCapture {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments
    )

    $output = (& $FilePath @Arguments 2>&1 | Out-String).Trim()
    if ($LASTEXITCODE -ne 0) {
        throw "$FilePath failed with exit code $LASTEXITCODE"
    }
    return $output
}

function New-GatewayToken {
    $bytes = New-Object byte[] 48
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($bytes)
    } finally {
        $rng.Dispose()
    }

    return [Convert]::ToBase64String($bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function Convert-SecureStringToPlainText {
    param([Parameter(Mandatory = $true)][Security.SecureString]$Secure)

    $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
    }
}

function Save-GatewayToken {
    param([Parameter(Mandatory = $true)][string]$Token)

    $tokenBytes = [Text.Encoding]::UTF8.GetBytes($Token)
    $protectedBytes = $null
    $encoded = $null
    try {
        $protectedBytes = [Security.Cryptography.ProtectedData]::Protect(
            $tokenBytes,
            $null,
            [Security.Cryptography.DataProtectionScope]::CurrentUser
        )
        New-Item -ItemType Directory -Path $GatewayTokenDir -Force | Out-Null
        $encoded = [Convert]::ToBase64String($protectedBytes)
        [IO.File]::WriteAllText($GatewayTokenFile, $encoded, (New-Object Text.UTF8Encoding($false)))
    } finally {
        if ($tokenBytes) { [Array]::Clear($tokenBytes, 0, $tokenBytes.Length) }
        if ($protectedBytes) { [Array]::Clear($protectedBytes, 0, $protectedBytes.Length) }
        $encoded = $null
    }
}

function Get-StoredGatewayToken {
    if (-not (Test-Path $GatewayTokenFile)) { return $null }

    try {
        $encoded = [IO.File]::ReadAllText($GatewayTokenFile).Trim()
        $protectedBytes = [Convert]::FromBase64String($encoded)
        try {
            $tokenBytes = [Security.Cryptography.ProtectedData]::Unprotect(
                $protectedBytes,
                $null,
                [Security.Cryptography.DataProtectionScope]::CurrentUser
            )
            try {
                $token = [Text.Encoding]::UTF8.GetString($tokenBytes).Trim()
                if ([string]::IsNullOrWhiteSpace($token)) { return $null }
                return $token
            } finally {
                if ($tokenBytes) { [Array]::Clear($tokenBytes, 0, $tokenBytes.Length) }
            }
        } finally {
            if ($protectedBytes) { [Array]::Clear($protectedBytes, 0, $protectedBytes.Length) }
        }
    } catch {
        Write-Warning 'Stored gateway token could not be read with current-user DPAPI; a replacement will be created.'
        return $null
    }
}

function Ensure-Winget {
    if (-not (Get-Command winget.exe -ErrorAction SilentlyContinue)) {
        throw 'winget is required to install or align Git/Node.js automatically. Install Microsoft App Installer, then rerun this script.'
    }
}

function Ensure-Git {
    if (Get-Command git.exe -ErrorAction SilentlyContinue) { return }

    Ensure-Winget
    Write-Host 'Installing Git...'
    Invoke-NativeChecked winget.exe install --id Git.Git -e --source winget --accept-package-agreements --accept-source-agreements --silent
    Refresh-ProcessPath

    if (-not (Get-Command git.exe -ErrorAction SilentlyContinue)) {
        throw 'Git installation completed but git.exe is not visible in PATH. Reopen PowerShell and rerun this script.'
    }
}

function Get-NodeMajor {
    $node = Get-Command node.exe -ErrorAction SilentlyContinue
    if (-not $node) { return $null }

    try {
        $raw = (& $node.Source --version).Trim().TrimStart('v')
        return ([Version]$raw).Major
    } catch {
        return $null
    }
}

function Ensure-Node {
    $node = Get-Command node.exe -ErrorAction SilentlyContinue
    $npm = Get-Command npm.cmd -ErrorAction SilentlyContinue
    $major = Get-NodeMajor

    if ($node -and $npm -and $major -eq $RequiredNodeMajor) {
        return
    }

    Ensure-Winget

    if ($node -and $npm) {
        Write-Host "Aligning Node.js to required major $RequiredNodeMajor..."
        & winget.exe upgrade --id OpenJS.NodeJS.LTS -e --source winget --accept-package-agreements --accept-source-agreements --silent
        if ($LASTEXITCODE -ne 0) {
            Invoke-NativeChecked winget.exe install --id OpenJS.NodeJS.LTS -e --source winget --accept-package-agreements --accept-source-agreements --silent --force
        }
    } else {
        Write-Host "Installing Node.js $RequiredNodeMajor LTS..."
        Invoke-NativeChecked winget.exe install --id OpenJS.NodeJS.LTS -e --source winget --accept-package-agreements --accept-source-agreements --silent
    }

    Refresh-ProcessPath

    if (-not (Get-Command node.exe -ErrorAction SilentlyContinue) -or -not (Get-Command npm.cmd -ErrorAction SilentlyContinue)) {
        throw 'Node.js installation completed but node/npm are not visible in PATH. Reopen PowerShell and rerun the script.'
    }

    $major = Get-NodeMajor
    if ($major -ne $RequiredNodeMajor) {
        throw "Node.js $RequiredNodeMajor.x is required for runtime parity; found $(& node.exe --version)."
    }
}

function Get-VercelCliVersion {
    param([Parameter(Mandatory = $true)][string]$Vercel)

    try {
        $raw = (& $Vercel --version 2>$null | Out-String).Trim()
        if ($raw -match '(\d+\.\d+\.\d+)') {
            return $Matches[1]
        }
    } catch {
        return $null
    }

    return $null
}

function Ensure-VercelCli {
    $vercel = Get-Command vercel.cmd -ErrorAction SilentlyContinue
    $currentVersion = if ($vercel) { Get-VercelCliVersion -Vercel $vercel.Source } else { $null }

    if (-not $vercel -or $currentVersion -ne $PinnedVercelCliVersion) {
        Write-Host "Installing pinned Vercel CLI $PinnedVercelCliVersion..."
        Invoke-NativeChecked npm.cmd install -g "vercel@$PinnedVercelCliVersion"
        Refresh-ProcessPath
        $vercel = Get-Command vercel.cmd -ErrorAction SilentlyContinue
    }

    if (-not $vercel) {
        throw 'Vercel CLI installation completed but vercel.cmd is not visible in PATH. Reopen PowerShell and rerun this script.'
    }

    $currentVersion = Get-VercelCliVersion -Vercel $vercel.Source
    if ($currentVersion -ne $PinnedVercelCliVersion) {
        throw "Vercel CLI $PinnedVercelCliVersion is required by this bootstrap; found '$currentVersion'."
    }

    return $vercel.Source
}

function Ensure-VercelLogin {
    param([Parameter(Mandatory = $true)][string]$Vercel)

    & $Vercel whoami *> $null
    if ($LASTEXITCODE -eq 0) { return }

    Write-Host 'Vercel login required. Complete the browser/email login flow once.'
    Invoke-NativeChecked $Vercel login
}

function Assert-ExactOriginMain {
    $dirty = Invoke-NativeCapture git.exe status --porcelain
    if (-not [string]::IsNullOrWhiteSpace($dirty)) {
        throw 'Repository has modified or untracked files. Commit/stash/remove them before provisioning so production cannot include unreviewed source.'
    }

    Invoke-NativeChecked git.exe fetch --depth 1 origin main
    $fetchedHead = Invoke-NativeCapture git.exe rev-parse FETCH_HEAD
    $currentHead = Invoke-NativeCapture git.exe rev-parse HEAD
    if ($currentHead -ne $fetchedHead) {
        throw "Local checkout is not the current origin/main ($fetchedHead). Update main to that commit and rerun the bootstrap."
    }

    return $fetchedHead
}

function Prepare-VerifiedWorkspace {
    param([Parameter(Mandatory = $true)][string]$Vercel)

    if (-not (Test-Path (Join-Path $RepoRoot '.git'))) {
        throw 'Run this bootstrap from a Git clone of ger1e/para11ax; a verified repository checkout is required for production deployment.'
    }

    Push-Location $RepoRoot
    try {
        $originUrl = Invoke-NativeCapture git.exe remote get-url origin
        $allowedOrigins = @(
            $RepoUrl,
            'https://github.com/ger1e/para11ax',
            'git@github.com:ger1e/para11ax.git'
        )
        if ($originUrl -notin $allowedOrigins) {
            throw "Unexpected origin remote '$originUrl'. Refusing to deploy source from an unapproved repository."
        }

        $verifiedCommit = Assert-ExactOriginMain
        New-Item -ItemType Directory -Path '.vercel' -Force | Out-Null
        $projectJson = @{ orgId = $OrgId; projectId = $ProjectId } | ConvertTo-Json -Compress
        [IO.File]::WriteAllText((Join-Path $RepoRoot '.vercel\project.json'), $projectJson, (New-Object Text.UTF8Encoding($false)))

        Write-Host "Verified clean origin/main source at $verifiedCommit and linked it to $TeamSlug/$ProjectName."
        Write-Host 'Connecting GitHub repository to the Vercel project...'
        Invoke-NativeChecked $Vercel git connect --yes --scope $TeamSlug
        Write-Host 'GitHub repository connection verified.'

        return $RepoRoot
    } catch {
        Pop-Location
        throw
    }
}

function Set-SensitiveVercelEnv {
    param(
        [Parameter(Mandatory = $true)][string]$Vercel,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Value
    )

    foreach ($target in @('production', 'preview')) {
        $Value | & $Vercel env add $Name $target --sensitive --force --scope $TeamSlug
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to set $Name for $target."
        }
    }
}

function Verify-ProductionHealth {
    param(
        [Parameter(Mandatory = $true)][string]$Vercel,
        [Parameter(Mandatory = $true)][string]$GatewayToken
    )

    $deploymentUrl = "https://$ProductionAlias"
    Write-Host "Verifying protected production health at $deploymentUrl/api/para11ax/health ..."

    $authorization = "Authorization: Bearer $GatewayToken"
    try {
        $raw = (& $Vercel curl '/api/para11ax/health' --deployment $deploymentUrl --scope $TeamSlug -- --header $authorization | Out-String).Trim()
    } finally {
        $authorization = $null
    }
    if ($LASTEXITCODE -ne 0) {
        throw "Authenticated Vercel production health request failed with exit code $LASTEXITCODE."
    }

    try {
        $health = $raw | ConvertFrom-Json
    } catch {
        throw 'Production health check failed: authenticated Vercel request did not return valid JSON.'
    }

    if ($health.status -ne 'ok') {
        throw "Production health check failed: status '$($health.status)'."
    }
    if (-not $health.gatewayAuthConfigured) {
        throw 'Production health check failed: PARA11AX_TOKEN is not configured.'
    }

    Write-Host 'Production health verified through authenticated Vercel CLI: gateway authentication is configured.'
}

Write-Host '=== PARA11AX / Vercel bootstrap ==='
Write-Host 'Secrets are entered locally with masked input and are never written to GitHub.'
Write-Host 'The gateway bearer is stored locally with current-user Windows DPAPI and reused by Maltego.'
Write-Host 'Production deployment is allowed only from a clean checkout exactly matching origin/main.'
Write-Host 'For provider secrets, Enter skips that provider.'
Write-Host ''

Ensure-Git
Ensure-Node
$Vercel = Ensure-VercelCli

Write-Host "Node.js: $(& node.exe --version)"
Write-Host "Vercel CLI: $(& $Vercel --version)"
Ensure-VercelLogin -Vercel $Vercel
$workspace = Prepare-VerifiedWorkspace -Vercel $Vercel
$gatewayToken = $null
$healthToken = $null

try {
    $gatewayToken = Get-StoredGatewayToken
    if ($gatewayToken) {
        Write-Host 'Reusing stored gateway token protected with current-user Windows DPAPI.'
    } else {
        $secure = Read-Host 'PARA11AX_TOKEN (Enter = generate securely)' -AsSecureString
        $gatewayToken = Convert-SecureStringToPlainText -Secure $secure
        if ([string]::IsNullOrWhiteSpace($gatewayToken)) {
            $gatewayToken = New-GatewayToken
            Write-Host 'Generated a new gateway token and protected it with current-user Windows DPAPI.'
        }
        Save-GatewayToken -Token $gatewayToken
    }

    Set-SensitiveVercelEnv -Vercel $Vercel -Name 'PARA11AX_TOKEN' -Value $gatewayToken
    Write-Host 'Added/updated PARA11AX_TOKEN for Production + Preview and retained only the DPAPI-protected local copy.'
    $gatewayToken = $null
    [GC]::Collect()

    foreach ($name in $SecretNames | Where-Object { $_ -ne 'PARA11AX_TOKEN' }) {
        $secure = Read-Host "$name (Enter = skip)" -AsSecureString
        $plain = Convert-SecureStringToPlainText -Secure $secure

        if ([string]::IsNullOrWhiteSpace($plain)) {
            Write-Host "Skipped $name"
            $plain = $null
            continue
        }

        Set-SensitiveVercelEnv -Vercel $Vercel -Name $name -Value $plain
        Write-Host "Added/updated $name for Production + Preview"
        $plain = $null
        [GC]::Collect()
    }

    Write-Host ''
    Write-Host 'Configured Vercel environment variables:'
    Invoke-NativeChecked $Vercel env ls --scope $TeamSlug

    Write-Host ''
    $verifiedCommit = Assert-ExactOriginMain
    Write-Host "Deploying exact verified origin/main source $verifiedCommit to production..."
    Invoke-NativeChecked $Vercel deploy --prod --yes --scope $TeamSlug

    $healthToken = Get-StoredGatewayToken
    if ([string]::IsNullOrWhiteSpace($healthToken)) {
        throw 'Production health check failed: stored gateway bearer is unavailable.'
    }
    try {
        Verify-ProductionHealth -Vercel $Vercel -GatewayToken $healthToken
    } finally {
        $healthToken = $null
        [GC]::Collect()
    }
} finally {
    $gatewayToken = $null
    $healthToken = $null
    [GC]::Collect()
    if ((Get-Location).Path -eq $workspace) {
        Pop-Location
    }
}

Write-Host ''
Write-Host 'Bootstrap complete.'
Write-Host 'No secret values were written to the repository or printed to the terminal.'
Write-Host 'GitHub is connected to Vercel, Production + Preview secrets were applied, exact origin/main was deployed, and /api/para11ax/health passed.'
