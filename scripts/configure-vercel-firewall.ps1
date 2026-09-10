#Requires -Version 5.1
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ProjectName            = 'para11ax'
$ProjectId              = 'prj_ojUpOTw8x8KOj9CrTs8jih1mrPjo'
$TeamSlug               = 'geri6'
$OrgId                  = 'team_hXokufMlDFuhPPT5r8jPf4aH'
$PinnedVercelCliVersion = '58.4.4'
$RuleName               = 'para11ax-api-post-rate-limit'
$PathCondition          = '{"type":"path","op":"pre","value":"/api/para11ax/"}'
$MethodCondition        = '{"type":"method","op":"eq","value":"POST"}'
$RepoRoot               = Split-Path -Parent $PSScriptRoot
$ProjectLink            = Join-Path $RepoRoot '.vercel\project.json'

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

function Get-PinnedVercelCli {
    $vercel = Get-Command vercel.cmd -ErrorAction SilentlyContinue
    if (-not $vercel) {
        throw "Vercel CLI $PinnedVercelCliVersion is required. Install it with: npm install -g vercel@$PinnedVercelCliVersion"
    }

    $version = Get-VercelCliVersion -Vercel $vercel.Source
    if ($version -ne $PinnedVercelCliVersion) {
        throw "Vercel CLI $PinnedVercelCliVersion is required; found '$version'."
    }

    return $vercel.Source
}

function Assert-VercelLogin {
    param([Parameter(Mandatory = $true)][string]$Vercel)

    & $Vercel whoami *> $null
    if ($LASTEXITCODE -ne 0) {
        throw 'Vercel authentication is required. Run vercel login, then rerun this helper.'
    }
}

function Assert-CanonicalProjectLink {
    if (-not (Test-Path $ProjectLink)) {
        throw "Vercel project link is missing. Run scripts/bootstrap-vercel.ps1 or vercel link for $TeamSlug/$ProjectName first."
    }

    try {
        $link = Get-Content -LiteralPath $ProjectLink -Raw | ConvertFrom-Json
    } catch {
        throw 'Vercel project link is unreadable or malformed; refusing to mutate firewall configuration.'
    }

    if ($link.projectId -ne $ProjectId -or $link.orgId -ne $OrgId) {
        throw "Linked Vercel project is not canonical $TeamSlug/$ProjectName ($ProjectId); refusing to mutate firewall configuration."
    }
}

$Vercel = Get-PinnedVercelCli
Assert-VercelLogin -Vercel $Vercel
Assert-CanonicalProjectLink

$ruleArgs = @(
    '--condition', $PathCondition,
    '--condition', $MethodCondition,
    '--action', 'rate_limit',
    '--rate-limit-window', '60',
    '--rate-limit-requests', '30',
    '--rate-limit-keys', 'ip',
    '--rate-limit-algo', 'fixed_window',
    '--rate-limit-action', 'rate_limit',
    '--yes',
    '--scope', $TeamSlug
)

Push-Location $RepoRoot
try {
    & $Vercel firewall rules inspect $RuleName --scope $TeamSlug *> $null
    $ruleExists = ($LASTEXITCODE -eq 0)

    if ($ruleExists) {
        Write-Host "Staging exact update for existing Vercel Firewall rule '$RuleName'..."
        Invoke-NativeChecked $Vercel firewall rules edit $RuleName @ruleArgs
    } else {
        Write-Host "Staging new Vercel Firewall rule '$RuleName'..."
        Invoke-NativeChecked $Vercel firewall rules add $RuleName @ruleArgs
    }

    Write-Host ''
    Write-Host 'Staged Vercel Firewall diff:'
    Invoke-NativeChecked $Vercel firewall diff --scope $TeamSlug

    Write-Host ''
    Write-Host 'No firewall changes were published automatically.'
    Write-Host 'Review the diff above. Publish only if it contains no unrelated staged changes:'
    Write-Host '  vercel firewall publish --yes'
} finally {
    Pop-Location
}
