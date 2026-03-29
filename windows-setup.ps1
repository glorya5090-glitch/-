# windows-setup.ps1 — agentpay Windows source-build setup & auto-start
# Run in PowerShell (Admin not required for Task Scheduler user tasks):
#   Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned -Force
#   .\windows-setup.ps1
#
# IMPORTANT: Never re-run after agentpay admin setup is done — address will change!

param(
  [switch]$SkipBuild,
  [switch]$RegisterStartup,
  [switch]$UnregisterStartup
)

$ErrorActionPreference = "Stop"

$BinDir    = "$env:USERPROFILE\.agentpay\bin"
$SrcDir    = "$env:USERPROFILE\.agentpay-sdk-src"
$DaemonExe = "$BinDir\agentpay-daemon.exe"
$TaskName  = "agentpay-daemon"

function Write-Step  { Write-Host "  -> $args" -ForegroundColor Cyan }
function Write-Ok    { Write-Host "  v  $args" -ForegroundColor Green }
function Write-Warn  { Write-Host "  !  $args" -ForegroundColor Yellow }
function Write-Fail  { Write-Host "  x  $args" -ForegroundColor Red; exit 1 }

# ── PATH helper ────────────────────────────────────────────────────────────────
function Add-ToUserPath([string]$Dir) {
  $current = [Environment]::GetEnvironmentVariable("PATH", "User")
  if ($current -notlike "*$Dir*") {
    [Environment]::SetEnvironmentVariable("PATH", "$current;$Dir", "User")
    $env:PATH += ";$Dir"
    Write-Ok "Added $Dir to user PATH"
  } else {
    Write-Ok "$Dir already in PATH"
  }
}

# ── Source build ───────────────────────────────────────────────────────────────
function Invoke-SourceBuild {
  Write-Host "`nagentpay Windows source build" -ForegroundColor White -BackgroundColor DarkBlue
  Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

  # Prerequisites check
  foreach ($cmd in @("git", "node", "pnpm", "cargo")) {
    if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) {
      Write-Fail "$cmd not found — install it first"
    }
  }

  # Ensure MSVC linker comes before Git's link.exe
  $vsWhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
  if (Test-Path $vsWhere) {
    $vsPath = & $vsWhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2>$null
    if ($vsPath) {
      $msvcBin = Get-ChildItem "$vsPath\VC\Tools\MSVC" -Directory | Sort-Object Name | Select-Object -Last 1
      if ($msvcBin) {
        $linkerDir = "$($msvcBin.FullName)\bin\Hostx64\x64"
        if (Test-Path "$linkerDir\link.exe") {
          $env:PATH = "$linkerDir;$env:PATH"
          Write-Ok "MSVC linker prepended to PATH"
        }
      }
    }
  }

  # Clone or update
  if (Test-Path "$SrcDir\.git") {
    Write-Step "Updating agentpay-sdk source..."
    git -C $SrcDir pull --ff-only
  } else {
    Write-Step "Cloning agentpay-sdk..."
    git clone --depth=1 https://github.com/worldliberty/agentpay-sdk.git $SrcDir
  }

  # Build JS bundle
  Write-Step "Installing Node dependencies..."
  Push-Location $SrcDir
  try {
    pnpm install --frozen-lockfile
    Write-Step "Building JS bundle..."
    pnpm run build
    Write-Step "Installing CLI launcher..."
    pnpm run install:cli-launcher
    Write-Step "Compiling Rust binaries (this takes a few minutes)..."
    pnpm run install:rust-binaries
  } finally {
    Pop-Location
  }

  Write-Ok "agentpay installed to $BinDir"
  Add-ToUserPath $BinDir
}

# ── Task Scheduler registration ────────────────────────────────────────────────
function Register-DaemonStartup {
  Write-Host "`nagentpay-daemon auto-start (Task Scheduler)" -ForegroundColor White -BackgroundColor DarkBlue
  Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

  if (-not (Test-Path $DaemonExe)) {
    Write-Fail "agentpay-daemon.exe not found at $DaemonExe — run the build first"
  }

  # Remove existing task if present
  $existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
  if ($existing) {
    Write-Step "Removing existing task..."
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
  }

  # Build the task with AGENTPAY_SIGNER_BACKEND=software
  $action = New-ScheduledTaskAction `
    -Execute $DaemonExe `
    -WorkingDirectory $BinDir

  $trigger = New-ScheduledTaskTrigger -AtLogon

  $settings = New-ScheduledTaskSettingsSet `
    -ExecutionTimeLimit (New-TimeSpan -Days 0) `
    -RestartCount 5 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -StartWhenAvailable

  # Pass env var via wrapper — Task Scheduler doesn't support per-task env vars
  # directly, so we create a tiny launcher script
  $launcherPs1 = "$BinDir\start-daemon.ps1"
  @"
`$env:AGENTPAY_SIGNER_BACKEND = 'software'
`$env:AGENTPAY_DAEMON_BIN     = '$DaemonExe'
Start-Process -FilePath '$DaemonExe' -NoNewWindow -PassThru
"@ | Set-Content -Path $launcherPs1 -Encoding UTF8

  $action = New-ScheduledTaskAction `
    -Execute "powershell.exe" `
    -Argument "-NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$launcherPs1`"" `
    -WorkingDirectory $BinDir

  $principal = New-ScheduledTaskPrincipal `
    -UserId ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name) `
    -LogonType Interactive `
    -RunLevel Limited

  Register-ScheduledTask `
    -TaskName  $TaskName `
    -Action    $action `
    -Trigger   $trigger `
    -Settings  $settings `
    -Principal $principal `
    -Description "AgentPay daemon (software signer, source build)" | Out-Null

  Write-Ok "Task '$TaskName' registered — runs at every login"

  # Start it now without waiting for next reboot
  Write-Step "Starting daemon now..."
  Start-ScheduledTask -TaskName $TaskName
  Start-Sleep -Seconds 2

  $state = (Get-ScheduledTask -TaskName $TaskName).State
  Write-Ok "Task state: $state"
}

function Unregister-DaemonStartup {
  $existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
  if ($existing) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    Write-Ok "Task '$TaskName' removed"
  } else {
    Write-Warn "Task '$TaskName' not found"
  }
}

# ── Verify installation ────────────────────────────────────────────────────────
function Test-AgentpayInstall {
  Write-Host "`nVerifying installation..." -ForegroundColor Cyan
  $ap = Get-Command agentpay -ErrorAction SilentlyContinue
  if ($ap) {
    $ver = & agentpay --version 2>&1
    Write-Ok "agentpay $ver"
  } else {
    Write-Warn "agentpay not in PATH yet — open a new terminal"
  }

  $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
  if ($task) {
    Write-Ok "Startup task: $($task.State)"
  } else {
    Write-Warn "Startup task not registered"
  }
}

# ── Main ───────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  wlfi / agentpay  Windows setup  v0.2.0" -ForegroundColor Cyan -BackgroundColor Black
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if ($UnregisterStartup) { Unregister-DaemonStartup; exit 0 }

if (-not $SkipBuild)      { Invoke-SourceBuild }
if ($RegisterStartup -or (-not $SkipBuild)) { Register-DaemonStartup }

Test-AgentpayInstall

Write-Host ""
Write-Ok "All done! Open a new terminal and run:  agentpay wallet --json"
Write-Host ""
