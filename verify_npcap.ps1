Param(
    [switch]$VerboseOutput,
    [switch]$Json,
    [switch]$StartService,
    [string]$MinVersion
)

function Test-IsAdmin {
    try {
        $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

function Compare-Version([string]$a, [string]$b) {
    if ([string]::IsNullOrWhiteSpace($a) -or [string]::IsNullOrWhiteSpace($b)) { return $null }
    try {
        $va = [Version]$a
        $vb = [Version]$b
        return $va.CompareTo($vb)
    } catch {
        return [string]::Compare($a, $b)
    }
}

function Get-NpcapInfo {
    $info = [ordered]@{
        ServiceName = $null
        ServiceStatus = $null
        ServiceRunning = $false
        FoundPaths = @()
        Version = $null
        RegistryChecked = @()
        PathsChecked = @()
        Installed = $false
        IsAdmin = (Test-IsAdmin)
        OsVersion = (Get-CimInstance Win32_OperatingSystem).Version
        Architecture = $env:PROCESSOR_ARCHITECTURE
    }

    try {
        $svc = Get-Service -Name 'npcap' -ErrorAction Stop
        $info.ServiceName = $svc.Name
        $info.ServiceStatus = $svc.Status.ToString()
        $info.ServiceRunning = ($svc.Status -eq 'Running')
    } catch {
        $info.ServiceName = 'npcap (not found)'
        $info.ServiceStatus = 'NotFound'
        $info.ServiceRunning = $false
    }

    $paths = @(
        "$env:SystemRoot\System32\drivers\npcap.sys",
        "$env:SystemRoot\System32\Npcap\npcap.dll",
        "$env:SystemRoot\SysWOW64\Npcap\npcap.dll",
        "$env:ProgramFiles\Npcap\npcap.dll",
        "$env:ProgramFiles(x86)\Npcap\npcap.dll",
        "$env:SystemRoot\System32\Npcap\Packet.dll"
    )
    $info.PathsChecked = $paths
    foreach ($p in $paths) { if (Test-Path $p) { $info.FoundPaths += $p } }

    $regPaths = @('HKLM:\SOFTWARE\Npcap','HKLM:\SOFTWARE\WOW6432Node\Npcap')
    $info.RegistryChecked = $regPaths
    foreach ($rp in $regPaths) {
        try { $key = Get-ItemProperty -Path $rp -ErrorAction Stop; if ($key.Version) { $info.Version = $key.Version; break } } catch {}
    }

    $info.Installed = ($info.ServiceStatus -ne 'NotFound') -or ($info.FoundPaths.Count -gt 0) -or ($info.Version)
    return $info
}

Write-Host "== Checking Npcap installation ==" -ForegroundColor Cyan
$info = Get-NpcapInfo
$exitCode = 1
$message = $null

if ($info.Installed) {
    if ($MinVersion) { $cmp = Compare-Version $info.Version $MinVersion; if ($cmp -ne $null -and $cmp -lt 0) { $exitCode = 3; $message = "Npcap installed but version '$($info.Version)' < required '$MinVersion'" } }
    if (-not $message) {
        if ($info.ServiceRunning) { $exitCode = 0; $message = "Npcap installed and service running" }
        else {
            if ($StartService) {
                if (-not $info.IsAdmin) { $exitCode = 2; $message = "Npcap installed but service stopped; re-run as Administrator to start it" }
                else {
                    try { Start-Service -Name 'npcap' -ErrorAction Stop; Start-Sleep -Seconds 1; $svc2 = Get-Service -Name 'npcap'; if ($svc2.Status -eq 'Running') { $exitCode = 0; $message = "Npcap installed and service started"; $info.ServiceRunning = $true; $info.ServiceStatus = 'Running' } else { $exitCode = 4; $message = "Npcap installed but failed to start service (status: $($svc2.Status))" } }
                    catch { $exitCode = 4; $message = "Npcap installed but failed to start service: $($_.Exception.Message)" }
                }
            } else { $exitCode = 2; $message = "Npcap installed but service stopped" }
        }
    }
} else { $exitCode = 1; $message = "Npcap not detected" }

if ($Json) {
    $out = [ordered]@{ service = [ordered]@{ name = $info.ServiceName; status = $info.ServiceStatus; running = $info.ServiceRunning }; installed = $info.Installed; version = $info.Version; paths_checked = $info.PathsChecked; found_paths = $info.FoundPaths; registry_checked = $info.RegistryChecked; os_version = $info.OsVersion; architecture = $info.Architecture; is_admin = $info.IsAdmin; exit_code = $exitCode; message = $message }
    $out | ConvertTo-Json -Depth 5 | Write-Output
} else {
    Write-Host "Service:" $info.ServiceName
    Write-Host "Status :" $info.ServiceStatus
    Write-Host "Running:" $info.ServiceRunning
    $versionOut = if ([string]::IsNullOrWhiteSpace($info.Version)) { 'Unknown' } else { $info.Version }
    $pathsOut = if ($info.FoundPaths -and $info.FoundPaths.Count -gt 0) { ($info.FoundPaths -join ', ') } else { 'None' }
    Write-Host "Version:" $versionOut
    Write-Host "Driver/Files Found:" $pathsOut
    if ($VerboseOutput) { Write-Host "Paths checked:" ($info.PathsChecked -join ', '); Write-Host "Registry checked:" ($info.RegistryChecked -join ', '); Write-Host "OS:" $info.OsVersion "Arch:" $info.Architecture "Admin:" $info.IsAdmin }
    if ($exitCode -eq 0) { Write-Host $message -ForegroundColor Green }
    elseif ($exitCode -eq 2) { Write-Host $message -ForegroundColor Yellow }
    elseif ($exitCode -eq 3) { Write-Host $message -ForegroundColor Yellow }
    elseif ($exitCode -eq 4) { Write-Host $message -ForegroundColor Red }
    else { Write-Host $message -ForegroundColor Red }
    if ($exitCode -ne 0) { Write-Host "Download: https://npcap.com/#download"; Write-Host "Hint: Run installer with '/npf_startup=yes' to auto-start the service." }
}

exit $exitCode