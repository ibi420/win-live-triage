# =============================================================================
#  network_forensics.ps1 — Process & Network Connection Auditor (Windows)
#  Usage: Run PowerShell as Administrator, then:
#         Set-ExecutionPolicy -Scope Process Bypass
#         .\network_forensics.ps1
#  Output: network_forensics_report_<timestamp>.txt
# =============================================================================

#Requires -Version 5.0

$Timestamp  = Get-Date -Format "yyyyMMdd_HHmmss"
$ReportFile = "network_forensics_report_$Timestamp.txt"
$Alerts     = 0

# ---------- colour & logging helpers -----------------------------------------
function Write-Log {
    param([string]$Text, [string]$Color = "White")
    Write-Host $Text -ForegroundColor $Color
    $Text | Out-File -FilePath $ReportFile -Append -Encoding UTF8
}

function Write-Sep  { Write-Log ("─" * 72) "DarkCyan" }
function Write-Head { param([string]$Title) Write-Sep; Write-Log "  $Title" "Yellow"; Write-Sep }

# ---------- admin check ------------------------------------------------------
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Log "[!] Not running as Administrator — some data may be incomplete." "Red"
    Write-Log "    Right-click PowerShell > 'Run as Administrator' for full results." "Red"
    Write-Log ""
}

# =============================================================================
Write-Log ""
Write-Log "  ██████  Network Forensics Report" "Green"
Write-Log "  Generated : $(Get-Date)"
Write-Log "  Hostname  : $env:COMPUTERNAME"
Write-Log "  OS        : $((Get-CimInstance Win32_OperatingSystem).Caption)"
Write-Log "  User      : $env:USERDOMAIN\$env:USERNAME"
Write-Log "  Report    : $ReportFile"
Write-Log ""

# =============================================================================
Write-Head "1 / 5  — SYSTEM SNAPSHOT"
Write-Log ""

# Uptime
$os      = Get-CimInstance Win32_OperatingSystem
$uptime  = (Get-Date) - $os.LastBootUpTime
Write-Log ("  Last Boot : {0}  (Uptime: {1}d {2}h {3}m)" -f $os.LastBootUpTime, $uptime.Days, $uptime.Hours, $uptime.Minutes)
Write-Log ""

# Logged-on users
Write-Log "  Logged-on users:" "Cyan"
try {
    $sessions = query user 2>$null
    if ($sessions) { $sessions | ForEach-Object { Write-Log "  $_" } }
    else           { Write-Log "  (query user not available)" "DarkGray" }
} catch { Write-Log "  (could not enumerate sessions)" "DarkGray" }
Write-Log ""

# Recent logins from Security event log
Write-Log "  Last 10 interactive logins (Event 4624 Type 2/10):" "Cyan"
try {
    Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -MaxEvents 200 -ErrorAction Stop |
        Where-Object { $_.Properties[8].Value -in @(2,10) } |
        Select-Object -First 10 |
        ForEach-Object {
            Write-Log ("  {0}  User: {1}\{2}  From: {3}" -f
                $_.TimeCreated,
                $_.Properties[6].Value,
                $_.Properties[5].Value,
                $_.Properties[18].Value)
        }
} catch {
    Write-Log "  (Security log not accessible — run as Administrator)" "DarkGray"
}

# =============================================================================
Write-Head "2 / 5  — ALL RUNNING PROCESSES"
Write-Log ""
Write-Log ("  {0,-7} {1,-7} {2,-28} {3,-8} {4}" -f "PID","PPID","NAME","CPU(s)","PATH")
Write-Log ("  {0,-7} {1,-7} {2,-28} {3,-8} {4}" -f "-------","-------","----------------------------","--------","----")

Get-CimInstance Win32_Process | Sort-Object -Property KernelModeTime -Descending | ForEach-Object {
    $cpu  = [math]::Round(($_.KernelModeTime + $_.UserModeTime) / 1e7, 1)
    $path = if ($_.ExecutablePath) { $_.ExecutablePath } else { "(system/no path)" }
    Write-Log ("  {0,-7} {1,-7} {2,-28} {3,-8} {4}" -f $_.ProcessId, $_.ParentProcessId, $_.Name.Substring(0,[math]::Min(28,$_.Name.Length)), $cpu, $path)
}

# =============================================================================
Write-Head "3 / 5  — ACTIVE NETWORK CONNECTIONS (per process)"
Write-Log ""

# Build PID → process name lookup
$pidMap = @{}
Get-Process | ForEach-Object { $pidMap[$_.Id] = $_.Name }

Write-Log ("  {0,-7} {1,-22} {2,-12} {3,-26} {4,-26} {5}" -f "PID","PROCESS","STATE","LOCAL","REMOTE","USER")
Write-Log ("  {0,-7} {1,-22} {2,-12} {3,-26} {4,-26} {5}" -f "-------","----------------------","------------","--------------------------","--------------------------","----")

$connections = Get-NetTCPConnection -ErrorAction SilentlyContinue
$connections += Get-NetUDPEndpoint  -ErrorAction SilentlyContinue | Select-Object `
    LocalAddress, LocalPort,
    @{N='RemoteAddress';E={''}},
    @{N='RemotePort';E={0}},
    @{N='State';E={'UDP'}},
    OwningProcess

foreach ($c in $connections) {
    $pid_   = $c.OwningProcess
    $pname  = if ($pidMap.ContainsKey($pid_)) { $pidMap[$pid_] } else { "?" }
    $local  = "$($c.LocalAddress):$($c.LocalPort)"
    $remote = if ($c.RemoteAddress) { "$($c.RemoteAddress):$($c.RemotePort)" } else { "" }
    $state  = $c.State

    # Resolve owner username
    $owner = try {
        (Get-CimInstance Win32_Process -Filter "ProcessId=$pid_" -ErrorAction Stop).GetOwner().User
    } catch { "?" }

    Write-Log ("  {0,-7} {1,-22} {2,-12} {3,-26} {4,-26} {5}" -f
        $pid_, $pname.Substring(0,[math]::Min(22,$pname.Length)),
        $state, $local.Substring(0,[math]::Min(26,$local.Length)),
        $remote.Substring(0,[math]::Min(26,$remote.Length)), $owner)
}

# =============================================================================
Write-Head "4 / 5  — EXTERNAL IP → REVERSE DNS RESOLUTION"
Write-Log ""

# Collect unique external remote IPs
$externalIPs = $connections |
    Where-Object { $_.RemoteAddress -and $_.RemoteAddress -notmatch '^(0\.0\.0\.0|127\.|::)' } |
    Select-Object -ExpandProperty RemoteAddress -Unique |
    Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' }   # IPv4 only

if (-not $externalIPs) {
    Write-Log "  No external IPv4 connections found at this moment." "Yellow"
} else {
    Write-Log ("  {0,-18} {1,-45} {2}" -f "IP ADDRESS","REVERSE DNS","PROCESSES")
    Write-Log ("  {0,-18} {1,-45} {2}" -f "------------------","---------------------------------------------","---------")

    foreach ($ip in $externalIPs) {
        # Reverse DNS
        $rdns = try {
            [System.Net.Dns]::GetHostEntry($ip).HostName
        } catch { "(unresolved)" }

        # Which processes connect to this IP?
        $procs = $connections |
            Where-Object { $_.RemoteAddress -eq $ip } |
            ForEach-Object { if ($pidMap.ContainsKey($_.OwningProcess)) { $pidMap[$_.OwningProcess] } else { "PID:$($_.OwningProcess)" } } |
            Sort-Object -Unique
        $procStr = $procs -join ", "

        # Flag private ranges
        $flag = if ($ip -match '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)') { " [LAN]" } else { "" }

        Write-Log ("  {0,-18} {1,-45} {2}{3}" -f $ip, $rdns.Substring(0,[math]::Min(45,$rdns.Length)), $procStr, $flag)
    }
}

# =============================================================================
Write-Head "5 / 5  — SUSPICIOUS INDICATORS SUMMARY"
Write-Log ""

# ── 5a: Processes running from suspicious paths ──────────────────────────────
Write-Log "  [5a] Processes running from suspicious paths (Temp/AppData/Downloads):" "Cyan"
$suspPaths = @('\\Temp\\','\\tmp\\','\\AppData\\Local\\Temp\\','\\Downloads\\','\\Public\\','%TEMP%')
$suspProcs = Get-CimInstance Win32_Process |
    Where-Object {
        $ep = $_.ExecutablePath
        $ep -and ($suspPaths | Where-Object { $ep -like "*$_*" })
    }

if ($suspProcs) {
    $suspProcs | ForEach-Object {
        Write-Log ("  ALERT  PID:{0}  {1}`n         Path: {2}" -f $_.ProcessId, $_.Name, $_.ExecutablePath) "Red"
    }
    $Alerts += $suspProcs.Count
} else {
    Write-Log "  None detected." "Green"
}
Write-Log ""

# ── 5b: Listening ports ───────────────────────────────────────────────────────
Write-Log "  [5b] Listening ports (potential backdoors):" "Cyan"
$knownPorts  = @(80,443,135,139,445,3389,22,53,88,389,636,3306,5432,8080,8443,25,587,993,995,631,5985,5986)
$listenPorts = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue
Write-Log ("  Total listening: {0}" -f $listenPorts.Count)

$unusualListen = $listenPorts | Where-Object { $_.LocalPort -notin $knownPorts -and $_.LocalPort -gt 1024 }
if ($unusualListen) {
    Write-Log "  Uncommon listening ports — investigate:" "Red"
    $unusualListen | ForEach-Object {
        $pname = if ($pidMap.ContainsKey($_.OwningProcess)) { $pidMap[$_.OwningProcess] } else { "?" }
        Write-Log ("  ALERT  Port:{0,-7} PID:{1}  Process:{2}" -f $_.LocalPort, $_.OwningProcess, $pname) "Red"
    }
    $Alerts += $unusualListen.Count
} else {
    Write-Log "  No obviously unusual listening ports." "Green"
}
Write-Log ""

# ── 5c: Processes with high outbound connection counts ───────────────────────
Write-Log "  [5c] Processes with 5+ simultaneous outbound connections:" "Cyan"
$outboundGroups = $connections |
    Where-Object { $_.RemoteAddress -and $_.RemoteAddress -ne '0.0.0.0' } |
    Group-Object OwningProcess |
    Where-Object { $_.Count -ge 5 } |
    Sort-Object Count -Descending

if ($outboundGroups) {
    $outboundGroups | ForEach-Object {
        $pname = if ($pidMap.ContainsKey([int]$_.Name)) { $pidMap[[int]$_.Name] } else { "?" }
        Write-Log ("  ALERT  {0} connections — PID:{1}  Process:{2}" -f $_.Count, $_.Name, $pname) "Red"
        $Alerts++
    }
} else {
    Write-Log "  None detected." "Green"
}
Write-Log ""

# ── 5d: Recently modified executables in system dirs ─────────────────────────
Write-Log "  [5d] Executables modified in the last 48h in System32/SysWOW64:" "Cyan"
$recentExes = Get-ChildItem -Path "$env:SystemRoot\System32","$env:SystemRoot\SysWOW64" `
    -Filter *.exe -ErrorAction SilentlyContinue |
    Where-Object { $_.LastWriteTime -gt (Get-Date).AddHours(-48) }

if ($recentExes) {
    $recentExes | ForEach-Object {
        Write-Log ("  ALERT  {0}  Modified:{1}" -f $_.FullName, $_.LastWriteTime) "Red"
        $Alerts++
    }
} else {
    Write-Log "  None detected." "Green"
}
Write-Log ""

# ── 5e: Scheduled tasks (persistence check) ──────────────────────────────────
Write-Log "  [5e] Non-Microsoft scheduled tasks (persistence check):" "Cyan"
try {
    $tasks = Get-ScheduledTask -ErrorAction Stop |
        Where-Object { $_.TaskPath -notmatch 'Microsoft' -and $_.State -ne 'Disabled' }
    if ($tasks) {
        $tasks | ForEach-Object {
            $action = ($_.Actions | Select-Object -First 1).Execute
            Write-Log ("  Task: {0,-40} Action: {1}" -f ($_.TaskPath+$_.TaskName), $action)
        }
    } else {
        Write-Log "  No non-Microsoft tasks found." "Green"
    }
} catch {
    Write-Log "  (Could not enumerate scheduled tasks)" "DarkGray"
}
Write-Log ""

# ── 5f: Startup entries ───────────────────────────────────────────────────────
Write-Log "  [5f] Registry Run keys (startup persistence):" "Cyan"
$runKeys = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
)
foreach ($key in $runKeys) {
    try {
        $entries = Get-ItemProperty -Path $key -ErrorAction Stop
        $entries.PSObject.Properties |
            Where-Object { $_.Name -notmatch '^PS' } |
            ForEach-Object { Write-Log ("  [{0}]  {1} = {2}" -f $key.Split('\')[-2..-1]-join'\', $_.Name, $_.Value) }
    } catch {}
}
Write-Log ""

# ── 5g: Recently installed software ──────────────────────────────────────────
Write-Log "  [5g] Software installed/modified in the last 7 days:" "Cyan"
$recentSW = Get-ItemProperty `
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*' `
    -ErrorAction SilentlyContinue |
    Where-Object {
        if (-not $_.InstallDate) { return $false }
        $parsed = [datetime]::MinValue
        $ok = [datetime]::TryParseExact(
            $_.InstallDate,
            'yyyyMMdd',
            [System.Globalization.CultureInfo]::InvariantCulture,
            [System.Globalization.DateTimeStyles]::None,
            [ref]$parsed
        )
        $ok -and $parsed -gt (Get-Date).AddDays(-7)
    } |
    Select-Object DisplayName, InstallDate, Publisher

if ($recentSW) {
    $recentSW | ForEach-Object {
        Write-Log ("  {0,-45} Installed:{1}  By:{2}" -f $_.DisplayName, $_.InstallDate, $_.Publisher)
    }
} else {
    Write-Log "  None detected in the past 7 days." "Green"
}
Write-Log ""

# ── Final score ───────────────────────────────────────────────────────────────
Write-Sep
if ($Alerts -eq 0) {
    Write-Log "  ✔  No automatic alerts triggered. Review Section 4 IPs manually." "Green"
} else {
    Write-Log "  ⚠  $Alerts alert(s) triggered — review highlighted sections above." "Red"
}
Write-Sep
Write-Log ""
Write-Log "  Full report saved to: $((Resolve-Path $ReportFile).Path)" "Cyan"
Write-Log ""
