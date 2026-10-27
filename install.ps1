<#
Demonstrator - Device Trust Manager installer for Windows 11, Windows Server 2022 and 2025 (x64, Desktop
Experience). The demonstrator is the same Linux stack as on Ubuntu: it runs in its own WSL 2 distro
("dtm-demonstrator"), set up by install.sh. Windows only adds the glue - port proxy and firewall for the
LAN, and a scheduled task that starts the distro at boot and keeps it running.
Re-running it updates the installation in place (data and secrets stay in the distro).

  In an elevated PowerShell:
  irm https://github.com/danielstroehmann/dc-dtm-demonstrator/releases/latest/download/install.ps1 | iex
  & ([scriptblock]::Create((irm <same URL>))) -Version v0.4.0     a specific release
  & ([scriptblock]::Create((irm <same URL>))) -Branch dev         the preview image of a branch
  & ([scriptblock]::Create((irm <same URL>))) -Uninstall          remove it (asks before deleting data)
#>
[CmdletBinding()]
param(
    [string]$Version = "",
    [string]$Branch = "",
    [switch]$Uninstall,
    [switch]$Yes
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"  # Windows PowerShell 5.1's progress bar slows downloads to a crawl
Set-StrictMode -Version 3.0

$Repo = "danielstroehmann/dc-dtm-demonstrator"
$Distro = "dtm-demonstrator"
$TaskName = "Demonstrator - Device Trust Manager"
$FirewallGroup = "Demonstrator - Device Trust Manager"
$Ports = @(443, 80)
$DistroImages = @("Ubuntu-26.04", "Ubuntu-24.04")  # preferred first
# Program Files, not ProgramData: a user can create folders in ProgramData and would own the script the
# elevated start task runs.
$DataRoot = Join-Path $env:ProgramFiles "dtm-demonstrator"
$MinWslVersion = [version]"2.4.4"  # `wsl --install <distro> --name`
$env:WSL_UTF8 = "1"  # wsl.exe answers in UTF-8 instead of UTF-16

function Write-Step([string]$Message) { Write-Host "==> $Message" }
function Stop-Install([string]$Message) { throw "ERROR: $Message" }

# --- pure helpers (unit-tested with Pester) ---------------------------------------------------------

function Test-SupportedWindows([int]$Build, [string]$ProductType, [int]$Revision) {
    # ProductType 1 = workstation; Win 11 22H2 = 22621. Server 2025 = 26100; Server 2022 = 20348, with WSL 2
    # from KB5014678 (20348.768) on.
    if ($ProductType -eq "1") { return $Build -ge 22621 }
    if ($Build -eq 20348) { return $Revision -ge 768 }
    return $Build -ge 26100
}

function Test-WslVersion([string]$VersionOutput) {
    # `wsl --version`: "WSL version: 2.4.13.0" (UTF-8 with WSL_UTF8); the inbox wsl.exe has no --version.
    if ($VersionOutput -match '(\d+\.\d+\.\d+)') { return [version]$Matches[1] -ge $MinWslVersion }
    return $false
}

function Get-InstallerUrl([string]$Version, [string]$Branch) {
    if ($Version -and $Branch) { Stop-Install "use either -Version or -Branch" }
    if ($Version) {
        if ($Version -notmatch '^v\d+\.\d+\.\d+$') { Stop-Install "invalid version: $Version" }
        return "https://github.com/$Repo/releases/download/$Version/install.sh"
    }
    if ($Branch) {
        if ($Branch -notmatch '^[A-Za-z0-9._/-]+$' -or $Branch.Contains("..")) { Stop-Install "invalid branch: $Branch" }
        return "https://raw.githubusercontent.com/$Repo/$Branch/install.sh"
    }
    return "https://github.com/$Repo/releases/latest/download/install.sh"
}

function Get-InstallerArgumentList([string]$Version, [string]$Branch, [string[]]$HostNames, [bool]$AssumeYes) {
    $installerArgs = @()
    if ($Version) { $installerArgs += @("--version", $Version) }
    if ($Branch) { $installerArgs += @("--branch", $Branch) }
    foreach ($h in $HostNames) { $installerArgs += @("--host", $h) }
    if ($AssumeYes) { $installerArgs += "--yes" }
    return $installerArgs
}

function Select-LanAddress([object[]]$Addresses, [int[]]$GatewayInterfaces = @()) {
    # The IPv4 addresses the LAN reaches this machine by - not loopback, link-local or virtual switches
    # (WSL, Hyper-V's Default Switch); with a default gateway somewhere, only those adapters.
    $candidates = @($Addresses | Where-Object {
            $_.IPAddress -notmatch '^(127\.|169\.254\.)' -and $_.InterfaceAlias -notmatch 'WSL|Loopback|Default Switch'
        })
    $routed = @($candidates | Where-Object { $GatewayInterfaces -contains $_.InterfaceIndex })
    if ($routed.Count -gt 0) { $candidates = $routed }
    return @($candidates | ForEach-Object { $_.IPAddress } | Sort-Object -Unique)
}

function Get-LanAddress {
    $gateways = @(Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway } | ForEach-Object { $_.InterfaceIndex })
    return Select-LanAddress (Get-NetIPAddress -AddressFamily IPv4 -AddressState Preferred) $gateways
}

function Get-HostName([string]$ComputerName, [string]$Domain, [bool]$PartOfDomain) {
    # The certificate covers the plain name and, in a domain, the FQDN; install.sh accepts [A-Za-z0-9.-].
    $names = @($ComputerName.ToLowerInvariant())
    if ($PartOfDomain -and $Domain) { $names += "$($ComputerName).$($Domain)".ToLowerInvariant() }
    return $names
}

function Get-PortProxyCommand([string[]]$ListenAddresses, [int[]]$PortList, [string]$Target) {
    # netsh arguments that point every LAN address's ports at the distro. Per address, not 0.0.0.0:
    # WSL itself forwards localhost, and a wildcard listener would collide with that.
    $commands = @()
    foreach ($address in $ListenAddresses) {
        foreach ($port in $PortList) {
            $commands += ,@("interface", "portproxy", "add", "v4tov4", "listenport=$port", "listenaddress=$address",
                "connectport=$port", "connectaddress=$Target")
        }
    }
    return , $commands  # one element must stay an array of commands
}

function Select-OwnPortProxy([string]$NetshOutput, [int[]]$PortList) {
    # Our entries in `netsh interface portproxy show v4tov4`: one of our ports forwarded to the same port.
    $own = @()
    foreach ($line in $NetshOutput -split "`r?`n") {
        if ($line -match '^\s*(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s*$' -and
            $PortList -contains [int]$Matches[2] -and $Matches[2] -eq $Matches[4]) {
            $own += [pscustomobject]@{ Address = $Matches[1]; Port = [int]$Matches[2] }
        }
    }
    return $own
}

function Test-PortProxyCurrent([string]$NetshOutput, [string[]]$ListenAddresses, [int[]]$PortList, [string]$Target) {
    # True when exactly the wanted forwardings exist (every LAN address and port to the distro, nothing else of ours).
    $have = @(foreach ($line in $NetshOutput -split "`r?`n") {
            if ($line -match '^\s*(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s*$' -and
                $PortList -contains [int]$Matches[2] -and $Matches[2] -eq $Matches[4]) { "$($Matches[1]):$($Matches[2])>$($Matches[3])" }
        }) | Sort-Object
    $want = @(foreach ($a in $ListenAddresses) { foreach ($p in $PortList) { "${a}:$p>$Target" } }) | Sort-Object
    return (@($have) -join ",") -eq (@($want) -join ",")
}

function ConvertTo-BashWord([string]$Value) {
    if ($Value -notmatch '^[A-Za-z0-9._/:=-]+$') { Stop-Install "unexpected character in '$Value'" }
    return $Value
}

# --- system steps -------------------------------------------------------------------------------------

function Assert-Admin {
    $principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Stop-Install "run this in an elevated PowerShell (Run as administrator)"
    }
}

function Assert-Prerequisite {
    Assert-Admin
    if (-not [Environment]::Is64BitOperatingSystem -or $env:PROCESSOR_ARCHITECTURE -ne "AMD64") {
        Stop-Install "x64 Windows is required"
    }
    $os = Get-CimInstance Win32_OperatingSystem
    $revision = [int](Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").UBR
    if (-not (Test-SupportedWindows ([int]$os.BuildNumber) ([string]$os.ProductType) $revision)) {
        Stop-Install ("Windows 11 22H2+, Windows Server 2022 (with the June 2022 update or later) or 2025 is required " +
            "(found $($os.Caption), build $($os.BuildNumber).$revision)")
    }
    # Best effort: inside a VM HypervisorPresent is always true - a missing nested virtualisation only shows
    # when WSL starts its VM (see $NestedHint).
    $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
    $hypervisor = (Get-CimInstance Win32_ComputerSystem).HypervisorPresent
    if (-not $hypervisor -and -not $cpu.VirtualizationFirmwareEnabled) {
        Stop-Install "virtualisation is not available - enable it in the firmware (VT-x / AMD-V)"
    }
}

$NestedHint = ("WSL could not start its VM. In a virtual machine, enable nested virtualisation on the host " +
    "(Hyper-V: Set-VMProcessor -VMName <vm> -ExposeVirtualizationExtensions `$true; VMware: 'Expose hardware " +
    "assisted virtualization'; KVM/Proxmox: CPU type 'host' and nested enabled in kvm_intel/kvm_amd), " +
    "then run the installer again.")

function Invoke-Native([string]$File, [string[]]$Arguments) {
    # Output and exit code of a native command. PowerShell 5.1 with ErrorActionPreference Stop turns stderr
    # lines into terminating errors - so collect them as text instead.
    $ErrorActionPreference = "Continue"
    $out = & $File @Arguments 2>&1 | ForEach-Object { "$_" }
    return [pscustomobject]@{ Code = $LASTEXITCODE; Text = (($out -join "`n") -replace "`0", "") }
}

function Install-Wsl {
    $features = "Microsoft-Windows-Subsystem-Linux", "VirtualMachinePlatform"
    $missing = @($features | Where-Object { (Get-WindowsOptionalFeature -Online -FeatureName $_).State -ne "Enabled" })
    if ($missing.Count -gt 0) {
        Write-Step "Enabling WSL ($($missing -join ', '))"
        foreach ($f in $missing) { Enable-WindowsOptionalFeature -Online -FeatureName $f -All -NoRestart | Out-Null }
        Register-Continuation
        Write-Host ""
        Write-Host "Windows must restart to finish enabling WSL. The installation continues after the next logon."
        if ($Yes -or (Read-Host "Restart now? [Y/n]") -notmatch '^[nN]') { Restart-Computer -Force }
        return $false  # not `exit`: under `irm | iex` it would close the admin's PowerShell
    }
    if (-not (Test-WslVersion (Invoke-Native "wsl.exe" @("--version")).Text)) { Install-WslPackage }
    $null = Invoke-Native "wsl.exe" @("--set-default-version", "2")
    return $true
}

function Install-WslPackage {
    # The inbox wsl.exe of a fresh Server only says "not installed" - even to `wsl --install` and `--update`
    # (verified on Server 2025, 2026-10-27). Microsoft's MSI from the WSL GitHub release installs it without the Store.
    Write-Step "Installing WSL (Microsoft's MSI package)"
    $release = Invoke-RestMethod "https://api.github.com/repos/microsoft/WSL/releases/latest"
    $asset = $release.assets | Where-Object { $_.name -match '\.x64\.msi$' } | Select-Object -First 1
    if (-not $asset) { Stop-Install "no x64 MSI in the WSL release $($release.tag_name)" }
    $msi = Join-Path $env:TEMP $asset.name
    try {
        Invoke-WebRequest $asset.browser_download_url -OutFile $msi -UseBasicParsing
        $signature = Get-AuthenticodeSignature $msi
        if ($signature.Status -ne "Valid" -or $signature.SignerCertificate.Subject -notmatch '^CN=Microsoft Corporation,') {
            Stop-Install "the WSL package is not signed by Microsoft ($($signature.Status)) - not installed"
        }
        $process = Start-Process msiexec.exe -ArgumentList "/i `"$msi`" /qn /norestart" -Wait -PassThru
        if ($process.ExitCode -notin 0, 3010) { Stop-Install "the WSL package did not install (msiexec $($process.ExitCode))" }
    } finally {
        Remove-Item $msi -Force -ErrorAction SilentlyContinue  # also after a failed or cut-off download
    }
    $wslVersion = Invoke-Native "wsl.exe" @("--version")
    if (-not (Test-WslVersion $wslVersion.Text)) {
        Stop-Install "WSL $MinWslVersion or newer is needed (wsl --version: $($wslVersion.Text))"
    }
}

function Save-Self {
    # A copy of this script for the restart continuation and the start task (under `irm | iex` there is no file).
    New-Item -ItemType Directory -Force -Path $DataRoot | Out-Null
    $self = Join-Path $DataRoot "install.ps1"
    if ($PSCommandPath -and (Resolve-Path $PSCommandPath).Path -ne $self) { Copy-Item $PSCommandPath $self -Force }
    elseif (-not $PSCommandPath) {
        Invoke-RestMethod ((Get-InstallerUrl $Version $Branch) -replace 'install\.sh$', 'install.ps1') -OutFile $self
    }
    return $self
}

function Register-Continuation {
    # After the restart: the same installation again, with the same choices (RunOnce runs at the next logon of an admin).
    $self = Save-Self
    $continue = "-NoExit -ExecutionPolicy Bypass -File `"$self`""
    if ($Version) { $continue += " -Version $Version" }
    if ($Branch) { $continue += " -Branch $Branch" }
    # The interactive questions (password) stay: the continuation opens a console window.
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" -Name "DtmDemonstratorInstall" `
        -Value "powershell.exe $continue"
}

function Test-Distro {
    # The registered distros of this account (no parsing of wsl.exe, which errors when there are none).
    $names = Get-ChildItem "HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss" -ErrorAction SilentlyContinue |
        ForEach-Object { (Get-ItemProperty $_.PSPath).DistributionName }
    return [bool](@($names) -contains $Distro)
}

function Install-Distro {
    if (Test-Distro) { return }
    $online = (Invoke-Native "wsl.exe" @("--list", "--online")).Text
    $image = $DistroImages | Where-Object { $online -match "(?m)^\s*$([regex]::Escape($_))\s" } | Select-Object -First 1
    if (-not $image) { Stop-Install "no Ubuntu WSL image available (looked for $($DistroImages -join ', '))" }
    Write-Step "Installing the WSL distro $Distro ($image)"
    $install = Invoke-Native "wsl.exe" @("--install", $image, "--name", $Distro, "--no-launch")
    if ($install.Code -ne 0) {
        if ($install.Text -match '80370102|HCS_E_HYPERV_NOT_INSTALLED|virtualization') { Stop-Install $NestedHint }
        Stop-Install "wsl --install failed: $($install.Text)"
    }
    # systemd runs Docker and the demonstrator's unit, as on Ubuntu Server. No Windows drives and no
    # Windows programs inside: the start task runs elevated, and root in the distro must not reach C:.
    Invoke-Distro ("printf '[boot]\nsystemd=true\n[user]\ndefault=root\n[automount]\nenabled=false\n" +
        "[interop]\nenabled=false\nappendWindowsPath=false\n' > /etc/wsl.conf")
    $null = Invoke-Native "wsl.exe" @("--terminate", $Distro)
}

function Invoke-Distro([string]$Command) {
    # --exec: parsed once by bash -c. The console stays attached (install.sh asks for the password on
    # /dev/tty) - never capture this output. $Command must not contain double quotes.
    if ($Command.Contains('"')) { Stop-Install "internal: double quote in a distro command" }
    & wsl.exe -d $Distro -u root --exec bash -c $Command
    if ($LASTEXITCODE -ne 0) { Stop-Install "command in $Distro failed ($LASTEXITCODE)" }
}

function Get-MachineName {
    # The DNS host name (the NetBIOS name in COMPUTERNAME is cut at 15 characters).
    $system = Get-CimInstance Win32_ComputerSystem
    return Get-HostName $system.DNSHostName $system.Domain $system.PartOfDomain
}

function Install-Demonstrator {
    $url = ConvertTo-BashWord (Get-InstallerUrl $Version $Branch)
    $hostNames = @(Get-MachineName) + @(Get-LanAddress)
    $installerArgs = (Get-InstallerArgumentList $Version $Branch $hostNames $Yes.IsPresent | ForEach-Object { ConvertTo-BashWord $_ }) -join " "
    Write-Step "Running install.sh in $Distro"
    # The script asks for the login password itself (the console is passed through).
    Invoke-Distro "set -o pipefail; curl -fsSL '$url' | bash -s -- $installerArgs"
}

function Update-PortProxy {
    # The distro's NAT address changes with every start: point the LAN addresses' ports at the current one.
    $ip = $null
    foreach ($i in 1..30) {
        $out = (Invoke-Native "wsl.exe" @("-d", $Distro, "-u", "root", "--exec", "ip", "-4", "-o", "addr", "show", "dev", "eth0")).Text
        if ($out -match 'inet (\d+\.\d+\.\d+\.\d+)/') { $ip = $Matches[1]; break }
        Start-Sleep 2
    }
    if (-not $ip) { Write-Warning "the distro has no address yet - the LAN cannot reach it"; return }
    $current = (& netsh interface portproxy show v4tov4) -join "`n"
    $lan = @(Get-LanAddress)
    if (Test-PortProxyCurrent $current $lan $Ports $ip) { return }  # unchanged: no reconnects every 5 minutes
    foreach ($entry in Select-OwnPortProxy $current $Ports) {
        & netsh interface portproxy delete v4tov4 "listenport=$($entry.Port)" "listenaddress=$($entry.Address)" | Out-Null
    }
    $wanted = Get-PortProxyCommand $lan $Ports $ip  # assigned first: the function returns , $commands
    foreach ($command in $wanted) { & netsh @command | Out-Null }
}

function Start-Demonstrator {
    # Run by the start task at boot: keeps the distro running (WSL stops an idle one, Docker with it) and,
    # every 5 minutes, points the port proxy at it again - a WSL update or restart and a new DHCP lease
    # change the addresses.
    while ($true) {
        Update-PortProxy
        $null = Invoke-Native "wsl.exe" @("-d", $Distro, "-u", "root", "--exec", "sleep", "300")
    }
}

function Install-StartTask {
    # At boot without a logon (S4U) as the installing admin - the distro belongs to that account.
    $self = Save-Self
    $action = New-ScheduledTaskAction -Execute "powershell.exe" `
        -Argument "-NoProfile -ExecutionPolicy Bypass -Command `". '$self'; Start-Demonstrator`""
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId ([Security.Principal.WindowsIdentity]::GetCurrent().Name) -LogonType S4U -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 `
        -RestartInterval (New-TimeSpan -Minutes 1) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -MultipleInstances IgnoreNew
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal `
        -Settings $settings -Force | Out-Null
    Write-Step "Starting the demonstrator task"
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Start-ScheduledTask -TaskName $TaskName
}

$WslVmCreatorId = "{40E0AC32-46A5-438A-A0B2-2B479E8F2E90}"  # WSL's id in the Hyper-V firewall

function Install-Firewall {
    # Defender Firewall is on in every profile of a fresh Windows: open the ports for the port proxy (IP
    # Helper service). Domain and private networks: any client (routed subnets, VPN); a network Windows
    # classified as public (common on a fresh workgroup machine): the local subnet only.
    Set-Service iphlpsvc -StartupType Automatic
    Start-Service iphlpsvc
    Get-NetFirewallRule -Group $FirewallGroup -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    New-NetFirewallRule -DisplayName "$FirewallGroup (HTTPS/HTTP)" -Group $FirewallGroup -Direction Inbound `
        -Protocol TCP -LocalPort $Ports -Action Allow -Profile Domain, Private | Out-Null
    New-NetFirewallRule -DisplayName "$FirewallGroup (HTTPS/HTTP, public network: local subnet)" -Group $FirewallGroup `
        -Direction Inbound -Protocol TCP -LocalPort $Ports -RemoteAddress LocalSubnet -Action Allow -Profile Public | Out-Null
    # Windows 11 22H2+ and Server 2025 also filter traffic into the WSL VM (Hyper-V firewall, WSL 2.0+).
    if (Get-Command New-NetFirewallHyperVRule -ErrorAction SilentlyContinue) {
        Get-NetFirewallHyperVRule -Name "DtmDemonstrator-*" -ErrorAction SilentlyContinue | Remove-NetFirewallHyperVRule
        foreach ($port in $Ports) {
            New-NetFirewallHyperVRule -Name "DtmDemonstrator-$port" -DisplayName "$FirewallGroup (TCP $port)" `
                -Direction Inbound -VMCreatorId $WslVmCreatorId -Protocol TCP -LocalPorts $port -Action Allow | Out-Null
        }
    }
}

function Test-Running([string[]]$HostNames) {
    # The app answers through the proxy in the distro (WSL forwards localhost) and the start task runs.
    foreach ($i in 1..30) {
        # Caddy serves the configured names only (SNI) - ask for this machine's name, connect to localhost.
        $health = Invoke-Native "curl.exe" @("-fsk", "--max-time", "5", "--resolve", "$($HostNames[0]):443:127.0.0.1",
            "https://$($HostNames[0])/healthz")
        $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        if ($health.Code -eq 0 -and $task -and $task.State -eq "Running") { return $true }
        Start-Sleep 2
    }
    return $false
}

function Uninstall-Demonstrator {
    Write-Step "Removing the start task, port proxy and firewall rules"
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    foreach ($entry in Select-OwnPortProxy ((& netsh interface portproxy show v4tov4) -join "`n") $Ports) {
        & netsh interface portproxy delete v4tov4 "listenport=$($entry.Port)" "listenaddress=$($entry.Address)" | Out-Null
    }
    Get-NetFirewallRule -Group $FirewallGroup -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    if (Get-Command Remove-NetFirewallHyperVRule -ErrorAction SilentlyContinue) {
        Get-NetFirewallHyperVRule -Name "DtmDemonstrator-*" -ErrorAction SilentlyContinue | Remove-NetFirewallHyperVRule
    }
    if (Test-Distro) {
        $answer = if ($Yes) { "y" } else { Read-Host "Delete the WSL distro $Distro with all demonstrator data? [y/N]" }
        if ($answer -match '^[yY]') {
            & wsl.exe --unregister $Distro | Out-Null
            Write-Step "Distro $Distro deleted"
        } else {
            # Stop the stack inside too, or it would come back with the next start of the distro.
            # The unit has no ExecStop (Docker's restart policy restarts the stack): stop the containers, too.
            $stop = Invoke-Native "wsl.exe" @("-d", $Distro, "-u", "root", "--exec", "bash", "-c",
                "systemctl disable --now dtm-demonstrator; docker compose -p dtm-demonstrator stop")
            if ($stop.Code -ne 0) { Write-Warning "could not stop the demonstrator in $Distro`: $($stop.Text)" }
            $null = Invoke-Native "wsl.exe" @("--terminate", $Distro)
            Write-Step "Distro $Distro kept with its data (start the installer again to use it)"
        }
    }
    Remove-Item (Join-Path $DataRoot "install.ps1") -Force -ErrorAction SilentlyContinue
    if ((Test-Path $DataRoot) -and -not (Get-ChildItem $DataRoot -Force)) { [IO.Directory]::Delete($DataRoot) }  # never recurse
}

function Invoke-Main {
    if ($Uninstall) { Assert-Admin; Uninstall-Demonstrator; return }
    Assert-Prerequisite
    # A continuation that is still pending (restart declined, installer started again) must not run twice.
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" -Name "DtmDemonstratorInstall" -ErrorAction SilentlyContinue
    $null = Get-InstallerUrl $Version $Branch  # validates the choice before anything changes
    if (-not (Install-Wsl)) { return }  # restarting first
    Install-Distro
    Install-Demonstrator
    Install-Firewall
    Install-StartTask
    Write-Host ""
    $names = @(Get-MachineName)
    if (-not (Test-Running $names)) {
        Stop-Install "installed, but the demonstrator does not answer on https://$($names[0])/ - see the start task in the Task Scheduler"
    }
    Write-Host "Done. Open https://$($names[0])/ from this or another machine on the LAN."
}

# Dot-sourced by the Pester tests and the start task: only the functions, no installation.
if ($MyInvocation.InvocationName -ne ".") {
    if (-not $Version -and -not $Branch -and -not $Uninstall) {
        # "latest" once, so install.sh, the saved copy and the continuation are the same release.
        try { $Version = (Invoke-RestMethod "https://api.github.com/repos/$Repo/releases/latest").tag_name }
        catch { throw "ERROR: could not look up the latest release on GitHub ($($_.Exception.Message)) - pass -Version vX.Y.Z" }
    }
    Invoke-Main
}
