# Pester 5+ unit tests for install.ps1 (the Windows installer). Dot-sourcing the script defines its functions
# only; every system command a tested function touches is mocked. On Linux pwsh the Windows-only cmdlets do
# not exist, so they get stubs first (Mock needs a command to replace). wsl.exe, netsh, curl.exe, msiexec.exe,
# Restart-Computer and the network/process cmdlets (Invoke-RestMethod, Invoke-WebRequest, Start-Process,
# Get-AuthenticodeSignature) are always shadowed by global functions - a global function wins over a cmdlet or
# an executable - so no test can reach the network or the real commands on a CI runner. The cmdlet shadows
# throw unless a test mocks them.

BeforeAll {
    if (-not $env:ProgramFiles) { $env:ProgramFiles = [IO.Path]::GetTempPath() }  # Linux pwsh
    $script:Installer = Join-Path $PSScriptRoot "../../install.ps1"

    function global:wsl.exe { $global:LASTEXITCODE = 0 }
    function global:netsh { $global:LASTEXITCODE = 0 }
    function global:curl.exe { $global:LASTEXITCODE = 0 }
    function global:Restart-Computer { param([switch]$Force) }
    function global:msiexec.exe { throw "test isolation: msiexec.exe must not run" }
    $script:Shadows = @{
        "Invoke-RestMethod"         = { param($Uri, $OutFile) throw "test isolation: no network ($Uri)" }
        "Invoke-WebRequest"         = { param($Uri, $OutFile, [switch]$UseBasicParsing) throw "test isolation: no network ($Uri)" }
        "Start-Process"             = { param($FilePath, $ArgumentList, [switch]$Wait, [switch]$PassThru) throw "test isolation: no process ($FilePath)" }
        "Get-AuthenticodeSignature" = { param($FilePath) throw "test isolation: no signature check ($FilePath)" }
    }
    foreach ($name in $script:Shadows.Keys) { Set-Item "function:global:$name" $script:Shadows[$name] }
    $stubs = @{
        "Get-CimInstance"               = { param($ClassName) }
        "Get-NetIPAddress"              = { param($AddressFamily, $AddressState) }
        "Get-NetIPConfiguration"        = { param() }
        "Get-WindowsOptionalFeature"    = { param([switch]$Online, $FeatureName) }
        "Enable-WindowsOptionalFeature" = { param([switch]$Online, $FeatureName, [switch]$All, [switch]$NoRestart) }
        "Unregister-ScheduledTask"      = { param($TaskName, $Confirm, $ErrorAction) }
        "Get-ScheduledTask"             = { param($TaskName, $ErrorAction) }
        "Get-NetFirewallRule"           = { param($Group, $ErrorAction) }
        "Remove-NetFirewallRule"        = { param([Parameter(ValueFromPipeline)]$InputObject) }
    }
    $script:CreatedStubs = @()
    foreach ($name in $stubs.Keys) {
        if (-not (Get-Command $name -ErrorAction SilentlyContinue)) {
            Set-Item "function:global:$name" $stubs[$name]
            $script:CreatedStubs += $name
        }
    }

    . $script:Installer

    # `netsh interface portproxy show v4tov4`, as Windows prints it (CRLF, blank and header lines).
    $script:NetshOutput = @"

Listen on ipv4:             Connect to ipv4:

Address         Port        Address         Port
--------------- ----------  --------------- ----------
192.168.1.20    443         172.28.240.2    443
192.168.1.20    80          172.28.240.2    80
10.0.0.7        443         172.28.240.2    443
0.0.0.0         8080        127.0.0.1       3000
192.168.1.20    8443        172.28.240.2    443
192.168.1.20    80          172.28.240.2    8080

"@ -replace "`r?`n", "`r`n"

    function script:Address([string]$Ip, [string]$Alias, [int]$Index) {
        [pscustomobject]@{ IPAddress = $Ip; InterfaceAlias = $Alias; InterfaceIndex = $Index }
    }
}

AfterAll {
    foreach ($name in @("wsl.exe", "netsh", "curl.exe", "msiexec.exe", "Restart-Computer") + $script:Shadows.Keys + $script:CreatedStubs) {
        Remove-Item "function:global:$name" -ErrorAction SilentlyContinue
    }
}

Describe "script file" {
    It "is ASCII-only or carries a UTF-8 BOM (Windows PowerShell 5.1 reads BOM-less files as ANSI)" {
        $bytes = [IO.File]::ReadAllBytes($script:Installer)
        $hasBom = $bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF
        $nonAscii = @($bytes | Where-Object { $_ -gt 0x7F }).Count
        ($hasBom -or $nonAscii -eq 0) | Should -BeTrue -Because ("powershell.exe runs the saved copy (RunOnce, start task); " +
            "a UTF-8 en dash contains 0x93, which cp1252 decodes to a curly quote that ends a string")
    }

    It "parses without errors" {
        $errors = $null
        $null = [Management.Automation.Language.Parser]::ParseFile($script:Installer, [ref]$null, [ref]$errors)
        $errors | Should -BeNullOrEmpty
    }

    It "stops with a hint when the latest release cannot be looked up" {
        # Run, not dot-sourced. A global function always wins over the cmdlet, so nothing reaches GitHub and the
        # throw comes before Invoke-Main - no installation step can run on the test machine.
        function global:Invoke-RestMethod { throw "rate limit exceeded" }
        try {
            { & $script:Installer } | Should -Throw "ERROR: could not look up the latest release on GitHub (rate limit exceeded) - pass -Version vX.Y.Z"
        } finally {
            Set-Item function:global:Invoke-RestMethod $script:Shadows["Invoke-RestMethod"]  # back to the isolating shadow
        }
    }

    It "does not look up the latest release for -ResetPassword" {
        # The isolating shadow of Invoke-RestMethod throws "no network" if the lookup ran; without it the run stops
        # in Assert-Admin or Reset-Password (no distro on the test machine) - nothing is installed or reset.
        $thrown = $null
        try { & $script:Installer -ResetPassword } catch { $thrown = "$_" }
        $thrown | Should -Not -BeLike "*look up the latest release*"
        $thrown | Should -Not -BeLike "*test isolation: no network*"
    }

    It "defines the functions without installing when dot-sourced" {
        # Had the guard failed, BeforeAll would have run Invoke-Main and thrown in Assert-Prerequisite.
        Get-Command Invoke-Main -CommandType Function | Should -Not -BeNullOrEmpty
    }
}

Describe "Test-SupportedWindows" {
    It "accepts <Name>" -ForEach @(
        @{ Name = "Windows 11 22H2"; Build = 22621; Type = "1"; Rev = 0 }
        @{ Name = "Windows 11 24H2"; Build = 26100; Type = "1"; Rev = 0 }
        @{ Name = "Windows Server 2022 with KB5014678"; Build = 20348; Type = "3"; Rev = 768 }
        @{ Name = "Windows Server 2022 later update"; Build = 20348; Type = "3"; Rev = 2700 }
        @{ Name = "Windows Server 2022 domain controller"; Build = 20348; Type = "2"; Rev = 768 }
        @{ Name = "Windows Server 2025"; Build = 26100; Type = "3"; Rev = 0 }
    ) {
        Test-SupportedWindows $Build $Type $Rev | Should -BeTrue
    }

    It "rejects <Name>" -ForEach @(
        @{ Name = "Windows 10 22H2"; Build = 19045; Type = "1"; Rev = 5000 }
        @{ Name = "Windows 11 21H2"; Build = 22000; Type = "1"; Rev = 0 }
        @{ Name = "Windows Server 2022 before KB5014678"; Build = 20348; Type = "3"; Rev = 767 }
        @{ Name = "Windows Server 23H2 (between 2022 and 2025)"; Build = 25398; Type = "3"; Rev = 0 }
        @{ Name = "Windows Server 2019"; Build = 17763; Type = "3"; Rev = 5000 }
        @{ Name = "Windows Server 2016"; Build = 14393; Type = "3"; Rev = 5000 }
    ) {
        Test-SupportedWindows $Build $Type $Rev | Should -BeFalse
    }
}

Describe "Test-WslVersion" {
    It "accepts <Text>" -ForEach @(
        @{ Text = "WSL version: 2.4.4.0`nKernel version: 5.15.167.4-1" }
        @{ Text = "WSL-Version: 2.6.1.0`nKernelversion: 6.6.87.2-1" }
        @{ Text = "WSL version: 3.0.0.0" }
    ) {
        Test-WslVersion $Text | Should -BeTrue
    }

    It "rejects <Name>" -ForEach @(
        @{ Name = "an older WSL"; Text = "WSL version: 2.4.3.0`nKernel version: 5.15.167.4-1" }
        @{ Name = "WSL 1.x"; Text = "WSL version: 1.2.5.0" }
        @{ Name = "the inbox wsl.exe usage text"; Text = "Invalid command line option: --version`nUsage: wsl.exe [Argument]" }
        @{ Name = "empty output"; Text = "" }
        # The inbox stub of a fresh Server answers in UTF-16 (ignoring WSL_UTF8); Invoke-Native strips the NULs.
        @{ Name = "the inbox stub's 'not installed' text"; Text = (("Windows Subsystem for Linux is not installed. You can install by running 'wsl.exe --install'.`nFor more information please visit https://aka.ms/wslinstall".ToCharArray() | ForEach-Object { "$_`0" }) -join "") -replace "`0", "" }
    ) {
        Test-WslVersion $Text | Should -BeFalse
    }
}

Describe "Get-InstallerUrl" {
    It "points at the latest release by default" {
        Get-InstallerUrl "" "" |
            Should -Be "https://github.com/danielstroehmann/dc-dtm-demonstrator/releases/latest/download/install.sh"
    }

    It "points at a specific release" {
        Get-InstallerUrl "v0.4.0" "" |
            Should -Be "https://github.com/danielstroehmann/dc-dtm-demonstrator/releases/download/v0.4.0/install.sh"
    }

    It "points at a branch with a slash" {
        Get-InstallerUrl "" "feature/x.y" |
            Should -Be "https://raw.githubusercontent.com/danielstroehmann/dc-dtm-demonstrator/feature/x.y/install.sh"
    }

    It "points at a branch" {
        Get-InstallerUrl "" "dev" |
            Should -Be "https://raw.githubusercontent.com/danielstroehmann/dc-dtm-demonstrator/dev/install.sh"
    }

    It "rejects the invalid version '<Version>'" -ForEach @(
        @{ Version = "0.4.0" }, @{ Version = "v0.4" }, @{ Version = "v0.4.0-rc1" }, @{ Version = "v0.4.0; rm -rf /" }
        @{ Version = "latest" }
    ) {
        { Get-InstallerUrl $Version "" } | Should -Throw "*invalid version*"
    }

    It "rejects the invalid branch '<Branch>'" -ForEach @(
        @{ Branch = "dev main" }, @{ Branch = "dev;id" }, @{ Branch = "dev'" }, @{ Branch = '$(id)' }, @{ Branch = "dev?x=1" }
        @{ Branch = "../../other/repo/main" }, @{ Branch = "dev/../main" }
    ) {
        { Get-InstallerUrl "" $Branch } | Should -Throw "*invalid branch*"
    }

    It "refuses -Version together with -Branch" {
        { Get-InstallerUrl "v0.4.0" "dev" } | Should -Throw "*either -Version or -Branch*"
    }
}

Describe "Get-InstallerArgumentList" {
    It "passes nothing for a plain install" {
        @(Get-InstallerArgumentList "" "" @() $false) | Should -HaveCount 0
    }

    It "passes the version, every host and --yes in order" {
        Get-InstallerArgumentList "v0.4.0" "" @("pc1", "pc1.corp.example", "192.168.1.20") $true |
            Should -Be @("--version", "v0.4.0", "--host", "pc1", "--host", "pc1.corp.example", "--host", "192.168.1.20", "--yes")
    }

    It "passes the branch" {
        Get-InstallerArgumentList "" "dev" @("pc1") $false | Should -Be @("--branch", "dev", "--host", "pc1")
    }
}

Describe "Select-LanAddress" {
    BeforeAll {
        $script:Mixed = @(
            Address "192.168.1.20" "Ethernet" 4
            Address "127.0.0.1" "Loopback Pseudo-Interface 1" 1
            Address "169.254.10.3" "Ethernet 2" 7
            Address "172.28.240.1" "vEthernet (WSL (Hyper-V firewall))" 30
            Address "172.17.0.1" "vEthernet (WSL)" 31
            Address "172.20.0.1" "vEthernet (Default Switch)" 32
            Address "10.0.0.7" "Wi-Fi" 9
            Address "192.168.1.20" "Ethernet" 4
        )
    }

    It "drops loopback, link-local and virtual switches, sorted and deduplicated" {
        Select-LanAddress $script:Mixed @() | Should -Be @("10.0.0.7", "192.168.1.20")
    }

    It "prefers the adapters with a default gateway" {
        Select-LanAddress $script:Mixed @(4) | Should -Be @("192.168.1.20")
    }

    It "falls back to all candidates when the gateway sits on a dropped adapter" {
        Select-LanAddress $script:Mixed @(32) | Should -Be @("10.0.0.7", "192.168.1.20")
    }

    It "returns nothing when no address qualifies" {
        @(Select-LanAddress @(Address "127.0.0.1" "Loopback Pseudo-Interface 1" 1) @()) | Should -HaveCount 0
    }
}

Describe "Get-HostName" {
    It "lowercases the plain name outside a domain" {
        Get-HostName "DEMO-PC" "WORKGROUP" $false | Should -Be @("demo-pc")
    }

    It "ignores a custom workgroup name" {
        Get-HostName "DEMO-PC" "LAB" $false | Should -Be @("demo-pc")
    }

    It "adds the lowercased FQDN in a domain" {
        Get-HostName "DEMO-PC" "Corp.Example" $true | Should -Be @("demo-pc", "demo-pc.corp.example")
    }
}

Describe "Get-MachineName" {
    It "takes the DNS host name and the domain from Win32_ComputerSystem" {
        Mock Get-CimInstance { [pscustomobject]@{ DNSHostName = "Demonstrator-Lobby"; Domain = "Corp.Example"; PartOfDomain = $true } }
        Get-MachineName | Should -Be @("demonstrator-lobby", "demonstrator-lobby.corp.example")
        Should -Invoke Get-CimInstance -Times 1 -Exactly -ParameterFilter { $ClassName -eq "Win32_ComputerSystem" }
    }
}

Describe "ConvertTo-BashWord" {
    It "passes '<Value>' unchanged" -ForEach @(
        @{ Value = "https://github.com/danielstroehmann/dc-dtm-demonstrator/releases/latest/download/install.sh" }
        @{ Value = "--host" }, @{ Value = "demo-pc.corp.example" }, @{ Value = "192.168.1.20" }, @{ Value = "a=b" }
    ) {
        ConvertTo-BashWord $Value | Should -BeExactly $Value
    }

    It "rejects <Name>" -ForEach @(
        @{ Name = "a single quote"; Value = "x'y" }
        @{ Name = "a double quote"; Value = 'x"y' }
        @{ Name = "a space"; Value = "x y" }
        @{ Name = "a semicolon"; Value = "x;id" }
        @{ Name = "a dollar"; Value = '$(id)' }
        @{ Name = "a backtick"; Value = 'x`id`' }
        @{ Name = "a pipe"; Value = "x|id" }
        @{ Name = "an ampersand"; Value = "x&id" }
        @{ Name = "a newline"; Value = "x`nid" }
        @{ Name = "a redirect"; Value = "x>y" }
        @{ Name = "an empty value"; Value = "" }
    ) {
        { ConvertTo-BashWord $Value } | Should -Throw "*unexpected character*"
    }
}

Describe "Get-PortProxyCommand" {
    It "adds one forwarding per address and port to the same port of the distro" {
        $commands = Get-PortProxyCommand @("192.168.1.20", "10.0.0.7") @(443, 80) "172.28.240.2"
        $commands | Should -HaveCount 4
        $commands[0] | Should -Be @("interface", "portproxy", "add", "v4tov4", "listenport=443", "listenaddress=192.168.1.20",
            "connectport=443", "connectaddress=172.28.240.2")
        $commands[3] | Should -Be @("interface", "portproxy", "add", "v4tov4", "listenport=80", "listenaddress=10.0.0.7",
            "connectport=80", "connectaddress=172.28.240.2")
    }

    It "stays a list of commands for a single address and port" {
        # As Update-PortProxy uses it: assigned first (a foreach directly over the call would see one item).
        $wanted = Get-PortProxyCommand @("192.168.1.20") @(443) "172.28.240.2"
        $seen = @(foreach ($command in $wanted) { $command -join " " })
        $seen | Should -Be @("interface portproxy add v4tov4 listenport=443 listenaddress=192.168.1.20 connectport=443 connectaddress=172.28.240.2")
    }

    It "never listens on the wildcard address" {
        $commands = Get-PortProxyCommand @("192.168.1.20") @(443, 80) "172.28.240.2"
        ($commands | ForEach-Object { $_ -join " " }) | Should -Not -Match "0\.0\.0\.0"
    }

    It "adds nothing without a LAN address" {
        $wanted = Get-PortProxyCommand @() @(443, 80) "172.28.240.2"
        $seen = @(foreach ($command in $wanted) { $command })
        $seen | Should -HaveCount 0
    }
}

Describe "Select-OwnPortProxy" {
    It "finds our ports forwarded to the same port, ignoring headers and other entries" {
        $own = @(Select-OwnPortProxy $script:NetshOutput @(443, 80))
        ($own | ForEach-Object { "$($_.Address):$($_.Port)" }) | Should -Be @("192.168.1.20:443", "192.168.1.20:80", "10.0.0.7:443")
        $own[0].Port | Should -BeOfType [int]
    }

    It "finds nothing in an empty list" {
        @(Select-OwnPortProxy "" @(443, 80)) | Should -HaveCount 0
    }

    It "accepts LF-only output" {
        @(Select-OwnPortProxy ($script:NetshOutput -replace "`r", "") @(443, 80)) | Should -HaveCount 3
    }
}

Describe "Test-PortProxyCurrent" {
    BeforeAll {
        $script:Ours = @"
Address         Port        Address         Port
--------------- ----------  --------------- ----------
192.168.1.20    443         172.28.240.2    443
192.168.1.20    80          172.28.240.2    80
0.0.0.0         8080        127.0.0.1       3000
"@ -replace "`r?`n", "`r`n"
    }

    It "is true when exactly the wanted forwardings exist, in any order, ignoring foreign ones" {
        Test-PortProxyCurrent $script:Ours @("192.168.1.20") @(80, 443) "172.28.240.2" | Should -BeTrue
    }

    It "is false after the distro got a new address" {
        Test-PortProxyCurrent $script:Ours @("192.168.1.20") @(443, 80) "172.28.240.9" | Should -BeFalse
    }

    It "is false when a LAN address is missing" {
        Test-PortProxyCurrent $script:Ours @("10.0.0.7", "192.168.1.20") @(443, 80) "172.28.240.2" | Should -BeFalse
    }

    It "is false when a stale address of ours is left" {
        Test-PortProxyCurrent $script:NetshOutput @("192.168.1.20") @(443, 80) "172.28.240.2" | Should -BeFalse
    }

    It "is false when nothing is set up yet" {
        Test-PortProxyCurrent "" @("192.168.1.20") @(443, 80) "172.28.240.2" | Should -BeFalse
    }
}

Describe "Invoke-Native" {
    It "returns exit code and text with stderr lines and NULs removed" {
        Mock wsl.exe { "W`0S`0L`0"; Write-Error "on stderr"; $global:LASTEXITCODE = 5 }
        $result = Invoke-Native "wsl.exe" @("--version")
        $result.Code | Should -Be 5
        $result.Text | Should -Be "WSL`non stderr"
    }

    It "does not turn stderr into a terminating error under ErrorActionPreference Stop" {
        $ErrorActionPreference = "Stop"
        Mock wsl.exe { Write-Error "boom"; $global:LASTEXITCODE = 1 }
        { Invoke-Native "wsl.exe" @() } | Should -Not -Throw
    }
}

Describe "Install-Wsl" {
    BeforeEach {
        $Yes = [switch]$false
        Mock Enable-WindowsOptionalFeature {}
        Mock Register-Continuation {}
        Mock Restart-Computer {}
        Mock Write-Host {}
        Mock wsl.exe { $global:LASTEXITCODE = 0 }
        Mock wsl.exe { "WSL version: 2.4.13.0"; $global:LASTEXITCODE = 0 } -ParameterFilter { $args -contains "--version" }
    }

    It "enables missing features, registers the continuation and returns false" {
        Mock Get-WindowsOptionalFeature { [pscustomobject]@{ State = "Disabled" } } -ParameterFilter { $FeatureName -eq "VirtualMachinePlatform" }
        Mock Get-WindowsOptionalFeature { [pscustomobject]@{ State = "Enabled" } } -ParameterFilter { $FeatureName -eq "Microsoft-Windows-Subsystem-Linux" }
        Mock Read-Host { "n" }

        Install-Wsl | Should -BeFalse

        Should -Invoke Enable-WindowsOptionalFeature -Times 1 -Exactly -ParameterFilter { $FeatureName -eq "VirtualMachinePlatform" }
        Should -Invoke Register-Continuation -Times 1 -Exactly
        Should -Invoke Restart-Computer -Times 0 -Exactly
        Should -Invoke wsl.exe -Times 0 -Exactly
    }

    It "restarts when the admin accepts the default answer" {
        Mock Get-WindowsOptionalFeature { [pscustomobject]@{ State = "Disabled" } }
        Mock Read-Host { "" }

        Install-Wsl | Should -BeFalse

        Should -Invoke Enable-WindowsOptionalFeature -Times 2 -Exactly
        Should -Invoke Restart-Computer -Times 1 -Exactly
    }

    It "restarts without asking with -Yes" {
        $Yes = [switch]$true
        Mock Get-WindowsOptionalFeature { [pscustomobject]@{ State = "Disabled" } }
        Mock Read-Host { throw "must not ask" }

        Install-Wsl | Should -BeFalse
        Should -Invoke Restart-Computer -Times 1 -Exactly
    }

    It "treats a pending enable as missing" {
        Mock Get-WindowsOptionalFeature { [pscustomobject]@{ State = "EnablePending" } }
        Mock Read-Host { "n" }

        Install-Wsl | Should -BeFalse
        Should -Invoke Register-Continuation -Times 1 -Exactly
    }

    It "keeps a current WSL and sets version 2 as default when the features are enabled" {
        Mock Get-WindowsOptionalFeature { [pscustomobject]@{ State = "Enabled" } }
        Mock Install-WslPackage {}

        Install-Wsl | Should -BeTrue

        Should -Invoke Enable-WindowsOptionalFeature -Times 0 -Exactly
        Should -Invoke Register-Continuation -Times 0 -Exactly
        Should -Invoke Install-WslPackage -Times 0 -Exactly
        Should -Invoke wsl.exe -Times 0 -Exactly -ParameterFilter { $args -contains "--update" -or $args -contains "--install" }
        Should -Invoke wsl.exe -Times 1 -Exactly -ParameterFilter { ($args -join " ") -eq "--set-default-version 2" }
    }

    It "installs the WSL package when <Name>" -ForEach @(
        @{ Name = "only the inbox stub exists"; Text = "W`0i`0n`0d`0o`0w`0s`0 `0S`0u`0b`0s`0y`0s`0t`0e`0m`0 `0f`0o`0r`0 `0L`0i`0n`0u`0x`0 `0i`0s`0 `0n`0o`0t`0 `0i`0n`0s`0t`0a`0l`0l`0e`0d`0.`0" }
        @{ Name = "WSL is too old for --name"; Text = "WSL version: 2.4.3.0" }
    ) {
        Mock Get-WindowsOptionalFeature { [pscustomobject]@{ State = "Enabled" } }
        Mock wsl.exe { $Text; $global:LASTEXITCODE = 1 } -ParameterFilter { $args -contains "--version" }
        Mock Install-WslPackage {}

        Install-Wsl | Should -BeTrue

        Should -Invoke Install-WslPackage -Times 1 -Exactly
        Should -Invoke wsl.exe -Times 0 -Exactly -ParameterFilter { $args -contains "--update" -or $args -contains "--install" }
        Should -Invoke wsl.exe -Times 1 -Exactly -ParameterFilter { ($args -join " ") -eq "--set-default-version 2" }
    }

    It "stops before setting the default version when the package install fails" {
        Mock Get-WindowsOptionalFeature { [pscustomobject]@{ State = "Enabled" } }
        Mock wsl.exe { "Invalid command line option: --version"; $global:LASTEXITCODE = 1 } -ParameterFilter { $args -contains "--version" }
        Mock Install-WslPackage { throw "ERROR: WSL 2.4.4 or newer is needed" }

        { Install-Wsl } | Should -Throw "*WSL 2.4.4 or newer is needed*"
        Should -Invoke wsl.exe -Times 0 -Exactly -ParameterFilter { $args -contains "--set-default-version" }
    }

    It "does not install the package while a restart is pending" {
        Mock Get-WindowsOptionalFeature { [pscustomobject]@{ State = "Disabled" } }
        Mock Read-Host { "n" }
        Mock Install-WslPackage {}

        Install-Wsl | Should -BeFalse
        Should -Invoke Install-WslPackage -Times 0 -Exactly
    }
}

Describe "Install-WslPackage" {
    BeforeEach {
        $script:SavedTemp = $env:TEMP
        $env:TEMP = Join-Path ([IO.Path]::GetTempPath()) "wsl pkg test"  # with a space: the msiexec argument must quote it
        $script:Msi = Join-Path $env:TEMP "wsl.2.6.1.0.x64.msi"
        $script:Version = "WSL version: 2.6.1.0"
        $script:Release = [pscustomobject]@{
            tag_name = "2.6.1"
            assets   = @(
                [pscustomobject]@{ name = "wsl.2.6.1.0.arm64.msi"; browser_download_url = "https://github.com/microsoft/WSL/releases/download/2.6.1/wsl.2.6.1.0.arm64.msi" }
                [pscustomobject]@{ name = "wsl.2.6.1.0.x64.msi"; browser_download_url = "https://github.com/microsoft/WSL/releases/download/2.6.1/wsl.2.6.1.0.x64.msi" }
                [pscustomobject]@{ name = "Microsoft.WSL_2.6.1.0_x64_ARM64.msixbundle"; browser_download_url = "https://github.com/microsoft/WSL/releases/download/2.6.1/bundle" }
            )
        }
        $script:Signature = [pscustomobject]@{
            Status            = "Valid"
            SignerCertificate = [pscustomobject]@{ Subject = "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US" }
        }
        $script:MsiExit = 0
        Mock Write-Host {}
        Mock Invoke-RestMethod { $script:Release }
        Mock Invoke-WebRequest {}
        Mock Get-AuthenticodeSignature { $script:Signature }
        Mock Start-Process { [pscustomobject]@{ ExitCode = $script:MsiExit } }
        Mock Remove-Item {}
        Mock wsl.exe { $script:Version; $global:LASTEXITCODE = 0 } -ParameterFilter { $args -contains "--version" }
    }
    AfterEach { $env:TEMP = $script:SavedTemp }

    It "downloads the x64 MSI of the latest release, checks its signature, installs it quietly and removes it" {
        Install-WslPackage

        Should -Invoke Invoke-RestMethod -Times 1 -Exactly -ParameterFilter { $Uri -eq "https://api.github.com/repos/microsoft/WSL/releases/latest" }
        Should -Invoke Invoke-WebRequest -Times 1 -Exactly -ParameterFilter {
            $Uri -eq "https://github.com/microsoft/WSL/releases/download/2.6.1/wsl.2.6.1.0.x64.msi" -and $OutFile -eq $script:Msi
        }
        Should -Invoke Get-AuthenticodeSignature -Times 1 -Exactly -ParameterFilter { $FilePath -eq $script:Msi }
        Should -Invoke Start-Process -Times 1 -Exactly -ParameterFilter {
            $FilePath -eq "msiexec.exe" -and $ArgumentList -eq "/i `"$($script:Msi)`" /qn /norestart" -and $Wait -and $PassThru
        }
        Should -Invoke Remove-Item -Times 1 -Exactly -ParameterFilter { $Path -eq $script:Msi }
        Should -Invoke wsl.exe -Times 1 -Exactly -ParameterFilter { ($args -join " ") -eq "--version" }
    }

    It "accepts msiexec exit code 3010 (success, restart required)" {
        $script:MsiExit = 3010
        { Install-WslPackage } | Should -Not -Throw
        Should -Invoke Remove-Item -Times 1 -Exactly
    }

    It "fails without an x64 MSI in the release, before downloading anything" {
        $script:Release.assets = @($script:Release.assets | Where-Object { $_.name -notmatch 'x64\.msi$' })
        { Install-WslPackage } | Should -Throw "*no x64 MSI in the WSL release 2.6.1*"
        Should -Invoke Invoke-WebRequest -Times 0 -Exactly
        Should -Invoke Start-Process -Times 0 -Exactly
    }

    It "deletes the download and refuses to install with the signature status <Status>" -ForEach @(
        @{ Status = "NotSigned" }, @{ Status = "HashMismatch" }, @{ Status = "UnknownError" }, @{ Status = "NotTrusted" }
    ) {
        $script:Signature.Status = $Status
        if ($Status -eq "NotSigned") { $script:Signature.SignerCertificate = $null }
        { Install-WslPackage } | Should -Throw "*not signed by Microsoft ($Status)*"
        Should -Invoke Remove-Item -Times 1 -Exactly -ParameterFilter { $Path -eq $script:Msi }
        Should -Invoke Start-Process -Times 0 -Exactly
    }

    It "deletes the download and refuses a valid signature by <Name>" -ForEach @(
        @{ Name = "another company"; Subject = "CN=Contoso Ltd, O=Contoso Ltd, C=US" }
        @{ Name = "a look-alike CN"; Subject = "CN=Microsoft Corporation Evil, O=Evil, C=US" }
        @{ Name = "Microsoft only in the O field"; Subject = "CN=Evil, O=Microsoft Corporation, C=US" }
    ) {
        $script:Signature.SignerCertificate.Subject = $Subject
        { Install-WslPackage } | Should -Throw "*not signed by Microsoft (Valid)*"
        Should -Invoke Remove-Item -Times 1 -Exactly -ParameterFilter { $Path -eq $script:Msi }
        Should -Invoke Start-Process -Times 0 -Exactly
    }

    It "fails when msiexec fails, still removing the download" {
        $script:MsiExit = 1603
        { Install-WslPackage } | Should -Throw "*did not install (msiexec 1603)*"
        Should -Invoke Remove-Item -Times 1 -Exactly -ParameterFilter { $Path -eq $script:Msi }
        Should -Invoke wsl.exe -Times 0 -Exactly
    }

    It "fails when WSL is still too old afterwards" {
        $script:Version = "WSL version: 2.4.3.0"
        { Install-WslPackage } | Should -Throw "*WSL 2.4.4 or newer is needed (wsl --version: WSL version: 2.4.3.0)*"
    }

    It "fails when wsl.exe still is only the inbox stub afterwards" {
        $script:Version = "W`0S`0L`0 `0i`0s`0 `0n`0o`0t`0 `0i`0n`0s`0t`0a`0l`0l`0e`0d`0"
        { Install-WslPackage } | Should -Throw "*WSL 2.4.4 or newer is needed (wsl --version: WSL is not installed)*"
    }
}

Describe "Register-Continuation" {
    BeforeEach {
        $Version = ""; $Branch = ""
        Mock Save-Self { "C:\Program Files\dtm-demonstrator\install.ps1" }
        Mock Set-ItemProperty {}
    }

    It "registers a RunOnce entry that runs the saved copy with the same release" {
        $Version = "v0.4.0"
        Register-Continuation
        Should -Invoke Set-ItemProperty -Times 1 -Exactly -ParameterFilter {
            $Path -eq "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" -and
            $Value -eq 'powershell.exe -NoExit -ExecutionPolicy Bypass -File "C:\Program Files\dtm-demonstrator\install.ps1" -Version v0.4.0'
        }
    }

    It "carries the branch" {
        $Branch = "dev"
        Register-Continuation
        Should -Invoke Set-ItemProperty -Times 1 -Exactly -ParameterFilter { $Value -like "* -Branch dev" -and $Value -notlike "*-Version*" }
    }
}

Describe "Test-Distro" {
    BeforeEach {
        Mock Get-ItemProperty { [pscustomobject]@{ DistributionName = "$Path" } }
    }

    It "finds our distro among the registered ones" {
        Mock Get-ChildItem { @([pscustomobject]@{ PSPath = "Ubuntu" }, [pscustomobject]@{ PSPath = "dtm-demonstrator" }) }
        Test-Distro | Should -BeTrue
        Should -Invoke Get-ChildItem -Times 1 -Exactly -ParameterFilter { $Path -eq "HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss" }
    }

    It "does not match a distro with a similar name" {
        Mock Get-ChildItem { @([pscustomobject]@{ PSPath = "dtm-demonstrator-old" }) }
        Test-Distro | Should -BeFalse
    }

    It "is false without any distro" {
        Mock Get-ChildItem {}
        Test-Distro | Should -BeFalse
    }
}

Describe "Install-Distro" {
    BeforeEach {
        Mock Test-Distro { $false }
        Mock Invoke-Distro {}
        Mock Write-Host {}
        $script:Online = @(
            "The following is a list of valid distributions that can be installed."
            "Install using 'wsl.exe --install <Distro>'."
            ""
            "NAME                            FRIENDLY NAME"
            "Ubuntu                          Ubuntu"
            "Ubuntu-24.04                    Ubuntu 24.04 LTS"
        )
        Mock wsl.exe { $script:Online; $global:LASTEXITCODE = 0 } -ParameterFilter { $args -contains "--online" }
        Mock wsl.exe { $global:LASTEXITCODE = 0 } -ParameterFilter { $args -contains "--install" -or $args -contains "--terminate" }
    }

    It "skips an existing distro" {
        Mock Test-Distro { $true }
        Install-Distro
        Should -Invoke wsl.exe -Times 0 -Exactly
    }

    It "installs 24.04 under its own name when no 26.04 image exists, then configures it" {
        Install-Distro
        Should -Invoke wsl.exe -Times 1 -Exactly -ParameterFilter {
            ($args -join " ") -eq "--install Ubuntu-24.04 --name dtm-demonstrator --no-launch"
        }
        Should -Invoke Invoke-Distro -Times 1 -Exactly -ParameterFilter {
            $Command -match "systemd=true" -and $Command -match "\[automount\]\\nenabled=false" -and
            $Command -match "\[interop\]\\nenabled=false" -and $Command -match "> /etc/wsl.conf$"
        }
        Should -Invoke wsl.exe -Times 1 -Exactly -ParameterFilter { ($args -join " ") -eq "--terminate dtm-demonstrator" }
    }

    It "prefers 26.04" {
        $script:Online += "Ubuntu-26.04                    Ubuntu 26.04 LTS"
        Install-Distro
        Should -Invoke wsl.exe -Times 1 -Exactly -ParameterFilter { $args -contains "--install" -and $args -contains "Ubuntu-26.04" }
    }

    It "fails without a usable image (a preview of the same name does not count)" {
        $script:Online = @("NAME   FRIENDLY NAME", "Debian  Debian GNU/Linux", "Ubuntu-24.04-Preview  Preview")
        { Install-Distro } | Should -Throw "*no Ubuntu WSL image*"
    }

    It "explains nested virtualisation when WSL cannot start its VM" {
        Mock wsl.exe { "Error code: Wsl/Service/CreateInstance/CreateVm/HCS/HCS_E_HYPERV_NOT_INSTALLED"; $global:LASTEXITCODE = 1 } -ParameterFilter { $args -contains "--install" }
        { Install-Distro } | Should -Throw "*nested virtualisation*"
        Should -Invoke Invoke-Distro -Times 0 -Exactly
    }

    It "reports any other install failure" {
        Mock wsl.exe { "disk full"; $global:LASTEXITCODE = 1 } -ParameterFilter { $args -contains "--install" }
        { Install-Distro } | Should -Throw "*wsl --install failed: disk full*"
    }
}

Describe "Invoke-Distro" {
    It "runs the command as root through bash in our distro" {
        Mock wsl.exe { $global:LASTEXITCODE = 0 }
        Invoke-Distro "echo hi"
        Should -Invoke wsl.exe -Times 1 -Exactly -ParameterFilter { ($args -join "|") -eq "-d|dtm-demonstrator|-u|root|--exec|bash|-c|echo hi" }
    }

    It "fails on a non-zero exit code" {
        Mock wsl.exe { $global:LASTEXITCODE = 3 }
        { Invoke-Distro "false" } | Should -Throw "*failed (3)*"
    }

    It "refuses a double quote (Windows PowerShell would pass it unescaped)" {
        Mock wsl.exe { $global:LASTEXITCODE = 0 }
        { Invoke-Distro 'echo "hi"' } | Should -Throw "*double quote*"
        Should -Invoke wsl.exe -Times 0 -Exactly
    }
}

Describe "Install-Demonstrator" {
    BeforeEach {
        $Version = ""; $Branch = ""; $Yes = [switch]$false
        $script:SavedComputerName = $env:COMPUTERNAME
        $env:COMPUTERNAME = "DEMO-PC"
        Mock Get-CimInstance { [pscustomobject]@{ DNSHostName = "Demo-PC"; Domain = "corp.example"; PartOfDomain = $true } }
        Mock Get-LanAddress { @("192.168.1.20") }
        Mock Invoke-Distro {}
        Mock Write-Host {}
    }
    AfterEach { $env:COMPUTERNAME = $script:SavedComputerName }

    It "pipes install.sh into bash with the host names and addresses" {
        $Version = "v0.4.0"; $Yes = [switch]$true
        Install-Demonstrator
        Should -Invoke Invoke-Distro -Times 1 -Exactly -ParameterFilter {
            $Command -eq ("set -o pipefail; curl -fsSL 'https://github.com/danielstroehmann/dc-dtm-demonstrator/releases/download/v0.4.0/install.sh' " +
                "| bash -s -- --version v0.4.0 --host demo-pc --host demo-pc.corp.example --host 192.168.1.20 --yes")
        }
    }

    It "uses the DNS host name, not the 15-character NetBIOS name" {
        $env:COMPUTERNAME = "DEMONSTRATOR-LO"
        Mock Get-CimInstance { [pscustomobject]@{ DNSHostName = "demonstrator-lobby"; Domain = "WORKGROUP"; PartOfDomain = $false } }
        Install-Demonstrator
        Should -Invoke Invoke-Distro -Times 1 -Exactly -ParameterFilter { $Command -match " --host demonstrator-lobby --host 192\.168\.1\.20$" }
    }

    It "refuses a host name that would break the bash command line" {
        Mock Get-CimInstance { [pscustomobject]@{ DNSHostName = "DEMO;REBOOT"; Domain = "WORKGROUP"; PartOfDomain = $false } }
        { Install-Demonstrator } | Should -Throw "*unexpected character*"
        Should -Invoke Invoke-Distro -Times 0 -Exactly
    }
}

Describe "Get-LanAddress" {
    It "uses preferred IPv4 addresses and the adapters with a default gateway" {
        Mock Get-NetIPConfiguration { @([pscustomobject]@{ InterfaceIndex = 4; IPv4DefaultGateway = "x" }, [pscustomobject]@{ InterfaceIndex = 9; IPv4DefaultGateway = $null }) }
        Mock Get-NetIPAddress { @((Address "192.168.1.20" "Ethernet" 4), (Address "10.0.0.7" "Wi-Fi" 9)) }
        Get-LanAddress | Should -Be @("192.168.1.20")
        Should -Invoke Get-NetIPAddress -Times 1 -Exactly -ParameterFilter { $AddressFamily -eq "IPv4" -and $AddressState -eq "Preferred" }
    }
}

Describe "Update-PortProxy" {
    BeforeEach {
        Mock Start-Sleep {}
        Mock Get-LanAddress { @("192.168.1.20") }
        Mock wsl.exe { "2: eth0    inet 172.28.240.9/20 brd 172.28.255.255 scope global eth0\       valid_lft forever"; $global:LASTEXITCODE = 0 }
        Mock netsh { $script:NetshOutput -split "`r`n" } -ParameterFilter { $args -contains "show" }
        Mock netsh { $global:LASTEXITCODE = 0 } -ParameterFilter { $args -notcontains "show" }
    }

    It "replaces our forwardings with ones to the distro's current address" {
        Update-PortProxy
        Should -Invoke wsl.exe -Times 1 -Exactly -ParameterFilter { ($args -join " ") -eq "-d dtm-demonstrator -u root --exec ip -4 -o addr show dev eth0" }
        Should -Invoke netsh -Times 3 -Exactly -ParameterFilter { $args -contains "delete" }
        Should -Invoke netsh -Times 1 -Exactly -ParameterFilter { ($args -join " ") -eq "interface portproxy delete v4tov4 listenport=443 listenaddress=10.0.0.7" }
        Should -Invoke netsh -Times 0 -Exactly -ParameterFilter { $args -contains "listenport=8080" -or $args -contains "listenport=8443" }
        Should -Invoke netsh -Times 2 -Exactly -ParameterFilter { $args -contains "add" -and $args -contains "connectaddress=172.28.240.9" }
    }

    It "leaves current forwardings alone (no reconnects every 5 minutes)" {
        Mock wsl.exe { "2: eth0    inet 172.28.240.2/20 brd 172.28.255.255 scope global eth0"; $global:LASTEXITCODE = 0 }
        Mock netsh { ($script:NetshOutput -split "`r`n") | Where-Object { $_ -notmatch "^10\.0\.0\.7|8443|8080\s*$" } } -ParameterFilter { $args -contains "show" }
        Update-PortProxy
        Should -Invoke netsh -Times 1 -Exactly
        Should -Invoke netsh -Times 0 -Exactly -ParameterFilter { $args -contains "delete" -or $args -contains "add" }
    }

    It "changes nothing when the distro gets no address" {
        Mock wsl.exe { ""; $global:LASTEXITCODE = 1 }
        Mock Write-Warning {}
        Update-PortProxy
        Should -Invoke Start-Sleep -Times 30 -Exactly
        Should -Invoke netsh -Times 0 -Exactly
        Should -Invoke Write-Warning -Times 1 -Exactly
    }
}

Describe "Test-Running" {
    BeforeEach { Mock Start-Sleep {} }

    It "is true once the app answers and the start task runs" {
        Mock curl.exe { $global:LASTEXITCODE = 0 }
        Mock Get-ScheduledTask { [pscustomobject]@{ State = "Running" } }
        Test-Running @("demo-pc", "192.168.1.20") | Should -BeTrue
        Should -Invoke Start-Sleep -Times 0 -Exactly
        Should -Invoke curl.exe -Times 1 -Exactly -ParameterFilter {
            ($args -join " ") -eq "-fsk --max-time 5 --resolve demo-pc:443:127.0.0.1 https://demo-pc/healthz"
        }
    }

    It "is false when the start task is not running" {
        Mock curl.exe { $global:LASTEXITCODE = 0 }
        Mock Get-ScheduledTask { [pscustomobject]@{ State = "Ready" } }
        Test-Running @("demo-pc") | Should -BeFalse
        Should -Invoke Start-Sleep -Times 30 -Exactly
    }

    It "is false when the app does not answer" {
        Mock curl.exe { $global:LASTEXITCODE = 7 }
        Mock Get-ScheduledTask { [pscustomobject]@{ State = "Running" } }
        Test-Running @("demo-pc") | Should -BeFalse
    }
}

Describe "Uninstall-Demonstrator" {
    BeforeEach {
        $Yes = [switch]$false
        Mock Write-Host {}
        Mock Unregister-ScheduledTask {}
        Mock Get-NetFirewallRule {}
        Mock Remove-NetFirewallRule {}
        Mock Remove-Item {}
        Mock Test-Path { $false }
        Mock Test-Distro { $true }
        Mock netsh { $script:NetshOutput -split "`r`n" } -ParameterFilter { $args -contains "show" }
        Mock netsh {} -ParameterFilter { $args -notcontains "show" }
        Mock wsl.exe { $global:LASTEXITCODE = 0 }
    }

    It "keeps the distro and its data unless the deletion is confirmed" {
        Mock Read-Host { "" }
        Uninstall-Demonstrator
        Should -Invoke wsl.exe -Times 0 -Exactly -ParameterFilter { $args -contains "--unregister" }
        Should -Invoke wsl.exe -Times 1 -Exactly -ParameterFilter { ($args -join " ") -eq "-d dtm-demonstrator -u root --exec bash -c systemctl disable --now dtm-demonstrator; docker compose -p dtm-demonstrator stop" }
        Should -Invoke wsl.exe -Times 1 -Exactly -ParameterFilter { ($args -join " ") -eq "--terminate dtm-demonstrator" }
        Should -Invoke Unregister-ScheduledTask -Times 1 -Exactly
        Should -Invoke netsh -Times 3 -Exactly -ParameterFilter { $args -contains "delete" }
    }

    It "warns but finishes when the stack inside cannot be stopped" {
        Mock Read-Host { "n" }
        Mock wsl.exe { "Failed to disable unit"; $global:LASTEXITCODE = 1 } -ParameterFilter { ($args -join " ") -match "systemctl disable" }
        Mock Write-Warning {}
        Uninstall-Demonstrator
        Should -Invoke Write-Warning -Times 1 -Exactly -ParameterFilter { $Message -like "*Failed to disable unit*" }
        Should -Invoke wsl.exe -Times 1 -Exactly -ParameterFilter { ($args -join " ") -eq "--terminate dtm-demonstrator" }
    }

    It "deletes the distro after confirmation" {
        Mock Read-Host { "y" }
        Uninstall-Demonstrator
        Should -Invoke wsl.exe -Times 1 -Exactly -ParameterFilter { ($args -join " ") -eq "--unregister dtm-demonstrator" }
    }

    It "deletes the distro with -Yes without asking" {
        $Yes = [switch]$true
        Mock Read-Host { throw "must not ask" }
        Uninstall-Demonstrator
        Should -Invoke wsl.exe -Times 1 -Exactly -ParameterFilter { $args -contains "--unregister" }
    }

    It "does not ask when there is no distro" {
        Mock Test-Distro { $false }
        Mock Read-Host { throw "must not ask" }
        Uninstall-Demonstrator
        Should -Invoke wsl.exe -Times 0 -Exactly
    }

    It "removes only its own script, never the folder recursively" {
        Mock Read-Host { "" }
        Uninstall-Demonstrator
        Should -Invoke Remove-Item -Times 1 -Exactly -ParameterFilter { $Path -like "*dtm-demonstrator*install.ps1" -and -not $Recurse }
    }
}

Describe "Reset-Password" {
    BeforeEach {
        $Version = ""; $Branch = ""
        Mock Test-Distro { $true }
        Mock Invoke-Distro {}
    }

    It "runs install.sh --reset-password of the latest release in the distro" {
        Reset-Password
        Should -Invoke Invoke-Distro -Times 1 -Exactly -ParameterFilter {
            $Command -eq ("set -o pipefail; curl -fsSL 'https://github.com/danielstroehmann/dc-dtm-demonstrator/releases/latest/download/install.sh' " +
                "| bash -s -- --reset-password")
        }
    }

    It "uses the chosen release or branch" {
        $Branch = "dev"
        Reset-Password
        Should -Invoke Invoke-Distro -Times 1 -Exactly -ParameterFilter {
            $Command -eq "set -o pipefail; curl -fsSL 'https://raw.githubusercontent.com/danielstroehmann/dc-dtm-demonstrator/dev/install.sh' | bash -s -- --reset-password"
        }
    }

    It "refuses an invalid branch before running anything" {
        $Branch = "dev;id"
        { Reset-Password } | Should -Throw "*invalid branch*"
        Should -Invoke Invoke-Distro -Times 0 -Exactly
    }

    It "refuses when the demonstrator is not installed" {
        Mock Test-Distro { $false }
        { Reset-Password } | Should -Throw "*not installed*"
        Should -Invoke Invoke-Distro -Times 0 -Exactly
    }
}

Describe "Invoke-Main" {
    BeforeEach {
        $Version = ""; $Branch = ""; $Uninstall = [switch]$false; $ResetPassword = [switch]$false
        Mock Reset-Password {}
        $script:SavedComputerName = $env:COMPUTERNAME
        $env:COMPUTERNAME = "DEMO-PC"
        Mock Write-Host {}
        Mock Assert-Prerequisite {}
        Mock Assert-Admin {}
        Mock Get-MachineName { @("demo-pc") }
        Mock Remove-ItemProperty {}
        Mock Install-Wsl { $true }
        Mock Install-Distro {}
        Mock Install-Demonstrator {}
        Mock Install-Firewall {}
        Mock Install-StartTask {}
        Mock Test-Running { $true }
        Mock Uninstall-Demonstrator {}
    }
    AfterEach { $env:COMPUTERNAME = $script:SavedComputerName }

    It "runs every step and drops a pending continuation" {
        Invoke-Main
        Should -Invoke Remove-ItemProperty -Times 1 -Exactly -ParameterFilter { $Name -eq "DtmDemonstratorInstall" }
        Should -Invoke Install-Distro -Times 1 -Exactly
        Should -Invoke Install-Demonstrator -Times 1 -Exactly
        Should -Invoke Install-Firewall -Times 1 -Exactly
        Should -Invoke Install-StartTask -Times 1 -Exactly
        Should -Invoke Uninstall-Demonstrator -Times 0 -Exactly
    }

    It "stops after enabling WSL when a restart is pending" {
        Mock Install-Wsl { $false }
        Invoke-Main
        Should -Invoke Install-Distro -Times 0 -Exactly
        Should -Invoke Install-Demonstrator -Times 0 -Exactly
        Should -Invoke Install-StartTask -Times 0 -Exactly
        Should -Invoke Test-Running -Times 0 -Exactly
    }

    It "checks the health under the machine's DNS name" {
        Invoke-Main
        Should -Invoke Test-Running -Times 1 -Exactly -ParameterFilter { $HostNames[0] -eq "demo-pc" }
    }

    It "fails when the demonstrator does not answer after the install" {
        Mock Test-Running { $false }
        { Invoke-Main } | Should -Throw "*does not answer on https://demo-pc/*"
    }

    It "only uninstalls with -Uninstall, needing admin rights but not the OS checks" {
        $Uninstall = [switch]$true
        Mock Assert-Prerequisite { throw "ERROR: virtualisation is not available" }
        Invoke-Main
        Should -Invoke Assert-Admin -Times 1 -Exactly
        Should -Invoke Uninstall-Demonstrator -Times 1 -Exactly
        Should -Invoke Install-Wsl -Times 0 -Exactly
    }

    It "only resets the password with -ResetPassword, needing admin rights but not the OS checks" {
        $ResetPassword = [switch]$true
        Mock Assert-Prerequisite { throw "ERROR: virtualisation is not available" }
        Invoke-Main
        Should -Invoke Assert-Admin -Times 1 -Exactly
        Should -Invoke Reset-Password -Times 1 -Exactly
        Should -Invoke Install-Wsl -Times 0 -Exactly
        Should -Invoke Install-Demonstrator -Times 0 -Exactly
        Should -Invoke Uninstall-Demonstrator -Times 0 -Exactly
        Should -Invoke Remove-ItemProperty -Times 0 -Exactly
    }

    It "does not reset the password without admin rights" {
        $ResetPassword = [switch]$true
        Mock Assert-Admin { throw "ERROR: run this in an elevated PowerShell" }
        { Invoke-Main } | Should -Throw "*elevated*"
        Should -Invoke Reset-Password -Times 0 -Exactly
    }

    It "a normal install does not reset the password" {
        Invoke-Main
        Should -Invoke Reset-Password -Times 0 -Exactly
    }

    It "does not uninstall without admin rights" {
        $Uninstall = [switch]$true
        Mock Assert-Admin { throw "ERROR: run this in an elevated PowerShell" }
        { Invoke-Main } | Should -Throw "*elevated*"
        Should -Invoke Uninstall-Demonstrator -Times 0 -Exactly
    }

    It "validates -Version and -Branch before changing anything" {
        $Version = "v0.4.0"; $Branch = "dev"
        { Invoke-Main } | Should -Throw "*either -Version or -Branch*"
        Should -Invoke Install-Wsl -Times 0 -Exactly
    }

    It "stops when the prerequisites are not met" {
        Mock Assert-Prerequisite { throw "ERROR: run this in an elevated PowerShell" }
        { Invoke-Main } | Should -Throw "*elevated*"
        Should -Invoke Install-Wsl -Times 0 -Exactly
        Should -Invoke Remove-ItemProperty -Times 0 -Exactly
    }
}
