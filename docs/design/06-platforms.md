# Platforms: Linux arm64 and Windows (decided 2026-10-27)

Requested by the author: besides Ubuntu Server 26.04 amd64 (NFR-1), a one-line install on **Linux arm64**
and on **Windows 11 x64, Windows Server 2022 and Windows Server 2025**. In each case the user starts from a
fresh machine and is logged in as a local administrator.

## Linux arm64

- **The image becomes multi-arch:** CI builds `linux/amd64` and `linux/arm64` with buildx under the same tags.
  Nothing in the image is architecture-specific: `python:3.14-slim` and Debian's `scep` package exist for
  arm64, and `caddy` is multi-arch.
- **The installer is already architecture-neutral:** the Docker apt repository is selected via
  `dpkg --print-architecture`. The target stays **Ubuntu Server 26.04** (minimal), now amd64 or arm64.
- **CI:** the stack smoke also runs on an arm64 runner (`ubuntu-24.04-arm`) against the arm64 image.
- **Decided:** "Linux arm" means **Ubuntu Server 26.04 arm64** (cloud VM, VM on Apple silicon, Raspberry Pi 5
  with Ubuntu). Other distributions are out of scope.

## Windows: the same Linux stack, inside WSL 2

Linux containers on Windows need a Linux VM. Three ways are possible:

| Option | For | Against |
|---|---|---|
| **A – WSL 2 + Ubuntu + Docker Engine, then the existing `install.sh` (decided)** | One stack on every platform; Docker Engine is Apache 2.0 (no Docker Desktop licence); `wsl --install` is supported on Win 11, Server 2022 and Server 2025 | Reboot after enabling WSL on a fresh machine; network and autostart need Windows-side glue |
| B – Docker Desktop | Familiar | Paid for companies > 250 employees; not supported on Windows Server |
| C – Hyper-V VM with Ubuntu | Full Linux | Heavy, needs an image download and VM management; Hyper-V is not on every edition / VM host |

### Option A in detail

One-liner in an elevated PowerShell:

```powershell
irm https://github.com/danielstroehmann/dc-dtm-demonstrator/releases/latest/download/install.ps1 | iex
```

1. **Checks:** admin rights, the OS (Win 11 22H2+, Server 2022 with the June 2022 update or later, Server
   2025), x64, and virtualisation available. In a VM that means nested virtualisation is enabled on the host.
2. **WSL:** the optional features *Microsoft-Windows-Subsystem-Linux* and *VirtualMachinePlatform*, then
   `wsl --update --web-download` (WSL >= 2.4.4). If the features were missing a **reboot** follows: the script registers a one-time
   continuation at the next logon (RunOnce) and asks for the reboot. The same one-liner run again also
   continues.
3. **Distro:** its own instance `dtm-demonstrator` (Ubuntu 26.04 WSL image, or 24.04 until a 26.04 image
   exists), with systemd enabled in `/etc/wsl.conf`. It is kept separate from any Ubuntu the user already has.
4. **Install:** `install.sh` runs inside the distro unchanged (Docker Engine, `.env`, TLS, compose,
   systemd unit).
5. **Reachable from the LAN:** WSL 2 uses NAT by default. *Mirrored* networking is documented for
   Win 11 22H2+ only, and one user reported it failing on Server. So the script uses NAT plus
   `netsh interface portproxy` (443/80 → the distro's IP, refreshed at every start, since that IP changes)
   and Windows Firewall rules for 443/80. On Win 11 mirrored networking would be simpler; one path for all
   three systems is easier to test.
6. **Autostart without a logon:** a scheduled task at system start, running as the installing admin
   ("run whether the user is logged on or not"). It starts the distro, keeps it alive (WSL otherwise stops
   an idle instance) and refreshes the port proxy.
7. **Update:** the same one-liner. Data stays inside the distro under `/opt/dtm-demonstrator` (`.env`,
   `./data`).
8. **Uninstall:** `install.ps1 -Uninstall` removes the task, the port proxy, the firewall rules and the
   distro (after a confirmation, because that also deletes `./data`).

### After the review (2026-10-27)

- Script copy for the restart continuation and the start task under `%ProgramFiles%\dtm-demonstrator` – not
  `ProgramData`, where any user can create the folder first and own the script the elevated task runs.
- WSL is enabled with `Enable-WindowsOptionalFeature` (as Microsoft's server guide does), then
  `wsl --update --web-download`; WSL ≥ 2.4.4 is required (`--name`). Server 2022 needs build 20348.768+.
- "latest" is resolved to a tag once – install.sh, the saved copy and the continuation are the same release.
- The distro gets no Windows drives and no interop (`/etc/wsl.conf`): the start task runs elevated.
- The start task loops: keep-alive plus a port proxy refresh every 5 minutes (WSL updates, DHCP).
- LAN addresses: adapters with a default gateway, without virtual switches; the IP Helper service (port
  proxy) is set to automatic.
- Firewall (author, 2026-10-27: Defender is on on a fresh Windows): Defender Firewall rules for TCP 443/80 –
  domain and private profile from any address, public profile from the local subnet only; plus Hyper-V
  firewall rules for the WSL VM where it exists (Win 11 22H2+, Server 2025).
- The installer ends with a check: `https://localhost/healthz` answers and the start task runs.

### Risks and open questions
- **Autostart without a logon is the biggest risk:** a task at boot runs in session 0, and launching WSL
  from session 0 is a known, open WSL issue ([#9231](https://github.com/microsoft/WSL/issues/9231); reports
  are mixed – it works with the MSI WSL on Server 2022/2025 for some). Acceptance test on all three systems:
  reboot, **no logon**, the UI answers from another machine. Fallback if it fails: a logon task with
  automatic logon – a security trade-off the author decides.

- **Nested virtualisation:** Server 2022/2025 as a VM (Hyper-V, VMware, Azure, AWS) needs it enabled on the
  host; on some clouds only certain instance types support it. The script checks this and explains the fix.
- **Server Core: out of scope** (decided) – Windows Server with Desktop Experience only.
- **Ubuntu 26.04 WSL image:** whether a 26.04 WSL image is available at release time, else 24.04 in WSL
  (the installer supports both?).
- **Tests (decided):** GitHub-hosted runners have no nested virtualisation, so WSL 2 cannot run there. CI
  runs PSScriptAnalyzer and Pester unit tests of the script logic on `windows-2022` and `windows-2025`; the
  real install is verified manually in VMs (Win 11, Server 2022, Server 2025 – provided by the author) before
  every release that touches the Windows installer.

Sources: Microsoft, [Install WSL on Windows Server](https://learn.microsoft.com/windows/wsl/install-on-server);
[WSL issue 12569](https://github.com/microsoft/WSL/issues/12569) (mirrored mode on Server).

## Verified on Windows Server 2025 (2026-10-27)

Fresh Windows Server 2025 Standard (build 26100.33650, Desktop Experience) as a KVM VM (CPU type `host`,
nested virtualisation), workgroup, network profile *Public*; driven over SSH with `-Branch dev -Yes`:

- Run 1 enabled the WSL features and restarted. Run 2 (the continuation) installed WSL 3.0.3 from Microsoft's
  MSI (the inbox `wsl.exe` only answers "not installed", even to `--update` and `--install`), the distro
  (Ubuntu 26.04), Docker and the stack, then the firewall, port proxy and start task; health check passed.
- From another machine on the LAN: `/healthz` and the login 200, HTTP → HTTPS 302, certificate for the IP and
  the DNS host name.
- **Restart without any logon:** the UI answered from the LAN 42 s after the restart (uptime 45 s, no
  interactive session, start task running) – launching WSL from session 0 works here.
- Update (installer again): secrets and data unchanged, healthy.
- Learned: with the CPU type *QEMU Virtual CPU* (no VMX/SVM) WSL fails with `HCS_E_HYPERV_NOT_INSTALLED` –
  the installer's hint names the fix.

Still open: uninstall on Server 2025; Windows Server 2022 and Windows 11.
