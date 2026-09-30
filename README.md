# Linux System Log Collector

An automated, cross-distribution audit collector for Linux workstation fleets. The admin-side script discovers SSH-accessible machines, provisions a restricted remote collector, and retrieves system and security data over SSH.

## Highlights

- **Temporary remote workspace:** The collector stages data in an isolated `/tmp/audit.XXXXXX` directory, streams a tar archive over SSH standard output, and removes its temporary files with a cleanup trap. It does not leave permanent archives on target workstations.
- **Restricted privilege escalation:** Provisioning installs `/etc/sudoers.d/audit-collect`, allowing passwordless execution only of `/usr/local/sbin/audit-collect`.
- **Cross-distribution collection:** Supports Debian, Ubuntu, and Kali (`dpkg`); RHEL, CentOS, Fedora, and Rocky (`rpm`); Arch (`pacman`); and openSUSE (`zypper`).
- **Browser data minimization:** When enabled, browser history is exported as CSV containing timestamps, URLs, and page titles. Raw browser databases are not retained in the collected output and are removed from the temporary workspace.
- **Flexible discovery:** Reads an optional `hosts.txt`, uses `nmap` for fast SSH port sweeps when available, or falls back to parallel Bash `/dev/tcp` probes.

## What It Collects

| Category | Data collected | Sources and methods |
| --- | --- | --- |
| System information | Hostname, OS distribution, kernel, and interface IP addresses | `uname`, `/etc/os-release`, `ip` |
| Authentication | Sudo activity, SSH logins, and GDM/LightDM/SDDM screen unlocks | `/var/log/auth.log`, `/var/log/secure`, `journalctl` (`_SYSTEMD_UNIT`) |
| Failed logins | PAM authentication failures, incorrect passwords, and invalid users | `lastb`, `last -b`, and PAM-pattern matches from `systemd-journald` |
| System state | Kernel panics, hardware warnings, and boot history | `/var/log/syslog`, `/var/log/messages`, `journalctl -p warning`, `journalctl --list-boots` |
| Installed applications | Package manifest and available Snap/Flatpak manifests | `dpkg-query`, `rpm`, `pacman`, `zypper`, `snap list`, `flatpak list` |
| Security logs | Antivirus and rootkit scan logs, and firewall state/logs | `/var/log/clamav`, `/var/log/rkhunter.log`, `ufw.log`, `firewalld` |
| Browser history | Timestamp (UTC), URL, and page title | Firefox `places.sqlite`; Chromium/Chrome `History` databases |

Collected data depends on the tools, services, and log sources available on each target.

## Requirements

### Admin machine

- Linux (for example, Debian, Ubuntu, or Kali)
- Bash 4.0 or later
- `openssh-client`
- `sqlite3` if browser history collection is enabled
- `nmap` (optional; without it, discovery uses Bash `/dev/tcp` probes)

Install the dependencies on Debian, Ubuntu, or Kali:

```bash
sudo apt update
sudo apt install -y openssh-client sqlite3 nmap
```

### Target workstations

- An SSH server listening on port 22 (`openssh-server`)
- A user account with `sudo` privileges

## Quick Start

### 1. Configure the collector

Edit the settings near the top of `collect_audit_logs.sh` to match your network and collection policy:

```bash
ADMIN_IP="192.168.0.93"           # Admin machine IP; excluded from scans
SUBNET="192.168.0.0/24"           # Network range to inspect
SSH_USER="${SSH_USER:-kali}"      # Target account with sudo rights
OUT_ROOT="${OUT_ROOT:-$HOME/audit-logs}"
DAYS=35                            # Log look-back window
COLLECT_BROWSER=1                  # 1 = collect browser history; 0 = skip
```

To restrict collection to specific workstations, create `hosts.txt` alongside the script. Put one hostname or IP address per line:

```text
192.168.0.10
192.168.0.223
```

### 2. Discover reachable targets

List hosts responding on SSH port 22:

```bash
./collect_audit_logs.sh list
```

### 3. Provision target workstations

Generate an Ed25519 administrative SSH key if needed, install the public key on targets, deploy `/usr/local/sbin/audit-collect`, and configure the restricted sudoers rule:

```bash
./collect_audit_logs.sh setup
```

You will be prompted for the remote user's password on each target to authorize SSH key installation.

### 4. Collect audit data

Run collection across the configured targets:

```bash
./collect_audit_logs.sh collect
```

## Output

Results are written on the admin machine under `OUT_ROOT`, grouped by collection date and workstation. The output directory is created with restricted `chmod 700` permissions.

```text
~/audit-logs/
└── 2026-09-30/
	├── summary.txt
	└── workstation01_192.168.0.223/
		├── info.txt
		├── browser_history_chromium_kali__.config__google-chrome__Default.csv
		├── browser_history_firefox_kali__.mozilla__firefox__abc123.default.csv
		├── auth/
		│   ├── failed_logins_lastb.txt
		│   ├── logins_last.txt
		│   ├── journal_auth.txt
		│   └── auditd/
		├── system/
		│   ├── boots.txt
		│   └── journal_warnings.txt
		└── apps/
			├── installed_packages.tsv
			└── dpkg.log
```

The exact files vary by target distribution and by which logs, packages, and services are present.

## Monthly Automation

To run collection at 02:00 on the first day of every month, edit the admin user's crontab:

```bash
crontab -e
```

Add an entry using the actual path to the script:

```cron
0 2 1 * * /bin/bash /home/kali/scripts/collect_audit_logs.sh collect >/dev/null 2>&1
```

