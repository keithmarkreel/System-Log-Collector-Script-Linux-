# Linux System Log Collector

An automated, cross-distribution audit collector for Linux workstation fleets. The admin-side script discovers SSH-accessible machines, provisions a restricted remote collector, and retrieves system and security data over SSH. It audits three account types (AM shift, PM shift, ADMIN), optionally runs read-only ClamAV scans, and builds a monthly tracking-sheet CSV with hardware inventory and scan results.

## Highlights

- **SSH access with the existing `admin2025` account:** The collector logs in as `admin2025` by default (`SSH_USER`). PCs that use a different admin login (for example `admin2026` or `admin`) can be set per PC in `hosts.txt`.
- **Temporary remote workspace:** The collector stages data in an isolated `/tmp/audit.XXXXXX` directory, streams a tar archive over SSH standard output, and removes its temporary files with a cleanup trap. It does not leave permanent archives on target workstations.
- **Restricted privilege escalation:** Provisioning installs `/etc/sudoers.d/audit-collect`, allowing passwordless execution only of `/usr/local/sbin/audit-collect`.
- **Per-account auditing (AM / PM / ADMIN):** Successful logins, failed logins, and sudo activity are split by account. Any other account that logs in or fails sudo is reported as `OTHER`.
- **Monthly tracking-sheet CSV:** Each run adds one row per PC (hardware inventory, scan status, infected and scanned file counts, invalid entries) to `scan_log_<Month>.csv`, in the column order of the tracking sheet.
- **Read-only ClamAV scans:** `scan` mode scans the account home folders, by default only files modified or changed in the last 30 days. Nothing is deleted, moved, or quarantined.
- **Parallel collection:** All PCs are processed at the same time by default, or limit it with `JOBS`.
- **Cross-distribution collection:** Supports Debian, Ubuntu, and Kali (`dpkg`); RHEL, CentOS, Fedora, and Rocky (`rpm`); Arch (`pacman`); and openSUSE (`zypper`).
- **Browser data minimization:** When enabled, browser history is exported as CSV containing timestamps, URLs, and page titles. Raw browser databases are not retained in the collected output and are removed from the temporary workspace.
- **Flexible discovery:** Reads an optional `hosts.txt`, uses `nmap -sT` for SSH port sweeps when available, or falls back to parallel Bash `/dev/tcp` probes. Specific hosts can be excluded.

## What It Collects

| Category | Data collected | Sources and methods |
| --- | --- | --- |
| System information | Hostname, OS distribution, kernel, and interface IP addresses | `uname`, `/etc/os-release`, `ip` |
| Hardware inventory | CPU and generation, memory and module layout, primary disk size/type/serial, GPU, MAC address, wired/wireless | `lscpu`, `/proc/meminfo`, `dmidecode`, `lsblk`, `lspci`, `/sys/class/net` |
| Authentication | Sudo activity, SSH logins, and GDM/LightDM/SDDM logins and screen unlocks | `/var/log/auth.log`, `/var/log/secure`, `journalctl` |
| Per-account logins | Successful logins, failed logins, and sudo failures for the AM, PM and ADMIN accounts (plus `OTHER`) | `journalctl` (or `auth.log`), `last`, `lastb` |
| Failed logins | PAM authentication failures, incorrect passwords, and invalid users | `lastb`, `last -b`, and PAM-pattern matches from `systemd-journald` |
| System state | Kernel panics, hardware warnings, and boot history | `/var/log/syslog`, `/var/log/messages`, `journalctl -p warning`, `journalctl --list-boots` |
| Installed applications | Package manifest and available Snap/Flatpak manifests | `dpkg-query`, `rpm`, `pacman`, `zypper`, `snap list`, `flatpak list` |
| Security logs | Antivirus and rootkit scan logs, and firewall state/logs | `/var/log/clamav`, `/var/log/rkhunter.log`, `ufw.log`, `firewalld` |
| Virus scan (`scan` mode) | Scanned-file count, infected-file count, and the names of infected files | `clamscan` on each account home folder |
| Browser history | Timestamp (UTC), URL, and page title | Firefox `places.sqlite`; Chromium/Chrome `History` databases |

Collected data depends on the tools, services, and log sources available on each target.

## Requirements

### Admin machine

- Linux (for example, Debian, Ubuntu, or Kali)
- Bash 4.0 or later
- `openssh-client`
- `sqlite3` if browser history collection is enabled
- `nmap` (optional; without it, discovery uses Bash `/dev/tcp` probes)
- `flock` (part of `util-linux`, normally preinstalled; keeps the CSV consistent during parallel runs)

Install the dependencies on Debian, Ubuntu, or Kali:

```bash
sudo apt update
sudo apt install -y openssh-client sqlite3 nmap
```

### Target workstations

- An SSH server listening on port 22 (`openssh-server`)
- The `admin2025` account (or the per-PC login set in `hosts.txt`) with `sudo` privileges
- `clamscan` (ClamAV) installed, for `scan` mode
- Optional, for the hardware inventory: `dmidecode`, `lsblk`, `lspci`

## Quick Start

### 1. Configure the collector

Edit the settings near the top of `collect_audit_logs.sh`, or override any of them for a single run, for example `JOBS=5 ./collect_audit_logs.sh scan`:

```bash
ADMIN_IP="192.168.0.93"           # Admin machine IP; excluded from scans
SUBNET="192.168.0.0/24"           # Network range to inspect
SSH_USER="${SSH_USER:-admin2025}" # Default SSH login on the workstations
DAYS=35                           # Log look-back window (login/failed-login entries)
COLLECT_BROWSER=1                 # 1 = collect browser history; 0 = skip
AM_USER="AM"                      # Morning-shift account
PM_USER="PM"                      # Afternoon-shift account
ADMIN_USERS="admin2025,admin2026,admin"   # Admin account name(s) used on the workstations
SCAN_DAYS=30                      # scan mode: only files changed in the last N days (0 = everything)
JOBS=0                            # PCs processed at once (0 = all, 1 = one by one)
EXCLUDE_IPS="192.168.0.43"        # Hosts to skip (space/comma separated); set your own
```

### 2. Choose the target PCs (optional)

To restrict collection to specific workstations, create `hosts.txt` alongside the script, one IP address per line. Add a login name after the IP only for PCs that do not use the default `admin2025`:

```text
192.168.0.21
192.168.0.22 admin2026
192.168.0.23 admin
# lines starting with # are ignored
```

Without `hosts.txt`, the script discovers every host with SSH open on `SUBNET` and uses the default login for all of them. The collector does not guess usernames, because failed guesses would appear as failed logins in the targets' own audit logs.

### 3. Discover reachable targets

List the hosts the script will contact:

```bash
./collect_audit_logs.sh list
```

### 4. Provision target workstations

Generate an Ed25519 administrative SSH key if needed, install the public key on targets, deploy `/usr/local/sbin/audit-collect`, and configure the restricted sudoers rule. Run it again after any update to the collector:

```bash
./collect_audit_logs.sh setup
```

You will be prompted for the remote account's password on each target (one PC at a time). `setup` and `collect` must be run as the same user on the admin machine, because the SSH key lives in that user's `~/.ssh`.

### 5. Collect audit data

| Command | What it does |
| --- | --- |
| `./collect_audit_logs.sh collect` | Fast. Collects logs, per-account login reports, hardware inventory, and the CSV row for each PC. |
| `./collect_audit_logs.sh scan` | Everything `collect` does, plus a read-only ClamAV scan of the AM, PM and ADMIN home folders. Slow; run it outside working hours. |

The scan columns of the CSV (`ScanLog`, `Scanned Files`, `Infected File Count`, infected-file names) are filled only by `scan`.

## Output

Results are written on the admin machine under `OUT_ROOT`, by default `~/audit-logs` of the `admin2025` account on the admin PC (`/home/admin2025/audit-logs`), even when the script is run as root. If that account does not exist, the account the script was run from is used. Override with `OUT_ROOT=/some/folder` or `OUT_USER=<account>`. The output is restricted with `go-rwx` permissions.

```text
~/audit-logs/
├── 2026-10-15/                          # full collection, one folder per run
│   ├── summary.txt                      # fleet summary
│   └── workstation01_192.168.0.23/
│       ├── info.txt
│       ├── inventory.txt
│       ├── auth/
│       │   ├── failed_logins_lastb.txt
│       │   ├── logins_last.txt
│       │   ├── journal_auth.txt
│       │   └── shift/                   # AM / PM / ADMIN breakdown
│       │       ├── events.tsv
│       │       ├── AM_events.tsv  PM_events.tsv  ADMIN_events.tsv  OTHER_events.tsv
│       │       ├── counts.tsv
│       │       └── entry_Admin.txt  entry_AM.txt  entry_PM.txt
│       ├── scan/                        # scan mode only
│       │   └── result_Admin.txt  result_AM.txt  result_PM.txt
│       ├── system/
│       │   ├── boots.txt
│       │   └── journal_warnings.txt
│       └── apps/
│           ├── installed_packages.tsv
│           └── dpkg.log
└── October Scan Logs/                   # monthly report folder
    ├── scan_log_October.csv             # tracking-sheet rows, one per PC
    └── Production/
        └── workstation01/
            ├── Entry Logs/   entryAdmin_workstation01.txt, entryAM_…, entryPM_…
            └── Scan Logs/    resultAdmin_workstation01.txt, resultAM_…, resultPM_…   (scan mode)
```

To keep the monthly folder somewhere else, such as a USB drive, set `REPORTS_ROOT`, for example `REPORTS_ROOT=/media/admin2025/NEW ./collect_audit_logs.sh scan`. The exact files vary by target distribution and by which logs, packages, and services are present.

### Entry and result files

- **`entry<Account>_<PC>.txt`:** Three sections for that account: successful logins, failed login attempts, and sudo usage, followed by `last` / `lastb` history and a totals line.
- **`result<Account>_<PC>.txt`:** The raw ClamAV output for that account's home folder, starting with a line stating the scan scope and ending with the ClamAV `SCAN SUMMARY` block.

### Tracking-sheet CSV

`scan_log_<Month>.csv` follows the column order of the PC tracking sheet. Re-running in the same month replaces that PC's row. Month-specific columns carry the month number (for example `ScanLog10`, `Date10` in October). If the column layout changes between versions, the old file is kept as `scan_log_<Month>.csv.old-layout.bak` and a new one is started.

| Filled automatically | Source |
| --- | --- |
| Hostname, IP address, MAC address, connection type (wired/wireless) | Target PC / SSH connection |
| Processor, processor generation, memory, memory modules, storage capacity/type/serial, GPU, OS | Hardware inventory |
| `<Month> Status` | "Active" for every PC that responded |
| `ScanLog`, `Date` | Whether the ClamAV scan completed, and the run date (`scan` mode) |
| `Infected File Count`, `Scanned Files`, `Infected File Remarks` | ClamAV summaries totalled across AM, PM and ADMIN; remarks name up to three infected files (`scan` mode) |
| `Invalid Entry`, `Invalid Entry Remarks` | Failed logins plus failed sudo attempts across all accounts; remarks list who and how many, marked "needs review" |

Left blank for manual entry: Site, Area and Department (unless set with `SITE`, `AREA`, `DEPARTMENT`), Compatible with Windows 11, OS Activated, System Update, Ping Test, SpeedTest, Crimp Eval, and their dates.

## Account Auditing

- **AM / PM:** The morning-shift and afternoon-shift accounts (`AM_USER`, `PM_USER`).
- **ADMIN:** Any account listed in `ADMIN_USERS` that exists on the PC. Their logs are merged into one ADMIN report, and the scan covers the first one with a home folder.
- **OTHER:** Any other account with logins or failed sudo attempts, listed by name in the summary.
- Account names are matched case-insensitively, and login-screen (`gdm`) sessions are ignored.
- Counts cover the last `DAYS` days of logs, not strictly the calendar month.

## ClamAV Scans

`scan` mode runs `clamscan` on the AM, PM and ADMIN home folders:

- **Scope:** With `SCAN_DAYS=30` (default) only files modified or changed (`mtime`/`ctime`) in the last 30 days are scanned. `SCAN_DAYS=0` scans every file.
- **Read-only:** The scan only reports. It never removes, moves, or copies files.
- **Updates paused:** `clamav-freshclam` is stopped during the scan and restarted afterwards, including if the connection drops.
- **Timing:** PCs scan in parallel, so the total time is about that of the slowest PC.

Files not changed within the scan window are not checked, so run an occasional `SCAN_DAYS=0` scan as well.

## Parallel Runs and Excluding Hosts

```bash
JOBS=5 ./collect_audit_logs.sh scan                      # 5 PCs at a time
EXCLUDE_IPS="192.168.0.21 192.168.0.30" ./collect_audit_logs.sh collect   # skip these PCs
```

`setup` always runs one PC at a time because it prompts for passwords.

## USB Mode (no SSH)

`usb_audit.sh` runs directly on a workstation from a USB stick and writes the same `entry*` and `result*` files in the same `<Month> Scan Logs/Production/<PC>/` layout next to the script:

```bash
sudo bash /media/<user>/<USB>/usb_audit.sh              # logs + ClamAV scans
sudo bash /media/<user>/<USB>/usb_audit.sh --logs-only  # skip the scans
```

## Monthly Automation

To run a scan at 02:00 on the first day of every month, edit the crontab of the account that ran `setup` (the SSH key must belong to that account):

```bash
crontab -e
```

Add an entry using the actual path to the script:

```cron
0 2 1 * * /bin/bash /home/admin2025/scripts/collect_audit_logs.sh scan >/dev/null 2>&1
```

## Troubleshooting

| Symptom | Likely cause and fix |
| --- | --- |
| "No SSH-reachable hosts were found" | The admin PC is not on `SUBNET`, the targets are off, or SSH is not running. Run `./collect_audit_logs.sh list`, or put the PCs in `hosts.txt`. |
| A PC answers ping but is not listed | Its SSH port is closed or filtered (`nmap -sT -p 22 <ip>`), or it is excluded. Install and start `openssh-server` and allow port 22. |
| `Couldn't open a raw socket` from `nmap` | Typical of a snap-installed `nmap`. The collector uses `nmap -sT` and falls back to Bash probes, so discovery still works. |
| `Connection refused` on port 22 | Nothing is listening on SSH on that PC (`sudo systemctl enable --now ssh`). |
| `FAIL ... (cannot connect via SSH)` | The key is not installed yet or the login name is wrong. Run `setup`, and set the right login for that PC in `hosts.txt`. |
| Scan columns of the CSV are blank | The run used `collect`. Use `scan`. |

## Data Handling and Security

- The output contains employee login activity, and browser history if `COLLECT_BROWSER=1`. Collect it only as permitted by company policy, and store it with restricted permissions.
- Do not publish real hostnames, IP addresses, logs, scan results, or the tracking sheet in a public repository.
- The collector and scans are read-only on the targets. The only changes `setup` makes are installing `/usr/local/sbin/audit-collect`, the sudoers rule, and the SSH public key.
