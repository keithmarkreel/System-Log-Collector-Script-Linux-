#!/usr/bin/env bash
# collect_audit_logs.sh / script_flipside.sh
# Run on the admin PC (192.168.0.93).
# Pulls auth/system/app logs and browser history from workstations into:
#   $OUT_ROOT/<YYYY-MM-DD>/<pc-hostname>_<pc-ip>/
#
# Also audits three shift accounts (AM, PM, ADMIN): successful logins, failed
# logins, sudo failures, plus any OTHER account that shows up.
#
# Usage:
#   ./script_flipside.sh list       # show which hosts would be contacted
#   ./script_flipside.sh setup      # ONE-TIME (or after any update): install SSH key + collector on each PC
#   ./script_flipside.sh collect    # log collection, all PCs at the same time (JOBS=1 for one by one)
#   ./script_flipside.sh scan       # same as collect + ClamAV scan of the AM/PM/ADMIN home folders (slow)
#
# Also builds the monthly tracking-sheet rows (hardware inventory + ScanLog / Infected File Count /
# Invalid Entry columns) in:  $REPORTS_ROOT/<Month> Scan Logs/scan_log_<Month>.csv
#
# Besides the full per-PC folders, every run also files the per-account reports in the
# monthly folder layout:
#   $REPORTS_ROOT/<Month> Scan Logs/Production/<PC>/Entry Logs/entryAdmin_<PC>.txt, entryAM_<PC>.txt, entryPM_<PC>.txt
#   $REPORTS_ROOT/<Month> Scan Logs/Production/<PC>/Scan Logs/resultAdmin_<PC>.txt, resultAM_<PC>.txt, resultPM_<PC>.txt  (scan mode)

set -euo pipefail

# ---------------- CONFIG ----------------
ADMIN_IP="192.168.0.93"
SUBNET="192.168.0.0/24"
SUBNET_PREFIX="192.168.0"
SSH_USER="${SSH_USER:-admin2025}"
OUT_ROOT="${OUT_ROOT:-$HOME/audit-logs}"
DAYS=35
COLLECT_BROWSER=1
HOSTS_FILE="$(dirname "$(readlink -f "$0")")/hosts.txt"

# Shift accounts (the accounts being audited, not the SSH_USER collector account)
AM_USER="${AM_USER:-AM}"              # morning-shift account (matched case-insensitively)
PM_USER="${PM_USER:-PM}"              # afternoon-shift account (matched case-insensitively)
ADMIN_USER="${ADMIN_USER:-admin2025}"
SITE="${SITE:-}"                           # tracking-sheet columns that can't be detected (optional)
AREA="${AREA:-}"
DEPARTMENT="${DEPARTMENT:-}"
JOBS="${JOBS:-0}"                          # PCs processed at the same time: 0 = all at once, 1 = one by one
EXCLUDE_IPS="${EXCLUDE_IPS:-192.168.0.43}"             # hosts to skip, space/comma separated, e.g. "192.168.0.21 192.168.0.30"
REPORTS_ROOT="${REPORTS_ROOT:-$OUT_ROOT}"   # where "<Month> Scan Logs" is created (e.g. /media/kali/NEW)
ENV_FOLDER="Production"                    # folder under "<Month> Scan Logs"
SCAN_DAYS="${SCAN_DAYS:-30}"               # scan only files modified/changed in the last N days (0 = scan everything)
CLAM_SCAN="${CLAM_SCAN:-0}"           # 1 = also run clamscan on each account home (or use: ./script scan)
# ----------------------------------------

SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=8 -o StrictHostKeyChecking=accept-new -o ServerAliveInterval=30 -o ServerAliveCountMax=20)
REMOTE_BIN="/usr/local/sbin/audit-collect"

# ---- Embedded collector payload installed on target machines ----
write_collector() {
cat > "$1" <<'REMOTE'
#!/usr/bin/env bash
set -uo pipefail

DAYS="${1:-35}"; BROWSER="${2:-0}"
AM_USER="${3:-AM}"; PM_USER="${4:-PM}"; ADMIN_USER="${5:-admin2025}"
SCAN="${6:-0}"; SCAN_DAYS="${7:-0}"
[[ "$DAYS" =~ ^[0-9]+$ ]] || exit 2
[[ "$BROWSER" =~ ^[01]$ ]] || exit 2
[[ "$SCAN" =~ ^[01]$ ]] || exit 2
[[ "$SCAN_DAYS" =~ ^[0-9]+$ ]] || exit 2
for u in "$AM_USER" "$PM_USER" "$ADMIN_USER"; do
  [[ "$u" =~ ^[A-Za-z_][A-Za-z0-9_.-]*$ ]] || exit 2
done

W=$(mktemp -d /tmp/audit.XXXXXX) || exit 1
FRESH_WAS_ACTIVE=0
cleanup() {
  rm -rf "$W"
  [ "$FRESH_WAS_ACTIVE" -eq 1 ] && systemctl start clamav-freshclam.service 2>/dev/null
  return 0
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
mkdir -p "$W"/{auth,system,apps,browser}

resolve_user() {   # case-insensitive lookup of the real account name (AM vs am)
  local r
  r=$(getent passwd | cut -d: -f1 | grep -ixF -- "$1" | head -n1)
  echo "${r:-$1}"
}

# ---- Hardware / OS inventory for the monthly tracking sheet -> inventory.txt (key=value) ----
collect_inventory() {
  local inv="$W/inventory.txt" model short gen n mem sticks line name size rota serial type dev mac conn gpu osn
  model=$(lscpu 2>/dev/null | awk -F: '/Model name/ { gsub(/^[ \t]+/, "", $2); print $2; exit }')
  short="$model"; gen=""
  if [[ "$model" =~ (i[3579])-([0-9]{4,5}) ]]; then
    short="${BASH_REMATCH[1]}"; n="${BASH_REMATCH[2]}"
    if [ "${#n}" -eq 5 ]; then n="${n:0:2}"; else n="${n:0:1}"; fi
    case "$n" in 1) gen="1st";; 2) gen="2nd";; 3) gen="3rd";; *) gen="${n}th";; esac
  fi
  mem=$(awk '/MemTotal/ { printf "%d", ($2/1048576)+0.5 }' /proc/meminfo 2>/dev/null)
  sticks=$(dmidecode -t memory 2>/dev/null | awk '
    /^[ \t]+Size: [0-9]+ (MB|GB)/ { s=$2; if ($3=="MB") s=s/1024; c[s]++ }
    END { o=""; for (k in c) o = o (o ? "+" : "") c[k] "x" k " GB"; print o }')
  line=$(lsblk -dbnP -o NAME,SIZE,ROTA,SERIAL,TYPE,RM 2>/dev/null | grep 'TYPE="disk"' | grep 'RM="0"' | head -n1)
  name=$(sed -n 's/.*NAME="\([^"]*\)".*/\1/p' <<<"$line")
  size=$(sed -n 's/.*SIZE="\([^"]*\)".*/\1/p' <<<"$line")
  rota=$(sed -n 's/.*ROTA="\([^"]*\)".*/\1/p' <<<"$line")
  serial=$(sed -n 's/.*SERIAL="\([^"]*\)".*/\1/p' <<<"$line" | sed 's/[[:space:]]*$//')
  [ -n "$size" ] && size="$(awk -v b="$size" 'BEGIN { printf "%d", (b/1000000000)+0.5 }') GB"
  case "$name" in nvme*) type="NVMe SSD";; "") type="";; *) if [ "$rota" = "1" ]; then type="HDD"; else type="SSD"; fi;; esac
  gpu=$(lspci 2>/dev/null | grep -Ei 'vga compatible|3d controller|display controller' \
        | sed -E 's/^[^ ]+ [^:]+: //; s/ \(rev [0-9a-f]+\)//' | paste -sd';' -)
  osn=$( . /etc/os-release 2>/dev/null; echo "${NAME:-} ${VERSION_ID:-}" )
  dev=$(ip -o -4 route show to default 2>/dev/null | awk '{ print $5; exit }')
  mac=""; conn=""
  if [ -n "$dev" ]; then
    mac=$(cat "/sys/class/net/$dev/address" 2>/dev/null)
    if [ -d "/sys/class/net/$dev/wireless" ]; then conn="Wireless"; else conn="Wired"; fi
  fi
  {
    echo "cpu=$short"; echo "cpu_model=$model"; echo "cpu_gen=$gen"
    echo "memory=${mem:+${mem}GB}"; echo "sticks=$sticks"
    echo "disk_size=$size"; echo "disk_type=$type"; echo "disk_serial=$serial"
    echo "gpu=$gpu"; echo "os=$osn"; echo "mac=$mac"; echo "conn=$conn"
  } > "$inv"
}

# ---- Supervisor-format entry file for one account (login / failed login / sudo) ----
# usage: build_entry_file <Label> <username> <rawlogfile> <outfile>
build_entry_file() {
  local label="$1" user="$2" raw="$3" outf="$4" re mine lg fl sd
  user=$(resolve_user "$user")
  mine=$(mktemp); lg=$(mktemp); fl=$(mktemp); sd=$(mktemp)
  re="(user[= ]|for |by |logname=|sudo(\[[0-9]+\])?: )${user}([^A-Za-z0-9_-]|\$)"
  grep -iE "$re" "$raw" > "$mine"
  grep -Ev 'sudo(\[[0-9]+\])?:' "$mine" | grep -E 'New session|Accepted |:session\): session opened' > "$lg"
  grep -Ev 'sudo(\[[0-9]+\])?:' "$mine" | grep -Ei 'Failed password|authentication failure|FAILED LOGIN|invalid user|maximum authentication attempts|more authentication failures' > "$fl"
  grep -E 'sudo(\[[0-9]+\])?:' "$mine" > "$sd"
  show() { if [ -s "$1" ]; then cat "$1"; else echo "(none found)"; fi; }
  {
    echo "=== ENTRY LOG: $user ($label) | PC: $(hostname) | Generated: $(date '+%Y-%m-%d %H:%M:%S') ==="
    echo
    echo "--- login attempts (successful) ---"; show "$lg"
    if command -v last >/dev/null 2>&1; then
      echo; echo "--- login history (last) ---"; last -F -w "$user" 2>/dev/null
    fi
    echo
    echo "--- failed login attempts ---"; show "$fl"
    if command -v lastb >/dev/null 2>&1 && [ -f /var/log/btmp ]; then
      echo; echo "--- failed login history (lastb) ---"; lastb -F -w "$user" 2>/dev/null
    fi
    echo
    echo "--- sudo usage ---"; show "$sd"
    echo
    echo "=== Totals: logins $(wc -l < "$lg") | failed attempts $(wc -l < "$fl") | sudo lines $(wc -l < "$sd") ==="
  } > "$outf"
  rm -f "$mine" "$lg" "$fl" "$sd"
}

# Scan one home folder (read-only). SCAN_DAYS > 0 = only files modified or changed in the last N days.
scan_one() {
  local home="$1" out="$2" list
  if [ "$SCAN_DAYS" -gt 0 ]; then
    list=$(mktemp)
    find "$home" -type f \( -mtime "-$SCAN_DAYS" -o -ctime "-$SCAN_DAYS" \) 2>/dev/null > "$list"
    {
      echo "Scan scope: files modified or changed in the last $SCAN_DAYS days under $home"
      if [ -s "$list" ]; then
        # READ-ONLY scan: never add --remove / --move / --copy here
        clamscan --file-list="$list"
      else
        printf '\n----------- SCAN SUMMARY -----------\nScanned directories: 0\nScanned files: 0\nInfected files: 0\n(no files were modified or changed in this period)\n'
      fi
    } > "$out"
    rm -f "$list"
  else
    {
      echo "Scan scope: all files under $home"
      # READ-ONLY scan: never add --remove / --move / --copy here
      clamscan -r "$home"
    } > "$out"
  fi
}

# ---- ClamAV scan of each account home (same as the supervisor script) ----
run_clam_scans() {
  mkdir -p "$W/scan"
  if ! command -v clamscan >/dev/null 2>&1; then
    echo "clamscan not installed" > "$W/scan/NOT_INSTALLED.txt"; return 0
  fi
  if systemctl is-active --quiet clamav-freshclam.service 2>/dev/null; then
    FRESH_WAS_ACTIVE=1
    systemctl stop clamav-freshclam.service 2>/dev/null
  fi
  local pair label user home
  for pair in "Admin:$ADMIN_USER" "AM:$AM_USER" "PM:$PM_USER"; do
    label=${pair%%:*}; user=$(resolve_user "${pair#*:}")
    home=$(getent passwd "$user" | cut -d: -f6); home=${home:-/home/$user}
    if [ -d "$home" ]; then
      scan_one "$home" "$W/scan/result_$label.txt"
    else
      echo "Home folder not found: $home" > "$W/scan/result_$label.txt"
    fi
  done
  return 0
}

# ---- Shift account auditing (AM / PM / ADMIN) ----
# Writes auth/shift/{events.tsv,counts.tsv,stats.tsv,clamav_last_scan.txt}
collect_shift_logins() {
  local out="$W/auth/shift" raw t0
  raw="$out/.raw"
  mkdir -p "$out"; t0=$SECONDS

  # 1. Auth events with ISO timestamps: journal first, auth.log fallback
  if command -v journalctl >/dev/null 2>&1; then
    journalctl --since "$DAYS days ago" -o short-iso --no-pager -q \
      -t systemd-logind -t sshd -t sshd-session -t sudo -t su -t login \
      -t unix_chkpwd -t gdm-password -t lightdm -t sddm > "$raw" 2>/dev/null || true
  fi
  if [ ! -s "$raw" ]; then
    local cutoff; cutoff=$(date -d "-$DAYS days" +%F)
    for f in /var/log/auth.log*; do [ -r "$f" ] && zcat -f "$f"; done 2>/dev/null \
      | awk -v c="$cutoff" '$1 >= c' > "$raw" || true
  fi
  [ -e "$raw" ] || : > "$raw"

  # 2. Normalise to events.tsv: time, user, shift, event, flag, detail
  printf 'time\tuser\tshift\tevent\tdetail\n' > "$out/events.tsv"
  awk -v am="$AM_USER" -v pm="$PM_USER" -v ad="$ADMIN_USER" '
    function emit(ev, u,   sh, d, lu) {
      if (u == "" || u == "gdm") return          # gdm = login-screen greeter noise
      lu = tolower(u)
      sh = (lu==tolower(am)) ? "AM" : (lu==tolower(pm)) ? "PM" : (lu==tolower(ad)) ? "ADMIN" : "OTHER"
      d = $0; sub(/^[^ ]+ [^ ]+ /, "", d)
      printf "%s\t%s\t%s\t%s\t%s\n", $1, u, sh, ev, d
    }
    /New session [^ ]+ of user /    { u=$NF; sub(/\.$/, "", u); emit("LOGIN", u); next }
    /Accepted (password|publickey)/ { for (i=1;i<NF;i++) if ($i=="for") { emit("LOGIN", $(i+1)); break }; next }
    /Failed password for/           { for (i=1;i<NF;i++) if ($i=="for") { u=$(i+1); if (u=="invalid") u=$(i+3); emit("FAILED_LOGIN", u); break }; next }
    /authentication failure/ && / user=[^ ]/ {
      match($0, / user=[^ ]+/); u = substr($0, RSTART+6, RLENGTH-6)
      svc = "login"
      if (match($0, /pam_unix\([^:]+:auth\)/)) svc = substr($0, RSTART+9, RLENGTH-15)
      emit((svc=="sudo" || svc=="su") ? "FAILED_SUDO" : "FAILED_LOGIN", u); next
    }
    /NOT in sudoers|incorrect password attempt/ {
      for (i=2;i<=NF;i++) if ($i==":") { emit("FAILED_SUDO", $(i-1)); break }; next
    }
  ' "$raw" | sort -k1,1 >> "$out/events.tsv" || true

  # 2b. One file per account: AM_events.tsv, PM_events.tsv, ADMIN_events.tsv, OTHER_events.tsv
  for sh in AM PM ADMIN OTHER; do
    { head -n1 "$out/events.tsv"; awk -F'\t' -v s="$sh" 'NR>1 && $3==s' "$out/events.tsv"; } \
      > "$out/${sh}_events.tsv"
  done

  # 3. Per-account counts: shift, logins, failed logins, sudo failures
  awk -F'\t' '
    NR==1 { next }
    { k=$3; if (k!="AM" && k!="PM" && k!="ADMIN") k="OTHER"
      if ($4=="LOGIN") l[k]++
      else if ($4=="FAILED_LOGIN") f[k]++
      else if ($4=="FAILED_SUDO") s[k]++
      if (k=="OTHER" && $4!="LOGIN") oth[$2]++ }
    END { n=split("AM PM ADMIN OTHER", ks, " ")
          for (i=1;i<=n;i++) { k=ks[i]; printf "%s\t%d\t%d\t%d\n", k, l[k], f[k], s[k] }
          for (u in oth) printf "#other\t%s\t%d\n", u, oth[u] }
  ' "$out/events.tsv" > "$out/counts.tsv" || true

  # 4. Stats + last ClamAV scan summary (if clamscan logged one)
  printf 'log_lines\t%s\nseconds\t%s\n' "$(wc -l < "$raw")" "$((SECONDS - t0))" > "$out/stats.tsv"
  grep -h -A10 'SCAN SUMMARY' /var/log/clamav/*.log 2>/dev/null | tail -n 11 \
    > "$out/clamav_last_scan.txt" || true
  build_entry_file Admin "$ADMIN_USER" "$raw" "$out/entry_Admin.txt"
  build_entry_file AM    "$AM_USER"    "$raw" "$out/entry_AM.txt"
  build_entry_file PM    "$PM_USER"    "$raw" "$out/entry_PM.txt"
  rm -f "$raw"    # keep only extracted events, not the full raw auth log
}

# ---- Distribution & Host Telemetry ----
{
  echo "hostname=$(hostname 2>/dev/null || uname -n)"
  echo "collected_at=$(date -Is 2>/dev/null || date)"
  echo "window_days=$DAYS"
  if [ -f /etc/os-release ]; then
    . /etc/os-release
    echo "os=$PRETTY_NAME"
  elif command -v lsb_release >/dev/null 2>&1; then
    echo "os=$(lsb_release -ds)"
  else
    echo "os=$(uname -s)"
  fi
  echo "kernel=$(uname -r)"
  echo "ips=$(hostname -I 2>/dev/null || ip addr show | awk '/inet /{print $2}' | tr '\n' ' ')"
} > "$W/info.txt"

# ---- Authentication Logs ----
for logfile in /var/log/auth.log* /var/log/secure*; do
  [ -f "$logfile" ] && cp -p "$logfile" "$W/auth/" 2>/dev/null || true
done

# Failed logins: combines utmp/btmp with PAM, SSH, and GUI screen locker logs
{
  if command -v lastb >/dev/null 2>&1 && [ -f /var/log/btmp ]; then
    echo "=== UTMP / LASTB ENTRIES ==="
    lastb -F -w 2>/dev/null || true
    echo ""
  fi

  echo "=== SYSTEMD / PAM FAILED AUTHENTICATION ATTEMPTS ==="
  if command -v journalctl >/dev/null 2>&1; then
    journalctl --since "$DAYS days ago" --no-pager -o short-iso \
      | grep -Ei "pam_unix\(.*:auth\): authentication failure|password check failed|FAILED LOGIN|Failed password" \
      || echo "No PAM/auth failures recorded in systemd journal."
  else
    echo "journalctl not available."
  fi
} > "$W/auth/failed_logins_lastb.txt" 2>&1

# Successful logins
if command -v last >/dev/null 2>&1; then
  last -F -w > "$W/auth/logins_last.txt" 2>&1 || last > "$W/auth/logins_last.txt" 2>&1 || true
fi

# systemd auth journal extraction (covers GDM, LightDM, SDDM, SSH, and PAM sessions)
if command -v journalctl >/dev/null 2>&1; then
  journalctl --since "$DAYS days ago" -o short-iso --no-pager \
    _SYSTEMD_UNIT=ssh.service _SYSTEMD_UNIT=sshd.service \
    _SYSTEMD_UNIT=systemd-logind.service _SYSTEMD_UNIT=gdm.service \
    _SYSTEMD_UNIT=lightdm.service _SYSTEMD_UNIT=sddm.service \
    > "$W/auth/journal_auth.txt" 2>&1 || true
fi

[ -d /var/log/audit ] && cp -rp /var/log/audit "$W/auth/auditd" 2>/dev/null || true

# AM / PM / ADMIN account breakdown
collect_shift_logins
collect_inventory
[ "$SCAN" -eq 1 ] && run_clam_scans

# ---- System Logs ----
for sysfile in /var/log/syslog* /var/log/messages* /var/log/kern.log* /var/log/ufw.log* /var/log/firewalld*; do
  [ -f "$sysfile" ] && cp -p "$sysfile" "$W/system/" 2>/dev/null || true
done

if command -v journalctl >/dev/null 2>&1; then
  journalctl --since "$DAYS days ago" -o short-iso --no-pager -p warning > "$W/system/journal_warnings.txt" 2>&1 || true
  journalctl --list-boots --no-pager > "$W/system/boots.txt" 2>&1 || true
fi

# ---- Cross-Distro Package Management ----
if command -v dpkg-query >/dev/null 2>&1; then
  dpkg-query -W -f='${Package}\t${Version}\n' > "$W/apps/installed_packages.tsv" 2>/dev/null || true
  cp -p /var/log/dpkg.log* /var/log/apt/history.log* "$W/apps/" 2>/dev/null || true
elif command -v rpm >/dev/null 2>&1; then
  rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\n' | sort > "$W/apps/installed_packages.tsv" 2>/dev/null || true
  cp -p /var/log/dnf.log* /var/log/yum.log* "$W/apps/" 2>/dev/null || true
elif command -v pacman >/dev/null 2>&1; then
  pacman -Q > "$W/apps/installed_packages.tsv" 2>/dev/null || true
  cp -p /var/log/pacman.log* "$W/apps/" 2>/dev/null || true
elif command -v zypper >/dev/null 2>&1; then
  zypper se --installed-only > "$W/apps/installed_packages.tsv" 2>/dev/null || true
  cp -p /var/log/zypp/history* "$W/apps/" 2>/dev/null || true
fi

command -v snap >/dev/null 2>&1 && snap list > "$W/apps/snaps.txt" 2>/dev/null || true
command -v flatpak >/dev/null 2>&1 && flatpak list > "$W/apps/flatpaks.txt" 2>/dev/null || true
[ -d /var/log/clamav ] && cp -rp /var/log/clamav "$W/apps/clamav" 2>/dev/null || true
[ -f /var/log/rkhunter.log ] && cp -p /var/log/rkhunter.log* "$W/apps/" 2>/dev/null || true

# ---- Browser History Collection ----
if [ "$BROWSER" -eq 1 ]; then
  find /home -maxdepth 6 -type f \( -name "places.sqlite" -o -name "History" \) 2>/dev/null | while IFS= read -r db; do
    d=$(dirname "$db")
    b=$(basename "$db")
    safe=$(echo "$d" | sed 's#^/home/##; s#/#__#g')
    target_dir="$W/browser/$safe"
    mkdir -p "$target_dir"

    if command -v sqlite3 >/dev/null 2>&1; then
      sqlite3 "file:$db?immutable=1" ".backup '$target_dir/$b'" 2>/dev/null || cp -p "$db" "$target_dir/" 2>/dev/null || true
    else
      for s in "" -wal -journal -shm; do
        [ -f "$d/$b$s" ] && cp -p "$d/$b$s" "$target_dir/" 2>/dev/null || true
      done
    fi
  done
fi

tar -czf - -C "$W" .
REMOTE
}

discover_hosts_raw() {
  if [ -f "$HOSTS_FILE" ]; then
    grep -Ev '^\s*(#|$)' "$HOSTS_FILE" | grep -vx "$ADMIN_IP"
    return
  fi
  if command -v nmap >/dev/null 2>&1; then
    nmap -n -p22 --open -oG - "$SUBNET" | awk '/22\/open/{print $2}' | grep -vx "$ADMIN_IP" | sort -V
  else
    for i in $(seq 1 254); do
      ip="$SUBNET_PREFIX.$i"
      ( timeout 1 bash -c "</dev/tcp/$ip/22" 2>/dev/null && echo "$ip" ) &
    done | grep -vx "$ADMIN_IP" | sort -V
    wait
  fi
}

# discover_hosts = discovery minus anything listed in EXCLUDE_IPS
discover_hosts() {
  local out
  out=$(discover_hosts_raw) || true
  if [ -n "${EXCLUDE_IPS//[ ,]/}" ]; then
    out=$(printf '%s\n' "$out" | grep -vxF -f <(printf '%s\n' ${EXCLUDE_IPS//,/ }) || true)
  fi
  [ -n "$out" ] && printf '%s\n' "$out"
  return 0
}

extract_history() {
  local dest="$1" dir name
  shopt -s nullglob
  for dir in "$dest"/browser/*/; do
    name=$(basename "$dir")
    if [ -f "$dir/places.sqlite" ]; then
      sqlite3 -csv -header "file:$dir/places.sqlite?immutable=1" \
        "SELECT datetime(v.visit_date/1000000,'unixepoch') AS visited_utc, p.url, p.title
         FROM moz_historyvisits v JOIN moz_places p ON p.id=v.place_id
         WHERE v.visit_date >= strftime('%s','now','-$DAYS days')*1000000
         ORDER BY v.visit_date;" > "$dest/browser_history_firefox_${name}.csv" 2>>"$dest/errors.log" || true
    fi
    if [ -f "$dir/History" ]; then
      sqlite3 -csv -header "file:$dir/History?immutable=1" \
        "SELECT datetime(v.visit_time/1000000-11644473600,'unixepoch') AS visited_utc, u.url, u.title
         FROM visits v JOIN urls u ON u.id=v.url
         WHERE (v.visit_time/1000000-11644473600) >= strftime('%s','now','-$DAYS days')
         ORDER BY v.visit_time;" > "$dest/browser_history_chromium_${name}.csv" 2>>"$dest/errors.log" || true
    fi
  done
  shopt -u nullglob
  rm -rf "$dest/browser"
}

# ---------- Monthly tracking sheet (CSV in the same column order as the sheet) ----------
csvq() { local v="${1//\"/\"\"}"; printf '"%s"' "$v"; }
inv_get() { awk -F= -v k="$2" '$1==k { sub(/^[^=]*=/, ""); print; exit }' "$1" 2>/dev/null; }

init_sheet_csv() {
  local mname m mm
  mname=$(LC_ALL=C date +%B); m=$(date +%-m); mm=$(date +%m)
  SHEET_CSV="$REPORTS_ROOT/$mname Scan Logs/scan_log_${mname}.csv"
  mkdir -p "$(dirname "$SHEET_CSV")"
  local header="Site,Area,Department,Hostname,Processor,Processor Generation,Memory,Number of Memory Stick,Storage Capacity,Storage Type,Storage Serial,GPU,OS,Compatible with windows 11,OS Activated,IP Address,MAC Address,Connectiontype,${mname} Status,ScanLog${m},Date${mm},Infected File Count${mm},Scanned Files${mm},Infected File Remarks${mm},Invalid Entry${mm},Invalid Entry Remarks${mm},System Update${mm},Date0${mm},Ping Test${m},Date00${mm},SpeedTest${m},Date000${mm},Crimp Eval${m},Date0000${mm}"
  if [ -f "$SHEET_CSV" ]; then
    [ "$(head -n1 "$SHEET_CSV")" = "$header" ] && return 0
    mv "$SHEET_CSV" "$SHEET_CSV.old-layout.bak"      # columns changed: keep the old file, start a new one
  fi
  printf '%s\n' "$header" > "$SHEET_CSV"
}

# usage: append_sheet_row <host_dir> <hostname> <ip>   (re-running replaces that host's row)
append_sheet_row() {
  local dest="$1" pc="$2" ip="$3" inv="$dest/inventory.txt" cnt="$dest/auth/shift/counts.tsv"
  local scan_done="" inf="" scanned="" inf_rem="" inv_n="" inv_rem="" parts="" others="" L c f row tmp
  local -a res=()
  shopt -s nullglob; res=("$dest"/scan/result_*.txt); shopt -u nullglob

  # ClamAV columns (only filled when the scan mode was used)
  if [ -f "$dest/scan/NOT_INSTALLED.txt" ]; then
    scan_done="ClamAV not installed"
  elif [ "${#res[@]}" -gt 0 ]; then
    if grep -q 'SCAN SUMMARY' "${res[@]}" 2>/dev/null; then scan_done="Done"; else scan_done="Not completed"; fi
    inf=$(grep -h 'Infected files' "${res[@]}" 2>/dev/null | awk '{ s += $3 } END { print s+0 }' || true)
    scanned=$(grep -h '^Scanned files:' "${res[@]}" 2>/dev/null | awk '{ s += $3 } END { print s+0 }' || true)
    for L in Admin AM PM; do
      f="$dest/scan/result_$L.txt"; [ -f "$f" ] || continue
      c=$(grep -h 'Infected files' "$f" 2>/dev/null | awk '{ print $3 }' | head -n1 || true)
      parts+="${parts:+, }$L ${c:-n/a}"
    done
    if [ "${inf:-0}" -eq 0 ]; then
      inf_rem="n/a"
    else
      # name the infected files (clamscan prints "<path>: <signature> FOUND")
      local found nfound list
      found=$(grep -h ' FOUND$' "${res[@]}" 2>/dev/null | sed 's/ FOUND$//' || true)
      nfound=$(printf '%s\n' "$found" | grep -c . || true)
      list=$(printf '%s\n' "$found" | head -n 3 | paste -sd';' - || true)
      [ "${nfound:-0}" -gt 3 ] && list+="; +$((nfound - 3)) more"
      inf_rem="Infected files found ($parts): ${list:-see Scan Logs} - see Scan Logs"
    fi
  fi

  # Invalid entries = failed logins + failed sudo attempts (all accounts)
  if [ -f "$cnt" ]; then
    parts=""
    read -r inv_n parts < <(awk -F'\t' '!/^#/ { n=$3+$4; t+=n; if (n>0) p=p (p ? ", " : "") $1 " " n } END { print t+0, p }' "$cnt")
    others=$(awk -F'\t' '/^#other/ { printf "%s%s", (c++ ? "," : ""), $2 }' "$cnt")
    if [ "${inv_n:-0}" -eq 0 ]; then inv_rem="None"
    else
      inv_rem="$inv_n failed attempts ($parts)"
      [ -n "$others" ] && inv_rem+="; other accounts: $others"
      inv_rem+=" - needs review"
    fi
  fi

  row=""
  for f in "$SITE" "$AREA" "$DEPARTMENT" "$pc" \
           "$(inv_get "$inv" cpu)" "$(inv_get "$inv" cpu_gen)" "$(inv_get "$inv" memory)" "$(inv_get "$inv" sticks)" \
           "$(inv_get "$inv" disk_size)" "$(inv_get "$inv" disk_type)" "$(inv_get "$inv" disk_serial)" \
           "$(inv_get "$inv" gpu)" "$(inv_get "$inv" os)" "" "" \
           "$ip" "$(inv_get "$inv" mac)" "$(inv_get "$inv" conn)" "Active" \
           "$scan_done" "$(date +%F)" "$inf" "$scanned" "$inf_rem" "$inv_n" "$inv_rem" \
           "" "" "" "" "" "" "" ""; do
    row+="${row:+,}$(csvq "$f")"
  done

  tmp=$(mktemp)
  grep -vE "^([^,]*,){3}\"${pc}\"," "$SHEET_CSV" > "$tmp" || true
  printf '%s\n' "$row" >> "$tmp"
  cat "$tmp" > "$SHEET_CSV"; rm -f "$tmp"
  return 0
}

# File the per-account reports in the monthly layout:
#   <Month> Scan Logs/Production/<PC>/Entry Logs/entry<Label>_<PC>.txt
#   <Month> Scan Logs/Production/<PC>/Scan Logs/result<Label>_<PC>.txt
export_reports() {
  local dest="$1" pc="$2" L base="$REPORT_BASE/$2"
  mkdir -p "$base/Entry Logs"
  for L in Admin AM PM; do
    [ -f "$dest/auth/shift/entry_$L.txt" ] && cp "$dest/auth/shift/entry_$L.txt" "$base/Entry Logs/entry${L}_${pc}.txt"
    if [ -f "$dest/scan/result_$L.txt" ]; then
      mkdir -p "$base/Scan Logs"
      cp "$dest/scan/result_$L.txt" "$base/Scan Logs/result${L}_${pc}.txt"
    fi
  done
  return 0
}

collect_host() {
  local ip="$1" name dest
  name=$(ssh -n "${SSH_OPTS[@]}" "$SSH_USER@$ip" "hostname 2>/dev/null || uname -n" 2>/dev/null) || {
    echo "FAIL  $ip  (cannot connect via SSH)"
    return 1
  }
  name=${name//[^A-Za-z0-9._-]/_}
  dest="$RUN_DIR/${name}_${ip}"
  mkdir -p "$dest"

  if ssh -n "${SSH_OPTS[@]}" "$SSH_USER@$ip" \
       "sudo -n $REMOTE_BIN '$DAYS' '$COLLECT_BROWSER' '$AM_USER' '$PM_USER' '$ADMIN_USER' '$CLAM_SCAN' '$SCAN_DAYS'" \
       2>"$dest/collect.err" \
       | tar -xzf - -C "$dest" --no-same-owner 2>>"$dest/collect.err"; then
    [ "$COLLECT_BROWSER" -eq 1 ] && extract_history "$dest"
    export_reports "$dest" "$name"
    if command -v flock >/dev/null 2>&1; then
      ( flock 9; append_sheet_row "$dest" "$name" "$ip" ) 9>"$SHEET_CSV.lock"
    else
      append_sheet_row "$dest" "$name" "$ip"
    fi
    [ -s "$dest/collect.err" ] || rm -f "$dest/collect.err"
    echo "OK    $ip  -> $dest"
  else
    echo "FAIL  $ip  (collector execution failed, check $dest/collect.err)"
    return 1
  fi
}

# ClamAV-style fleet summary (printed to terminal and appended to summary.txt by the caller)
# usage: build_fleet_summary <run_dir> <start_ts> <t0_seconds> <summary_file>
build_fleet_summary() {
  local run_dir="$1" start_ts="$2" t0="$3" sfile="$4"
  local elapsed hosts failed lines infected scanned size c host inf_label
  local -a counts stats clams scans
  shopt -s nullglob
  counts=("$run_dir"/*/auth/shift/counts.tsv)
  stats=("$run_dir"/*/auth/shift/stats.tsv)
  clams=("$run_dir"/*/auth/shift/clamav_last_scan.txt)
  scans=("$run_dir"/*/scan/result_*.txt)
  shopt -u nullglob

  elapsed=$((SECONDS - t0))
  hosts=${#counts[@]}
  failed=$(grep -c '^FAIL' "$sfile" || true)
  lines=0; infected=0
  if [ "${#stats[@]}" -gt 0 ]; then
    lines=$(cat "${stats[@]}" | awk -F'\t' '$1=="log_lines" { s += $2 } END { print s+0 }' || true)
  fi
  scanned=0
  if [ "${#scans[@]}" -gt 0 ]; then
    scanned=$(grep -h '^Scanned files:' "${scans[@]}" 2>/dev/null | awk '{ s += $3 } END { print s+0 }' || true)
  fi
  inf_label="last scans"
  if [ "${#scans[@]}" -gt 0 ]; then
    inf_label="this run"
    infected=$(grep -h 'Infected files' "${scans[@]}" 2>/dev/null | awk '{ s += $3 } END { print s+0 }' || true)
  elif [ "${#clams[@]}" -gt 0 ]; then
    infected=$(grep -h 'Infected files' "${clams[@]}" 2>/dev/null | awk '{ s += $3 } END { print s+0 }' || true)
  fi
  size=$(du -sh "$run_dir" 2>/dev/null | cut -f1 || true)

  echo
  echo "----------- AUDIT SUMMARY -----------"
  echo "Hosts audited: $hosts (failed: $failed)"
  echo "Accounts audited: AM ($AM_USER), PM ($PM_USER), ADMIN ($ADMIN_USER)"
  echo "Log window: $DAYS days"
  echo "Scanned log lines: $lines"
  if [ "$hosts" -gt 0 ]; then
    cat "${counts[@]}" | awk -F'\t' '
      /^#/ { next }
      { l[$1]+=$2; f[$1]+=$3; s[$1]+=$4; TL+=$2; TF+=$3; TS+=$4 }
      END { n=split("AM PM ADMIN OTHER", ks, " ")
            for (i=1;i<=n;i++) { k=ks[i]
              printf "%-6s logins: %d | failed logins: %d | sudo failures: %d\n", k, l[k], f[k], s[k] }
            printf "Total logins: %d\nFailed login attempts: %d\nSudo failures: %d\n", TL, TF, TS }' || true
  fi
  if [ "${#scans[@]}" -gt 0 ]; then
    if [ "$SCAN_DAYS" -gt 0 ]; then echo "ClamAV scan scope: files modified/changed in the last $SCAN_DAYS days"; else echo "ClamAV scan scope: all files"; fi
  fi
  echo "ClamAV scanned files (this run): $scanned"
  echo "ClamAV infected files ($inf_label): $infected"
  echo "Data collected: $size"
  printf 'Time: %d sec (%d m %d s)\n' "$elapsed" "$((elapsed/60))" "$((elapsed%60))"
  echo "Start Date: $start_ts"
  echo "End Date:   $(date '+%Y:%m:%d %H:%M:%S')"

  echo
  echo "----------- PER-HOST DETAIL -----------"
  for c in "${counts[@]}"; do
    host=$(basename "$(dirname "$(dirname "$(dirname "$c")")")")
    echo "[$host]"
    awk -F'\t' '/^#other/ { printf "  other account: %s (%d failed events)\n", $2, $3; next }
                { printf "  %-6s logins: %d | failed: %d | sudo failures: %d\n", $1,$2,$3,$4 }' "$c" || true
    grep -h ' FOUND$' "$(dirname "$(dirname "$(dirname "$c")")")"/scan/result_*.txt 2>/dev/null \
      | sed 's/^/  INFECTED: /' || true
  done
}

setup_host() {
  local ip="$1" tmp="$2"
  echo ">>> Configuring $ip..."
  ssh-copy-id -o ConnectTimeout=8 -o StrictHostKeyChecking=accept-new "$SSH_USER@$ip" || return 1
  scp -q -o ConnectTimeout=8 "$tmp" "$SSH_USER@$ip:/tmp/audit-collect.new" || return 1
  ssh -t -o ConnectTimeout=8 "$SSH_USER@$ip" bash -c "'
    sudo install -m 0750 -o root -g root /tmp/audit-collect.new $REMOTE_BIN &&
    rm -f /tmp/audit-collect.new &&
    echo \"$SSH_USER ALL=(root) NOPASSWD: $REMOTE_BIN\" | sudo tee /etc/sudoers.d/audit-collect.tmp >/dev/null &&
    sudo chmod 0440 /etc/sudoers.d/audit-collect.tmp &&
    sudo visudo -cf /etc/sudoers.d/audit-collect.tmp &&
    sudo mv /etc/sudoers.d/audit-collect.tmp /etc/sudoers.d/audit-collect
  '"
}

no_hosts_help() {
  cat >&2 <<HELP
No SSH-reachable hosts were found, so nothing was collected.
Check:
  1. Admin PC network:  ip -4 addr   (is it really on $SUBNET? ADMIN_IP=$ADMIN_IP)
  2. Target PCs are on and running SSH:  sudo systemctl status ssh
  3. Test one PC by hand:  ssh $SSH_USER@<pc-ip>
  4. Or list the PCs yourself, one IP per line, in:  $HOSTS_FILE
HELP
}

MODE="${1:-collect}"

case "$MODE" in
  list)
    discover_hosts
    ;;
  setup)
    [ -f "$HOME/.ssh/id_ed25519" ] || ssh-keygen -t ed25519 -N "" -f "$HOME/.ssh/id_ed25519"
    TMP=$(mktemp)
    trap 'rm -f "$TMP"' EXIT
    write_collector "$TMP"
    mapfile -t HOSTS < <(discover_hosts)
    [ "${#HOSTS[@]}" -gt 0 ] || { no_hosts_help; exit 1; }
    echo "Found ${#HOSTS[@]} host(s) to provision."
    for ip in "${HOSTS[@]}"; do
      setup_host "$ip" "$TMP" && echo "  Setup complete: $ip" || echo "  Setup failed: $ip"
    done
    ;;
  collect|scan)
    [ "$MODE" = "scan" ] && CLAM_SCAN=1
    REPORT_BASE="$REPORTS_ROOT/$(LC_ALL=C date +%B) Scan Logs/$ENV_FOLDER"
    init_sheet_csv
    if [ "$COLLECT_BROWSER" -eq 1 ] && ! command -v sqlite3 >/dev/null; then
      echo "Error: sqlite3 required on admin host when COLLECT_BROWSER=1." >&2
      exit 1
    fi
    START_TS=$(date '+%Y:%m:%d %H:%M:%S')
    T0=$SECONDS
    RUN_DIR="$OUT_ROOT/$(date +%F)"
    mkdir -p "$RUN_DIR"
    chmod 700 "$RUN_DIR"
    mapfile -t HOSTS < <(discover_hosts)
    [ "${#HOSTS[@]}" -gt 0 ] || { no_hosts_help; exit 1; }
    if [ "$JOBS" -eq 0 ]; then par="all at once"; else par="$JOBS at a time"; fi
    echo "Collecting from ${#HOSTS[@]} host(s) ($par) into $RUN_DIR..."

    summary_file="$RUN_DIR/summary.txt"
    : > "$summary_file"

    for ip in "${HOSTS[@]}"; do
      if [ "$JOBS" -gt 0 ]; then
        while [ "$(jobs -rp | wc -l)" -ge "$JOBS" ]; do sleep 1; done
      fi
      echo "START $ip"
      { collect_host "$ip" || true; } | tee -a "$summary_file" &
    done
    wait
    rm -f "$SHEET_CSV.lock"

    ok_count=$(grep -c '^OK' "$summary_file" || true)
    fail_count=$(grep -c '^FAIL' "$summary_file" || true)

    build_fleet_summary "$RUN_DIR" "$START_TS" "$T0" "$summary_file" | tee -a "$summary_file"

    chmod -R go-rwx "$RUN_DIR"
    echo "Run finished. Success: $ok_count | Failed: $fail_count"
    if [ -d "$REPORT_BASE" ]; then
      chmod -R go-rwx "$REPORTS_ROOT/$(LC_ALL=C date +%B) Scan Logs" 2>/dev/null || true
      echo "Entry/Scan log folders: $REPORT_BASE/<PC>/"
      echo "Tracking-sheet rows:    $SHEET_CSV"
      [ "$CLAM_SCAN" = "1" ] || echo "Note: ScanLog / Scanned Files / Infected File columns stay blank in collect mode - run: $0 scan"
    fi
    ;;
  *)
    echo "Usage: $0 {list|setup|collect|scan}"
    exit 1
    ;;
esac
