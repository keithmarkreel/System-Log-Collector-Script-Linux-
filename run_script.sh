#!/usr/bin/env bash
# collect_audit_logs.sh / script_flipside.sh
# Run on the admin PC (192.168.0.93).
# Pulls auth/system/app logs and browser history from workstations into:
#   $OUT_ROOT/<YYYY-MM-DD>/<pc-hostname>_<pc-ip>/
#
# Usage:
#   ./script_flipside.sh list       # show which hosts would be contacted
#   ./script_flipside.sh setup      # ONE-TIME (or update): install SSH key + collector on each PC
#   ./script_flipside.sh collect    # sequential collection run

set -euo pipefail

# ---------------- CONFIG ----------------
ADMIN_IP="192.168.0.93"
SUBNET="192.168.0.0/24"
SUBNET_PREFIX="192.168.0"
SSH_USER="${SSH_USER:-kali}"
OUT_ROOT="${OUT_ROOT:-$HOME/audit-logs}"
DAYS=35
COLLECT_BROWSER=1
HOSTS_FILE="$(dirname "$(readlink -f "$0")")/hosts.txt"
# ----------------------------------------

SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=8 -o StrictHostKeyChecking=accept-new)
REMOTE_BIN="/usr/local/sbin/audit-collect"

# ---- Embedded collector payload installed on target machines ----
write_collector() {
cat > "$1" <<'REMOTE'
#!/usr/bin/env bash
set -uo pipefail

DAYS="${1:-35}"; BROWSER="${2:-0}"
[[ "$DAYS" =~ ^[0-9]+$ ]] || exit 2
[[ "$BROWSER" =~ ^[01]$ ]] || exit 2

W=$(mktemp -d /tmp/audit.XXXXXX) || exit 1
trap 'rm -rf "$W"' EXIT
mkdir -p "$W"/{auth,system,apps,browser}

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

discover_hosts() {
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

collect_host() {
  local ip="$1" name dest
  name=$(ssh -n "${SSH_OPTS[@]}" "$SSH_USER@$ip" "hostname 2>/dev/null || uname -n" 2>/dev/null) || {
    echo "FAIL  $ip  (cannot connect via SSH)"
    return 1
  }
  name=${name//[^A-Za-z0-9._-]/_}
  dest="$RUN_DIR/${name}_${ip}"
  mkdir -p "$dest"

  if ssh -n "${SSH_OPTS[@]}" "$SSH_USER@$ip" "sudo -n $REMOTE_BIN '$DAYS' '$COLLECT_BROWSER'" 2>"$dest/collect.err" \
       | tar -xzf - -C "$dest" --no-same-owner 2>>"$dest/collect.err"; then
    [ "$COLLECT_BROWSER" -eq 1 ] && extract_history "$dest"
    [ -s "$dest/collect.err" ] || rm -f "$dest/collect.err"
    echo "OK    $ip  -> $dest"
  else
    echo "FAIL  $ip  (collector execution failed, check $dest/collect.err)"
    return 1
  fi
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
    echo "Found ${#HOSTS[@]} host(s) to provision."
    for ip in "${HOSTS[@]}"; do
      setup_host "$ip" "$TMP" && echo "  Setup complete: $ip" || echo "  Setup failed: $ip"
    done
    ;;
  collect)
    if [ "$COLLECT_BROWSER" -eq 1 ] && ! command -v sqlite3 >/dev/null; then
      echo "Error: sqlite3 required on admin host when COLLECT_BROWSER=1." >&2
      exit 1
    fi
    RUN_DIR="$OUT_ROOT/$(date +%F)"
    mkdir -p "$RUN_DIR"
    chmod 700 "$RUN_DIR"
    mapfile -t HOSTS < <(discover_hosts)
    echo "Collecting sequentially from ${#HOSTS[@]} host(s) into $RUN_DIR..."

    summary_file="$RUN_DIR/summary.txt"
    : > "$summary_file"

    for ip in "${HOSTS[@]}"; do
      collect_host "$ip" | tee -a "$summary_file"
    done

    chmod -R go-rwx "$RUN_DIR"
    echo "Run finished. Success: $(grep -c '^OK' "$summary_file") | Failed: $(grep -c '^FAIL' "$summary_file")"
    ;;
  *)
    echo "Usage: $0 {list|setup|collect}"
    exit 1
    ;;
esac