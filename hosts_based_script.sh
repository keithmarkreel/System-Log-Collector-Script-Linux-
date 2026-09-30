#!/usr/bin/env bash
# collect_audit_manual.sh
# Controlled pilot version with interactive username fallback & auto-saving to hosts.txt.
#
# Usage:
#   ./collect_audit_manual.sh list       # inspect targets loaded from hosts.txt
#   ./collect_audit_manual.sh setup      # interactive setup (updates hosts.txt with correct users)
#   ./collect_audit_manual.sh collect    # sequential collection run

set -euo pipefail

# ---------------- CONFIG ----------------
ADMIN_IP="192.168.0.93"
DEFAULT_SSH_USER="${SSH_USER:-kali}"
OUT_ROOT="${OUT_ROOT:-$HOME/audit-logs}"
DAYS=35
COLLECT_BROWSER=1
HOSTS_FILE="$(dirname "$(readlink -f "$0")")/hosts.txt"
# ----------------------------------------

SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=8 -o StrictHostKeyChecking=accept-new)
REMOTE_BIN="/usr/local/sbin/audit-collect"

# ---- Load & parse hosts.txt ----
load_target_hosts() {
  if [ ! -f "$HOSTS_FILE" ]; then
    echo "ERROR: Inventory file not found: $HOSTS_FILE" >&2
    echo "Create it first: echo '192.168.0.223' > hosts.txt" >&2
    exit 1
  fi

  mapfile -t RAW_HOSTS < <(grep -Ev '^\s*(#|$)' "$HOSTS_FILE" || true)

  HOSTS=()
  for entry in "${RAW_HOSTS[@]}"; do
    local user ip
    if [[ "$entry" =~ ^(.*)@(.*)$ ]]; then
      user="${BASH_REMATCH[1]}"
      ip="${BASH_REMATCH[2]}"
    else
      user="$DEFAULT_SSH_USER"
      ip="$entry"
    fi

    # Discard local admin PC from targets
    if [ "$ip" != "$ADMIN_IP" ]; then
      HOSTS+=("$user@$ip")
    fi
  done

  if [ "${#HOSTS[@]}" -eq 0 ]; then
    echo "ERROR: $HOSTS_FILE contains no valid target entries." >&2
    exit 1
  fi
}

# ---- Update hosts.txt with the confirmed username ----
update_hosts_file() {
  local ip="$1" confirmed_user="$2"
  local tmp_file
  tmp_file=$(mktemp)

  while IFS= read -r line || [ -n "$line" ]; do
    # Skip comments and empty lines as-is
    if [[ "$line" =~ ^\s*(#|$) ]]; then
      echo "$line" >> "$tmp_file"
      continue
    fi

    # Strip existing user if present
    local line_ip="${line#*@}"
    if [ "$line_ip" = "$ip" ]; then
      echo "${confirmed_user}@${ip}" >> "$tmp_file"
    else
      echo "$line" >> "$tmp_file"
    fi
  done < "$HOSTS_FILE"

  mv "$tmp_file" "$HOSTS_FILE"
}

# ---- The collector script payload ----
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

# Telemetry
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

# Authentication records
for logfile in /var/log/auth.log* /var/log/secure*; do
  [ -f "$logfile" ] && cp -p "$logfile" "$W/auth/" 2>/dev/null || true
done

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

if command -v last >/dev/null 2>&1; then
  last -F -w > "$W/auth/logins_last.txt" 2>&1 || last > "$W/auth/logins_last.txt" 2>&1 || true
fi

if command -v journalctl >/dev/null 2>&1; then
  journalctl --since "$DAYS days ago" -o short-iso --no-pager \
    _SYSTEMD_UNIT=ssh.service _SYSTEMD_UNIT=sshd.service \
    _SYSTEMD_UNIT=systemd-logind.service _SYSTEMD_UNIT=gdm.service \
    _SYSTEMD_UNIT=lightdm.service _SYSTEMD_UNIT=sddm.service \
    > "$W/auth/journal_auth.txt" 2>&1 || true
fi

[ -d /var/log/audit ] && cp -rp /var/log/audit "$W/auth/auditd" 2>/dev/null || true

# System logs
for sysfile in /var/log/syslog* /var/log/messages* /var/log/kern.log* /var/log/ufw.log* /var/log/firewalld*; do
  [ -f "$sysfile" ] && cp -p "$sysfile" "$W/system/" 2>/dev/null || true
done

if command -v journalctl >/dev/null 2>&1; then
  journalctl --since "$DAYS days ago" -o short-iso --no-pager -p warning > "$W/system/journal_warnings.txt" 2>&1 || true
  journalctl --list-boots --no-pager > "$W/system/boots.txt" 2>&1 || true
fi

# Package inventory
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

# Browser history
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

# ---- Data reduction for browser history ----
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

# ---- Collection execution per PC ----
collect_host() {
  local target="$1" user ip name dest
  user="${target%@*}"
  ip="${target#*@}"

  name=$(ssh -n "${SSH_OPTS[@]}" "$user@$ip" "hostname 2>/dev/null || uname -n" 2>/dev/null) || {
    echo "FAIL  $target  (cannot connect via SSH: run 'setup' first)"
    return 1
  }
  name=${name//[^A-Za-z0-9._-]/_}
  dest="$RUN_DIR/${name}_${ip}"
  mkdir -p "$dest"

  if ssh -n "${SSH_OPTS[@]}" "$user@$ip" "sudo -n $REMOTE_BIN '$DAYS' '$COLLECT_BROWSER'" 2>"$dest/collect.err" \
       | tar -xzf - -C "$dest" --no-same-owner 2>>"$dest/collect.err"; then
    [ "$COLLECT_BROWSER" -eq 1 ] && extract_history "$dest"
    [ -s "$dest/collect.err" ] || rm -f "$dest/collect.err"
    echo "OK    $target  -> $dest"
  else
    echo "FAIL  $target  (execution failed, check $dest/collect.err)"
    return 1
  fi
}

# ---- Interactive Setup with Prompting Fallback ----
setup_host() {
  local target="$1" tmp="$2" user ip
  user="${target%@*}"
  ip="${target#*@}"

  echo "----------------------------------------------------"
  echo ">>> Attempting setup on $ip using account: '$user'"

  # Try default/specified account
  if ! ssh-copy-id -o ConnectTimeout=5 -o StrictHostKeyChecking=accept-new "$user@$ip"; then
    echo ""
    echo "[!] Could not authenticate as '$user' on $ip."
    read -rp "--> Enter the correct admin username for $ip (or press Enter to skip): " manual_user
    
    if [ -z "$manual_user" ]; then
      echo "[-] Skipped $ip."
      return 1
    fi
    user="$manual_user"

    echo ">>> Retrying key installation as '$user@$ip'..."
    ssh-copy-id -o ConnectTimeout=8 -o StrictHostKeyChecking=accept-new "$user@$ip" || return 1
  fi

  echo ">>> Installing collector binary on $ip..."
  scp -q -o ConnectTimeout=8 "$tmp" "$user@$ip:/tmp/audit-collect.new" || return 1

  echo ">>> Configuring passwordless sudo policy for /usr/local/sbin/audit-collect..."
  ssh -t -o ConnectTimeout=8 "$user@$ip" bash -c "'
    sudo install -m 0750 -o root -g root /tmp/audit-collect.new $REMOTE_BIN &&
    rm -f /tmp/audit-collect.new &&
    echo \"$user ALL=(root) NOPASSWD: $REMOTE_BIN\" | sudo tee /etc/sudoers.d/audit-collect.tmp >/dev/null &&
    sudo chmod 0440 /etc/sudoers.d/audit-collect.tmp &&
    sudo visudo -cf /etc/sudoers.d/audit-collect.tmp &&
    sudo mv /etc/sudoers.d/audit-collect.tmp /etc/sudoers.d/audit-collect
  '" || return 1

  # Persist confirmed username back into hosts.txt
  update_hosts_file "$ip" "$user"
  echo "[+] Updated hosts.txt with confirmed account: $user@$ip"
  return 0
}

# ---- Main CLI Router ----
MODE="${1:-collect}"
load_target_hosts

case "$MODE" in
  list)
    echo "Configured hosts (${#HOSTS[@]} total):"
    printf "  - %s\n" "${HOSTS[@]}"
    ;;

  setup)
    [ -f "$HOME/.ssh/id_ed25519" ] || ssh-keygen -t ed25519 -N "" -f "$HOME/.ssh/id_ed25519"
    TMP=$(mktemp)
    trap 'rm -f "$TMP"' EXIT
    write_collector "$TMP"

    echo "Running interactive setup for ${#HOSTS[@]} host(s)..."
    idx=1
    for target in "${HOSTS[@]}"; do
      echo ""
      echo "=== [$idx/${#HOSTS[@]}] Target: $target ==="
      if setup_host "$target" "$TMP"; then
        echo "[+] Successfully configured: $target"
      else
        echo "[-] Setup failed on: $target"
      fi
      ((idx++))
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
    echo "Collecting sequentially from ${#HOSTS[@]} host(s) into $RUN_DIR..."

    summary_file="$RUN_DIR/summary.txt"
    : > "$summary_file"

    idx=1
    for target in "${HOSTS[@]}"; do
      echo -n "[$idx/${#HOSTS[@]}] "
      collect_host "$target" | tee -a "$summary_file"
      ((idx++))
    done

    chmod -R go-rwx "$RUN_DIR"
    echo "Done. OK: $(grep -c '^OK' "$summary_file") | FAILED: $(grep -c '^FAIL' "$summary_file")"
    ;;

  *)
    echo "Usage: $0 {list|setup|collect}"
    exit 1
    ;;
esac