#!/usr/bin/env bash
# vps-hardening: secure a fresh Ubuntu/Debian VPS in one run.
#
#   sudo NEW_USER=deploy SSH_PUBKEY="ssh-ed25519 AAAA..." ./harden.sh
#
# What it does (each step is idempotent, safe to re-run):
#   1. creates a sudo user and installs your SSH public key
#   2. UFW firewall: deny incoming, allow SSH (rate-limited) + optional ports
#   3. SSH: key-only login, no root login (only after the key is in place)
#   4. fail2ban for sshd
#   5. unattended security upgrades
#   6. small sysctl network hardening
#
# Options (environment variables):
#   NEW_USER      sudo user to create/use            (required)
#   SSH_PUBKEY    public key for NEW_USER            (required unless the user already has authorized_keys)
#   SSH_PORT      SSH port                           (default 22)
#   ALLOW_PORTS   extra TCP ports, space separated   (e.g. "80 443")
#   DRY_RUN=1     print what would change, change nothing
set -euo pipefail

NEW_USER="${NEW_USER:-}"
SSH_PUBKEY="${SSH_PUBKEY:-}"
SSH_PORT="${SSH_PORT:-22}"
ALLOW_PORTS="${ALLOW_PORTS:-}"
DRY_RUN="${DRY_RUN:-0}"

log()  { printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }
run()  { if [ "$DRY_RUN" = 1 ]; then echo "    would run: $*"; else "$@"; fi; }

write_file() { # write_file PATH MODE < content
  local path=$1 mode=$2 tmp
  tmp=$(mktemp)
  cat > "$tmp"
  if [ -f "$path" ] && cmp -s "$tmp" "$path"; then rm -f "$tmp"; return; fi
  if [ "$DRY_RUN" = 1 ]; then echo "    would write: $path"; rm -f "$tmp"; return; fi
  install -d "$(dirname "$path")"
  install -m "$mode" "$tmp" "$path"; rm -f "$tmp"
}

preflight() {
  [ "$(id -u)" -eq 0 ] || die "run as root (sudo)"
  command -v apt-get >/dev/null || die "only Debian/Ubuntu (apt) is supported"
  [ -n "$NEW_USER" ] || die "set NEW_USER"
  [[ "$NEW_USER" =~ ^[a-z_][a-z0-9_-]*$ ]] || die "invalid user name: $NEW_USER"
  if ! [[ "$SSH_PORT" =~ ^[0-9]+$ ]] || [ "$SSH_PORT" -lt 1 ] || [ "$SSH_PORT" -gt 65535 ]; then
    die "invalid SSH_PORT"
  fi
  if [ -n "$SSH_PUBKEY" ]; then
    [[ "$SSH_PUBKEY" =~ ^(ssh-(ed25519|rsa)|ecdsa-sha2-nistp(256|384|521))\  ]] || die "SSH_PUBKEY does not look like a public key"
  fi
  for p in $ALLOW_PORTS; do [[ "$p" =~ ^[0-9]+$ ]] || die "invalid port in ALLOW_PORTS: $p"; done
}

setup_user() {
  if id "$NEW_USER" >/dev/null 2>&1; then
    log "user $NEW_USER exists"
  else
    log "creating user $NEW_USER"
    run useradd -m -s /bin/bash "$NEW_USER"
  fi
  run usermod -aG sudo "$NEW_USER"
  local home ak
  home=$(getent passwd "$NEW_USER" | cut -d: -f6 || echo "/home/$NEW_USER")
  ak="$home/.ssh/authorized_keys"
  if [ -n "$SSH_PUBKEY" ]; then
    run install -d -m 700 -o "$NEW_USER" -g "$NEW_USER" "$home/.ssh"
    if [ -f "$ak" ] && grep -qxF "$SSH_PUBKEY" "$ak"; then
      log "SSH key already installed"
    elif [ "$DRY_RUN" = 1 ]; then
      echo "    would add SSH key to $ak"
    else
      echo "$SSH_PUBKEY" >> "$ak"; chown "$NEW_USER:$NEW_USER" "$ak"; chmod 600 "$ak"
      log "SSH key installed for $NEW_USER"
    fi
  fi
  if [ "$DRY_RUN" != 1 ] && ! [ -s "$ak" ]; then
    die "$NEW_USER has no authorized_keys: refusing to disable password login (you would be locked out)"
  fi
}

harden_ssh() {
  log "SSH: key-only, no root login, port $SSH_PORT"
  write_file /etc/ssh/sshd_config.d/10-hardening.conf 644 <<CONF
# managed by vps-hardening
Port $SSH_PORT
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
MaxAuthTries 3
LoginGraceTime 30
X11Forwarding no
AllowUsers $NEW_USER
CONF
  # cloud images often ship "PasswordAuthentication yes" in a file that sorts before ours
  for f in /etc/ssh/sshd_config.d/*.conf; do
    [ "$f" = /etc/ssh/sshd_config.d/10-hardening.conf ] && continue
    if grep -qiE '^\s*PasswordAuthentication\s+yes' "$f" 2>/dev/null; then
      warn "disabling PasswordAuthentication yes in $f"
      run sed -i -E 's/^\s*PasswordAuthentication\s+yes/PasswordAuthentication no/I' "$f"
    fi
  done
  if [ "$DRY_RUN" != 1 ]; then
    sshd -t || die "sshd config test failed, nothing reloaded"
    systemctl reload ssh 2>/dev/null || systemctl reload sshd
  fi
}

setup_firewall() {
  log "UFW: deny incoming, allow SSH $SSH_PORT${ALLOW_PORTS:+ and $ALLOW_PORTS}"
  run apt-get install -y -qq -o=Dpkg::Use-Pty=0 ufw
  run ufw default deny incoming
  run ufw default allow outgoing
  run ufw limit "$SSH_PORT/tcp"
  for p in $ALLOW_PORTS; do run ufw allow "$p/tcp"; done
  run ufw --force enable
}

setup_fail2ban() {
  log "fail2ban for sshd"
  run apt-get install -y -qq -o=Dpkg::Use-Pty=0 fail2ban
  write_file /etc/fail2ban/jail.d/sshd.local 644 <<CONF
[sshd]
enabled  = true
port     = $SSH_PORT
maxretry = 5
findtime = 10m
bantime  = 1h
CONF
  run systemctl enable --now fail2ban
  run systemctl restart fail2ban
}

setup_updates() {
  log "unattended security upgrades"
  run apt-get install -y -qq -o=Dpkg::Use-Pty=0 unattended-upgrades
  write_file /etc/apt/apt.conf.d/20auto-upgrades 644 <<'CONF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
CONF
}

setup_sysctl() {
  log "sysctl network hardening"
  write_file /etc/sysctl.d/90-hardening.conf 644 <<'CONF'
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.tcp_syncookies = 1
net.ipv6.conf.all.accept_redirects = 0
CONF
  run sysctl --system >/dev/null
}

main() {
  preflight
  [ "$DRY_RUN" = 1 ] && warn "DRY RUN: nothing will be changed"
  run apt-get update -qq
  setup_user
  setup_firewall   # open the (new) SSH port before sshd moves to it
  harden_ssh
  setup_fail2ban
  setup_updates
  setup_sysctl
  log "done. Test in a NEW terminal before closing this one:  ssh -p $SSH_PORT $NEW_USER@<server-ip>"
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then main "$@"; fi
