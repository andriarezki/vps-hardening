# vps-hardening

[![CI](https://github.com/andriarezki/vps-hardening/actions/workflows/ci.yml/badge.svg)](https://github.com/andriarezki/vps-hardening/actions/workflows/ci.yml)
![Shell](https://img.shields.io/badge/shell-bash-4EAA25?logo=gnubash&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-blue)

One script to secure a fresh **Ubuntu / Debian VPS** in about a minute: the first things you should do before installing anything else.

Password-guessing bots start hitting a new server within minutes of it going online. This script closes the common holes, and it refuses to do anything that could lock you out.

## What it does

| Step | Change |
|---|---|
| 1. User | Creates a sudo user and installs your SSH public key |
| 2. Firewall | UFW: deny all incoming, allow SSH (rate-limited) and the ports you list |
| 3. SSH | Key-only login, no root login, `MaxAuthTries 3`, `AllowUsers <you>`. Also fixes cloud images that re-enable passwords |
| 4. fail2ban | Bans IPs after 5 failed SSH logins for 1 hour |
| 5. Updates | Unattended security upgrades |
| 6. sysctl | Basic network hardening (no redirects, SYN cookies, reverse-path filter) |

## Safety first

- **Won't lock you out:** password login is only disabled if the user already has an `authorized_keys` file.
- **Validates before reloading:** `sshd -t` must pass, otherwise nothing is reloaded.
- **Firewall before SSH:** the new SSH port is opened before sshd moves to it.
- **Idempotent:** safe to run again; unchanged files are left alone.
- **Dry run:** `DRY_RUN=1` prints every change without making it.

## Usage

```bash
curl -fsSLO https://raw.githubusercontent.com/andriarezki/vps-hardening/main/harden.sh
less harden.sh    # always read a script before running it as root

# preview
sudo NEW_USER=deploy SSH_PUBKEY="$(cat ~/.ssh/id_ed25519.pub)" DRY_RUN=1 bash harden.sh

# apply (web server example: also open 80 and 443)
sudo NEW_USER=deploy SSH_PUBKEY="ssh-ed25519 AAAA... you@laptop" ALLOW_PORTS="80 443" bash harden.sh
```

Then, **before closing your current session**, open a new terminal and check you can log in:

```bash
ssh deploy@<server-ip>
```

### Options

| Variable | Default | Description |
|---|---|---|
| `NEW_USER` | (required) | sudo user to create or reuse |
| `SSH_PUBKEY` | | public key for that user (required unless it already has `authorized_keys`) |
| `SSH_PORT` | `22` | SSH port |
| `ALLOW_PORTS` | | extra TCP ports, space separated, e.g. `"80 443"` |
| `DRY_RUN` | `0` | `1` = show changes only |

## Files it manages

```
/etc/ssh/sshd_config.d/10-hardening.conf
/etc/fail2ban/jail.d/sshd.local
/etc/apt/apt.conf.d/20auto-upgrades
/etc/sysctl.d/90-hardening.conf
```

To undo a step, delete its file and reload the service (`systemctl reload ssh`, `systemctl restart fail2ban`, `sysctl --system`), or `ufw disable`.

## Tested on

Ubuntu 22.04 / 24.04 and Debian 12. CI runs ShellCheck and a dry run on every push.

## License

MIT © Andria Rezki · [andriarezki.tech](https://andriarezki.tech)
