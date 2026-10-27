#!/usr/bin/env bash
# MultipagePlus installer for Raspberry Pi OS (Bookworm or later, 64-bit).
#
#   sudo ./install.sh                 install or upgrade
#   sudo ./install.sh --rtlsdr-blog   also build the RTL-SDR Blog driver (needed for V4 dongles)
#
# Safe to re-run: it upgrades the code and keeps your database and settings.
set -euo pipefail

APP_DIR=/opt/multipage
DATA_DIR=/var/lib/multipage
CONF_DIR=/etc/multipage
ENV_FILE=$CONF_DIR/multipage.env
# Locations used before version 1.3 (moved automatically on upgrade)
OLD_APP_DIR=/opt/pager-monitor
OLD_DATA_DIR=/var/lib/pager-monitor
OLD_CONF_DIR=/etc/pager-monitor
OLD_ENV_FILE=$OLD_CONF_DIR/pager-monitor.env
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_BLOG_DRIVER=0

for arg in "$@"; do
  case "$arg" in
    --rtlsdr-blog) BUILD_BLOG_DRIVER=1 ;;
    -h|--help) sed -n '2,8p' "$0"; exit 0 ;;
    *) echo "Unknown option: $arg" >&2; exit 1 ;;
  esac
done

if [[ $EUID -ne 0 ]]; then
  echo "Run with sudo: sudo $0 $*" >&2
  exit 1
fi

say() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }

say "Installing packages"
apt-get update -qq
apt-get install -y -qq python3 python3-venv python3-pip multimon-ng coreutils sqlite3 rsync

if [[ $BUILD_BLOG_DRIVER -eq 1 ]]; then
  say "Building RTL-SDR Blog driver (supports V3 and V4 dongles)"
  apt-get purge -y -qq '^librtlsdr' rtl-sdr >/dev/null 2>&1 || true
  apt-get install -y -qq git cmake build-essential libusb-1.0-0-dev pkg-config
  tmp=$(mktemp -d)
  git clone --depth 1 https://github.com/rtlsdrblog/rtl-sdr-blog "$tmp/rtl-sdr-blog"
  cmake -S "$tmp/rtl-sdr-blog" -B "$tmp/build" -DINSTALL_UDEV_RULES=ON -DDETACH_KERNEL_DRIVER=ON
  make -C "$tmp/build" -j"$(nproc)"
  make -C "$tmp/build" install
  cp "$tmp/rtl-sdr-blog/rtl-sdr.rules" /etc/udev/rules.d/ 2>/dev/null || true
  ldconfig
  rm -rf "$tmp"
else
  apt-get install -y -qq rtl-sdr
fi

say "Stopping the DVB-T TV driver from claiming the dongle"
cat > /etc/modprobe.d/blacklist-rtl-sdr.conf <<'EOF'
# Leave RTL2832U dongles free for rtl_fm / librtlsdr
blacklist dvb_usb_rtl28xxu
blacklist rtl2832
blacklist rtl2830
blacklist rtl2832_sdr
EOF
for mod in rtl2832_sdr dvb_usb_rtl28xxu rtl2832 rtl2830; do
  modprobe -r "$mod" 2>/dev/null || true
done
udevadm control --reload-rules && udevadm trigger || true

if [[ -d $OLD_DATA_DIR || -d $OLD_CONF_DIR || -d $OLD_APP_DIR ]]; then
  say "Moving an earlier install to the new multipage locations"
  systemctl stop pager-decoder.service pager-web.service 2>/dev/null || true
  if [[ -d $OLD_DATA_DIR && ! -e $DATA_DIR ]]; then
    mv "$OLD_DATA_DIR" "$DATA_DIR"
    echo "Data:     $OLD_DATA_DIR -> $DATA_DIR"
  elif [[ -d $OLD_DATA_DIR ]]; then
    echo "WARNING: both $OLD_DATA_DIR and $DATA_DIR exist; leaving $OLD_DATA_DIR untouched." >&2
  fi
  if [[ -f $OLD_ENV_FILE && ! -e $ENV_FILE ]]; then
    mkdir -p "$CONF_DIR"
    mv "$OLD_ENV_FILE" "$ENV_FILE"
    sed -i "s#$OLD_DATA_DIR#$DATA_DIR#g; s#$OLD_APP_DIR#$APP_DIR#g; s#$OLD_ENV_FILE#$ENV_FILE#g" "$ENV_FILE"
    echo "Settings: $OLD_ENV_FILE -> $ENV_FILE"
  fi
  rmdir "$OLD_CONF_DIR" 2>/dev/null || true
  if [[ -d $OLD_APP_DIR ]]; then
    rm -rf "$OLD_APP_DIR"   # program files only; reinstalled below
    echo "Program:  $OLD_APP_DIR removed (reinstalled to $APP_DIR)"
  fi
  if id pager >/dev/null 2>&1; then
    usermod --home "$DATA_DIR" pager
  fi
fi

say "Creating service user"
if ! id pager >/dev/null 2>&1; then
  useradd --system --home-dir "$DATA_DIR" --shell /usr/sbin/nologin pager
fi
getent group plugdev >/dev/null || groupadd --system plugdev
usermod -aG plugdev pager

say "Installing application to $APP_DIR"
systemctl stop pager-decoder.service pager-web.service 2>/dev/null || true
mkdir -p "$APP_DIR" "$DATA_DIR" "$CONF_DIR"
rsync -a --delete --exclude venv --exclude '__pycache__' --exclude tests \
  "$SRC_DIR/app" "$SRC_DIR/requirements.txt" "$APP_DIR/"
if [[ ! -x $APP_DIR/venv/bin/python ]]; then
  python3 -m venv "$APP_DIR/venv"
fi
"$APP_DIR/venv/bin/pip" install --quiet --upgrade pip
"$APP_DIR/venv/bin/pip" install --quiet -r "$APP_DIR/requirements.txt"
chown -R root:root "$APP_DIR"
chown -R pager:pager "$DATA_DIR"
chmod 750 "$DATA_DIR"

if [[ ! -f $ENV_FILE ]]; then
  say "Writing default settings to $ENV_FILE"
  cat > "$ENV_FILE" <<EOF
# MultipagePlus deployment settings. Restart both services after editing:
#   sudo systemctl restart pager-decoder pager-web
PAGER_DB=$DATA_DIR/pager.db
PAGER_BIND=0.0.0.0
PAGER_PORT=8080
# Set to true when serving over HTTPS (e.g. behind Caddy).
PAGER_SECURE_COOKIES=false
# Set to true only when behind a reverse proxy on this Pi.
PAGER_TRUST_PROXY=false
PAGER_SESSION_HOURS=12
PAGER_LOG_LEVEL=INFO
# Replay a file of multimon-ng lines instead of using a dongle (testing):
#PAGER_SIMULATE_FILE=$APP_DIR/app/sample_pages.txt
EOF
fi
chown root:pager "$ENV_FILE"
chmod 640 "$ENV_FILE"

say "Installing admin command"
cat > /usr/local/bin/pager-admin <<EOF
#!/bin/sh
# MultipagePlus admin: pager-admin add-user NAME | reset-password NAME | list-users
set -a; . $ENV_FILE; set +a
cd $APP_DIR && exec sudo -E -u pager $APP_DIR/venv/bin/python -m app.cli "\$@"
EOF
chmod 755 /usr/local/bin/pager-admin

/usr/local/bin/pager-admin init

if ! sudo -u pager sqlite3 "$DATA_DIR/pager.db" "SELECT 1 FROM users WHERE role='admin' AND active=1 LIMIT 1" | grep -q 1; then
  say "Create the first admin account"
  read -rp "Admin username [admin]: " admin_user
  admin_user=${admin_user:-admin}
  /usr/local/bin/pager-admin add-user "$admin_user" --role admin
fi

say "Installing services"
install -m 644 "$SRC_DIR/systemd/pager-decoder.service" /etc/systemd/system/
install -m 644 "$SRC_DIR/systemd/pager-web.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now pager-web.service pager-decoder.service

port=$(grep -E '^PAGER_PORT=' "$ENV_FILE" | cut -d= -f2)
ip=$(hostname -I 2>/dev/null | awk '{print $1}')
say "Done"
echo "Open http://${ip:-<pi-address>}:${port:-8080}/ and sign in."
echo "Then go to Config and add a channel (frequency, dongle, PPM)."
echo
echo "Logs:   journalctl -u pager-decoder -f    journalctl -u pager-web -f"
if lsusb 2>/dev/null | grep -qi '0bda:2838\|0bda:2832'; then
  echo "RTL-SDR detected. If it was plugged in before install, a reboot makes sure the TV driver is released."
else
  echo "No RTL-SDR detected on USB yet. Plug it in, then check with: rtl_test -t"
fi
