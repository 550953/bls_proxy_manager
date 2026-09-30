#!/usr/bin/env bash
# Разовая установка на чистый Ubuntu/Debian. Запуск под root, можно повторно (идемпотентно):
#   REPO_URL=git@github.com:you/bls-proxy.git BRANCH=main bash install.sh
# Публичный репозиторий: REPO_URL=https://github.com/you/bls-proxy.git
# Firewall (ufw, только 22/80/443): SETUP_UFW=1
set -euo pipefail

: "${REPO_URL:?задай REPO_URL}"
BRANCH="${BRANCH:-main}"
DOMAIN="${DOMAIN:-bls-proxy.shikinn.com}"
SETUP_UFW="${SETUP_UFW:-0}"
APP_USER=blsproxy
BASE=/opt/bls-proxy
APP="$BASE/app"
ENV_FILE=/etc/bls-proxy.env
export DEBIAN_FRONTEND=noninteractive

[ "$(id -u)" = 0 ] || { echo "запусти под root"; exit 1; }

as_app() {
  runuser -u "$APP_USER" -- env HOME="$BASE" \
    GIT_SSH_COMMAND="ssh -i $BASE/.ssh/id_ed25519 -o IdentitiesOnly=yes -o UserKnownHostsFile=$BASE/.ssh/known_hosts" "$@"
}

echo "==> 1/7 обновление ОС и пакеты"
apt-get update -y
apt-get upgrade -y
apt-get install -y python3 python3-venv python3-pip git curl ca-certificates gnupg \
  debian-keyring debian-archive-keyring apt-transport-https unattended-upgrades
cat >/etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF

if ! command -v caddy >/dev/null; then
  echo "==> Caddy (авто-HTTPS)"
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' >/etc/apt/sources.list.d/caddy-stable.list
  apt-get update -y
  apt-get install -y caddy
fi

echo "==> 2/7 пользователь и каталоги"
id "$APP_USER" >/dev/null 2>&1 || useradd --system --home-dir "$BASE" --shell /usr/sbin/nologin "$APP_USER"
mkdir -p "$BASE/.ssh"
chown -R "$APP_USER":"$APP_USER" "$BASE"
chmod 700 "$BASE/.ssh"

echo "==> 3/7 доступ к репозиторию"
if [[ "$REPO_URL" == git@* || "$REPO_URL" == ssh://* ]]; then
  if [ ! -f "$BASE/.ssh/id_ed25519" ]; then
    as_app ssh-keygen -t ed25519 -N "" -C "bls-proxy-deploy" -f "$BASE/.ssh/id_ed25519"
    GIT_HOST=$(echo "$REPO_URL" | sed -E 's#^(ssh://)?[^@]+@([^:/]+).*#\2#')
    ssh-keyscan -t ed25519 "$GIT_HOST" >"$BASE/.ssh/known_hosts" 2>/dev/null
    chown "$APP_USER":"$APP_USER" "$BASE/.ssh/known_hosts"
    echo
    echo "Добавь этот публичный ключ в репозиторий как Deploy key (read-only):"
    echo "  GitHub -> Repo -> Settings -> Deploy keys -> Add deploy key"
    echo
    cat "$BASE/.ssh/id_ed25519.pub"
    echo
    read -rp "Добавил? Нажми Enter... " _
  fi
fi

echo "==> 4/7 код и venv"
if [ ! -d "$APP/.git" ]; then
  as_app git clone --branch "$BRANCH" "$REPO_URL" "$APP"
fi
[ -d "$BASE/venv" ] || as_app python3 -m venv "$BASE/venv"
as_app "$BASE/venv/bin/pip" install -q -U pip
as_app "$BASE/venv/bin/pip" install -q -r "$APP/requirements.txt"
chmod +x "$APP/deploy/update.sh"

echo "==> 5/7 секреты"
if [ ! -f "$ENV_FILE" ]; then
  install -m 600 -o root -g root "$APP/.env.example" "$ENV_FILE"
  echo "Создан $ENV_FILE. Заполни его (nano $ENV_FILE) и запусти install.sh ещё раз."
  exit 0
fi
if grep -q "change-me" "$ENV_FILE"; then
  echo "В $ENV_FILE остались значения change-me — заполни и запусти install.sh снова."
  exit 1
fi
chmod 600 "$ENV_FILE"

echo "==> 6/7 systemd + Caddy"
cat >/etc/systemd/system/bls-proxy.service <<'EOF'
[Unit]
Description=BLS proxy service
After=network-online.target
Wants=network-online.target

[Service]
User=blsproxy
WorkingDirectory=/opt/bls-proxy/app
EnvironmentFile=/etc/bls-proxy.env
ExecStart=/opt/bls-proxy/venv/bin/uvicorn proxy_service:app --host 127.0.0.1 --port 8080 --workers 1 --proxy-headers
Restart=always
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full

[Install]
WantedBy=multi-user.target
EOF

cat >/etc/systemd/system/bls-proxy-update.service <<'EOF'
[Unit]
Description=BLS proxy auto-update (git pull-based)

[Service]
Type=oneshot
ExecStart=/opt/bls-proxy/app/deploy/update.sh
EOF

cat >/etc/systemd/system/bls-proxy-update.timer <<'EOF'
[Unit]
Description=Проверка новых коммитов раз в минуту

[Timer]
OnBootSec=60
OnUnitActiveSec=60
AccuracySec=5s

[Install]
WantedBy=timers.target
EOF

cat >/etc/caddy/Caddyfile <<EOF
$DOMAIN {
    encode gzip
    reverse_proxy 127.0.0.1:8080
}
EOF

echo "==> 7/7 запуск"
if [ "$SETUP_UFW" = 1 ]; then
  apt-get install -y ufw
  ufw allow 22/tcp; ufw allow 80/tcp; ufw allow 443/tcp
  ufw --force enable
fi
systemctl daemon-reload
systemctl enable --now bls-proxy.service
systemctl enable --now bls-proxy-update.timer
systemctl restart caddy
sleep 4
curl -fsS http://127.0.0.1:8080/livez && echo && echo "OK. Дашборд: https://$DOMAIN/  (логин/пароль из $ENV_FILE)"
echo "Логи:   journalctl -u bls-proxy -f      Автообновление: journalctl -u bls-proxy-update -f"
