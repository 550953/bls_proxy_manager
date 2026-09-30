#!/usr/bin/env bash
# Вызывается таймером bls-proxy-update.timer раз в минуту (root).
# Новый коммит в ветке -> reset --hard -> pip install -> restart -> health-check.
# Не прошёл /livez -> откат на прежний коммит; плохой коммит запоминается и не повторяется.
# Всё тело в функции: git reset может перезаписать этот файл во время выполнения.
set -euo pipefail

main() {
  local BASE=/opt/bls-proxy APP_USER=blsproxy
  local APP="$BASE/app" BAD="$BASE/bad_commit"

  as_app() {
    runuser -u "$APP_USER" -- env HOME="$BASE" \
      GIT_SSH_COMMAND="ssh -i $BASE/.ssh/id_ed25519 -o IdentitiesOnly=yes -o UserKnownHostsFile=$BASE/.ssh/known_hosts" "$@"
  }

  cd "$APP"
  local BRANCH LOCAL REMOTE
  BRANCH=$(as_app git rev-parse --abbrev-ref HEAD)
  as_app git fetch --quiet origin "$BRANCH"
  LOCAL=$(as_app git rev-parse HEAD)
  REMOTE=$(as_app git rev-parse "origin/$BRANCH")

  [ "$LOCAL" = "$REMOTE" ] && return 0
  if [ -f "$BAD" ] && [ "$(cat "$BAD")" = "$REMOTE" ]; then return 0; fi

  echo "update: ${LOCAL:0:8} -> ${REMOTE:0:8}"
  as_app git reset --hard "$REMOTE"
  as_app "$BASE/venv/bin/pip" install -q -r requirements.txt
  systemctl restart bls-proxy
  sleep 6

  if ! curl -fsS --max-time 5 http://127.0.0.1:8080/livez >/dev/null; then
    echo "health-check FAILED, откат на ${LOCAL:0:8}"
    echo "$REMOTE" >"$BAD"
    as_app git reset --hard "$LOCAL"
    as_app "$BASE/venv/bin/pip" install -q -r requirements.txt
    systemctl restart bls-proxy
    return 1
  fi
  rm -f "$BAD"
  echo "update OK: ${REMOTE:0:8}"
}

main "$@"
exit $?
