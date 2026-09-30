# bls-proxy

Сервис пула прокси для ботов: API для ботов + HTML-дашборд. Postgres (Supabase) + FastAPI.

## Структура
- `proxy_service.py` — API ботов (`X-Bot-Token`), дашборд `/` (Basic auth), пробер и крон
- `dashboard.html` — дашборд
- `sql/00_full_install.sql` — схема, функции, роли, RLS (накатить первой)
- `sql/03_admin.sql` — роль `bls_admin` и `admin_*` функции (накатить второй)
- `deploy/install.sh` — разовая установка сервера
- `deploy/update.sh` — автообновление из git (таймер раз в минуту, с откатом)
- `.env.example` — имена переменных окружения (реальный `.env` в git не кладём)

## Запуск
1. Supabase SQL Editor: `sql/00_full_install.sql`, затем `sql/03_admin.sql`; задать пароли ролям
   (`alter role bls_issuer|bls_reporter|bls_prober|bls_admin password '...'`).
2. Сервер (root): `REPO_URL=git@github.com:<you>/bls-proxy.git bash deploy/install.sh`
3. Заполнить `/etc/bls-proxy.env` по `.env.example`, повторить шаг 2.
4. Дашборд: https://bls-proxy.shikinn.com/

Обновление: `git push` в ветку — сервер подтянет сам в течение минуты.
