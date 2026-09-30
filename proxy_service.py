"""proxy_service.py — единая точка входа к пулу прокси: API для ботов + HTML-дашборд.

Роли Postgres (у каждой урезанные права, см. sql/):
  bls_issuer   — /acquire, /renew, крон
  bls_reporter — /report, /release
  bls_prober   — фоновый пинг через прокси
  bls_admin    — дашборд (/admin/api/*), только через admin_* функции

Доступ:
  * боты      — заголовок  X-Bot-Token: $BLS_BOT_TOKEN
  * дашборд   — HTTP Basic: логин $BLS_DASH_USER, пароль $BLS_DASH_PASS
  * /livez    — открыт, отдаёт только {"ok": true} (для health-check деплоя)

ВАЖНО: запускать ровно ОДИН воркер uvicorn (фоновые циклы живут в процессе).
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import secrets
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Optional
from urllib.parse import quote

import asyncpg
import httpx
from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel, Field

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("proxy_service")


# --------------------------------------------------------------------------- #
# Конфиг: всё из окружения (/etc/bls-proxy.env). В код/репозиторий секреты не кладём.
# --------------------------------------------------------------------------- #
def _req(name: str) -> str:
    v = os.environ.get(name, "")
    if not v:
        raise SystemExit(f"Не задана переменная окружения {name}")
    return v


DASH_USER = _req("BLS_DASH_USER")      # логин дашборда
DASH_PASS = _req("BLS_DASH_PASS")      # пароль дашборда
BOT_TOKEN = _req("BLS_BOT_TOKEN")      # токен для ботов (X-Bot-Token)

DB_HOST = os.environ.get("BLS_DB_HOST", "")
DB_PORT = int(os.environ.get("BLS_DB_PORT", "5432"))
DB_NAME = os.environ.get("BLS_DB_NAME", "postgres")
DB_SSL = os.environ.get("BLS_DB_SSL", "require")
# Для Supabase pooler логин имеет вид  bls_issuer.<project-ref>  -> BLS_DB_USER_SUFFIX=.<project-ref>
DB_USER_SUFFIX = os.environ.get("BLS_DB_USER_SUFFIX", "")

ROLES = ("issuer", "reporter", "prober", "admin")

PROBE_INTERVAL_SECONDS = float(os.environ.get("BLS_PROBE_INTERVAL", "20"))
PROBE_BATCH_SIZE = int(os.environ.get("BLS_PROBE_BATCH_SIZE", "10"))
PROBE_HTTP_TIMEOUT = float(os.environ.get("BLS_PROBE_TIMEOUT", "6"))
PROBE_CONCURRENCY = int(os.environ.get("BLS_PROBE_CONCURRENCY", "15"))
CRON_INTERVAL_SECONDS = float(os.environ.get("BLS_CRON_INTERVAL", "300"))
SCHEMA = "bls_proxy_manager"
DASH_FILE = Path(__file__).with_name("dashboard.html")

ALLOWED_SCHEMES = ("http", "https", "socks5", "socks5h")
ALLOWED_KINDS = ("shared", "dedicated", "mobile")

pools: dict[str, asyncpg.Pool] = {}
_target_cache: dict[int, tuple[str, int]] = {}
_target_cache_at = 0.0
_probe_sema = asyncio.Semaphore(PROBE_CONCURRENCY)
_shutdown = asyncio.Event()


def _pool_kwargs(role: str) -> dict[str, Any]:
    dsn = os.environ.get(f"BLS_{role.upper()}_DSN")
    if dsn:
        return {"dsn": dsn}
    return dict(
        host=DB_HOST, port=DB_PORT, database=DB_NAME, ssl=DB_SSL,
        user=f"bls_{role}{DB_USER_SUFFIX}",
        password=_req(f"BLS_{role.upper()}_PASSWORD"),
    )


async def _sleep(seconds: float) -> None:
    """Сон, прерываемый остановкой сервиса (без утечки задач)."""
    try:
        await asyncio.wait_for(_shutdown.wait(), timeout=seconds)
    except asyncio.TimeoutError:
        pass


@asynccontextmanager
async def lifespan(app: FastAPI):
    for role in ROLES:
        pools[role] = await asyncpg.create_pool(
            min_size=1, max_size=3 if role == "admin" else 5, **_pool_kwargs(role)
        )
        log.info("connected pool: %s", role)
    tasks = [
        asyncio.create_task(prober_loop(), name="prober_loop"),
        asyncio.create_task(cron_loop(), name="cron_loop"),
    ]
    try:
        yield
    finally:
        _shutdown.set()
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        for pool in pools.values():
            await pool.close()


app = FastAPI(title="bls-proxy-service", lifespan=lifespan,
              docs_url=None, redoc_url=None, openapi_url=None)


# --------------------------------------------------------------------------- #
# Авторизация
# --------------------------------------------------------------------------- #
def require_bot(x_bot_token: str = Header(default="")) -> None:
    if not secrets.compare_digest(x_bot_token.encode(), BOT_TOKEN.encode()):
        raise HTTPException(401, "bad bot token")


_basic = HTTPBasic(auto_error=False)


async def require_admin(creds: Optional[HTTPBasicCredentials] = Depends(_basic)) -> None:
    ok = False
    if creds:
        u = secrets.compare_digest(creds.username.encode(), DASH_USER.encode())
        p = secrets.compare_digest(creds.password.encode(), DASH_PASS.encode())
        ok = u and p
    if not ok:
        await asyncio.sleep(1)  # притормозить перебор
        raise HTTPException(401, "auth required", headers={"WWW-Authenticate": 'Basic realm="bls-proxy"'})


# --------------------------------------------------------------------------- #
# API для ботов
# --------------------------------------------------------------------------- #
class AcquireRequest(BaseModel):
    account_id: str
    count: int = 1
    ttl_seconds: int = 300
    purpose: str = "bls"
    client_id: Optional[str] = None
    exclude: list[str] = Field(default_factory=list)
    replace: bool = True


class RenewRequest(BaseModel):
    lease_id: str
    ttl_seconds: int = 300


class ReportRequest(BaseModel):
    lease_id: str
    event_type: str  # 'cycle_ok' | 'error'
    error_code: Optional[str] = None
    phase: Optional[str] = None
    latency_ms: Optional[int] = None
    detail: dict[str, Any] = Field(default_factory=dict)


class ReleaseRequest(BaseModel):
    lease_id: str
    reason: str = "released"
    error_code: Optional[str] = None
    phase: Optional[str] = None
    detail: dict[str, Any] = Field(default_factory=dict)


bot = APIRouter(dependencies=[Depends(require_bot)])


@bot.post("/acquire")
async def acquire(req: AcquireRequest):
    rows = await pools["issuer"].fetch(
        f"select * from {SCHEMA}.acquire_proxies("
        "p_account_id := $1, p_count := $2, p_ttl_seconds := $3, "
        "p_purpose := $4, p_client_id := $5, p_exclude := $6, p_replace := $7)",
        req.account_id, req.count, req.ttl_seconds, req.purpose,
        req.client_id, req.exclude, req.replace,
    )
    if not rows:
        wait_s = await pools["issuer"].fetchval(f"select {SCHEMA}.next_available_in($1)", req.purpose)
        # Пусто — норма для пула: ждать wait_s и повторять, аккаунт не выключать.
        return {"leases": [], "retry_after_seconds": wait_s}
    return {
        "leases": [
            {
                "lease_id": str(r["lease_id"]),
                "proxy_id": r["proxy_id"],
                "scheme": r["scheme"],
                "host": r["host"],
                "port": r["port"],
                "username": r["username"],
                "password": r["password"],
                "expires_at": r["expires_at"].isoformat(),
            }
            for r in rows
        ]
    }


@bot.post("/renew")
async def renew(req: RenewRequest):
    until = await pools["issuer"].fetchval(
        f"select {SCHEMA}.renew_lease($1::uuid, $2)", req.lease_id, req.ttl_seconds
    )
    if until is None:
        raise HTTPException(409, "lease expired or already released — acquire a new one")
    return {"expires_at": until.isoformat()}


@bot.post("/report")
async def report(req: ReportRequest):
    if req.event_type not in ("cycle_ok", "error"):
        raise HTTPException(400, "event_type must be 'cycle_ok' or 'error'")
    await pools["reporter"].execute(
        f"select {SCHEMA}.report_event($1::uuid, $2, $3, $4, $5, $6::jsonb)",
        req.lease_id, req.event_type, req.error_code, req.phase,
        req.latency_ms, json.dumps(req.detail),
    )
    return {"ok": True}


@bot.post("/release")
async def release(req: ReleaseRequest):
    await pools["reporter"].execute(
        f"select {SCHEMA}.release_lease($1::uuid, $2, $3, $4, $5::jsonb)",
        req.lease_id, req.reason, req.error_code, req.phase, json.dumps(req.detail),
    )
    return {"ok": True}


@bot.get("/health")
async def health():
    rows = await pools["issuer"].fetch(f"select * from {SCHEMA}.v_pool_summary")
    return {"pool": [dict(r) for r in rows]}


@app.get("/livez")
async def livez():
    return {"ok": True}


app.include_router(bot)


# --------------------------------------------------------------------------- #
# Дашборд + админ-API
# --------------------------------------------------------------------------- #
def parse_proxy_line(line: str, default_scheme: str) -> dict[str, Any]:
    """Форматы: host:port | host:port:user:pass | user:pass@host:port | scheme://[user:pass@]host:port"""
    scheme = default_scheme
    m = re.match(r"^([a-zA-Z0-9]+)://(.+)$", line)
    if m:
        scheme, line = m.group(1).lower(), m.group(2)
    user = pw = None
    if "@" in line:
        cred, hostport = line.rsplit("@", 1)
        user, _, pw = cred.partition(":")
        host, _, port = hostport.rpartition(":")
    else:
        parts = line.split(":", 3)
        if len(parts) == 2:
            host, port = parts
        elif len(parts) == 4:
            host, port, user, pw = parts
        else:
            raise ValueError("формат: host:port[:user:pass] | user:pass@host:port | scheme://user:pass@host:port")
    if scheme not in ALLOWED_SCHEMES:
        raise ValueError(f"схема {scheme!r} не поддерживается")
    host = host.strip()
    if not host or not port.strip().isdigit() or not 1 <= int(port) <= 65535:
        raise ValueError("некорректные host/port")
    return {"scheme": scheme, "host": host, "port": int(port),
            "username": user or None, "password": pw or None}


class AddProxies(BaseModel):
    text: str = Field(max_length=300_000)
    scheme: str = "socks5"
    kind: str = "shared"
    pool: Optional[str] = Field(default=None, max_length=64)
    max_leases: int = Field(default=1, ge=1, le=10)


class IdsReq(BaseModel):
    ids: list[str] = Field(min_length=1, max_length=2000)


class EnableReq(IdsReq):
    enabled: bool


admin = APIRouter(prefix="/admin/api", dependencies=[Depends(require_admin)])


@app.get("/", response_class=HTMLResponse, dependencies=[Depends(require_admin)])
async def dashboard():
    return HTMLResponse(DASH_FILE.read_text(encoding="utf-8"), headers={"Cache-Control": "no-store"})


@admin.get("/state")
async def admin_state():
    p = pools["admin"]
    summary = await p.fetch(f"select * from {SCHEMA}.v_pool_summary order by 1, 2")
    proxies = await p.fetch(f"select * from {SCHEMA}.admin_list_proxies()")
    leases = await p.fetch(f"select * from {SCHEMA}.admin_active_leases()")
    events = await p.fetch(f"select * from {SCHEMA}.admin_recent_events($1)", 100)
    return {
        "summary": [dict(r) for r in summary],
        "proxies": [dict(r) for r in proxies],
        "leases": [dict(r) for r in leases],
        "events": [dict(r) for r in events],
    }


@admin.post("/proxies")
async def admin_add(req: AddProxies):
    if req.scheme not in ALLOWED_SCHEMES:
        raise HTTPException(400, "bad scheme")
    if req.kind not in ALLOWED_KINDS:
        raise HTTPException(400, "bad kind")
    items: list[dict[str, Any]] = []
    errors: list[str] = []
    for n, raw in enumerate(req.text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            item = parse_proxy_line(line, req.scheme)
            item.update(kind=req.kind, pool=req.pool, max_leases=req.max_leases)
            items.append(item)
        except ValueError as exc:
            errors.append(f"строка {n}: {exc}")
    result = {"inserted": 0, "updated": 0}
    if items:
        raw_res = await pools["admin"].fetchval(
            f"select {SCHEMA}.admin_upsert_proxies($1::jsonb)", json.dumps(items)
        )
        result = json.loads(raw_res)
    return {**result, "errors": errors}


@admin.post("/proxies/enable")
async def admin_enable(req: EnableReq):
    n = await pools["admin"].fetchval(
        f"select {SCHEMA}.admin_set_enabled($1::text[], $2)", req.ids, req.enabled)
    return {"changed": n}


@admin.post("/proxies/delete")
async def admin_delete(req: IdsReq):
    n = await pools["admin"].fetchval(f"select {SCHEMA}.admin_delete_proxies($1::text[])", req.ids)
    return {"deleted": n}


@admin.post("/proxies/unquarantine")
async def admin_unquarantine(req: IdsReq):
    n = await pools["admin"].fetchval(f"select {SCHEMA}.admin_clear_quarantine($1::text[])", req.ids)
    return {"changed": n}


app.include_router(admin)


# --------------------------------------------------------------------------- #
# Prober loop — единственная часть, которая реально ходит через прокси.
# Соединение с БД берётся только на время записи, не на время пинга.
# --------------------------------------------------------------------------- #
async def _refresh_target_cache() -> None:
    global _target_cache, _target_cache_at
    if time.monotonic() - _target_cache_at < 60 and _target_cache:
        return
    rows = await pools["prober"].fetch(
        f"select id, url, expected_status from {SCHEMA}.probe_targets where enabled"
    )
    _target_cache = {r["id"]: (r["url"], r["expected_status"]) for r in rows}
    _target_cache_at = time.monotonic()


def _proxy_url(scheme: str, host: str, port: int, username: Optional[str], password: Optional[str]) -> str:
    auth = ""
    if username:
        auth = quote(username, safe="") + (":" + quote(password or "", safe="")) + "@"
    return f"{scheme}://{auth}{host}:{port}"


async def _ping_once(proxy_url: str, target_url: str, expected_status: int) -> tuple[bool, Optional[int]]:
    started = time.perf_counter()
    try:
        async with httpx.AsyncClient(proxy=proxy_url, timeout=PROBE_HTTP_TIMEOUT) as client:
            resp = await client.get(target_url)
        return resp.status_code == expected_status, round((time.perf_counter() - started) * 1000)
    except Exception as exc:  # прокси/сеть мертвы — ожидаемый исход
        log.debug("probe failed for %s: %s", target_url, exc)
        return False, None


async def _probe_one_proxy(row: asyncpg.Record) -> None:
    async with _probe_sema:
        await _refresh_target_cache()
        pool = pools["prober"]
        proxy_url = _proxy_url(row["scheme"], row["host"], row["port"], row["username"], row["password"])
        bound = row["bound_target"]
        targets = [bound] if bound is not None else list(row["candidate_ids"] or [])
        for target_id in targets:
            url, expected = _target_cache.get(target_id, (None, None))
            if url is None:
                continue
            ok, latency = await _ping_once(proxy_url, url, expected)
            await pool.execute(
                f"select {SCHEMA}.record_probe($1, $2, $3, $4)",
                row["proxy_id"], target_id, ok, latency,
            )
        if bound is None and targets:
            await pool.execute(f"select {SCHEMA}.select_probe_target($1)", row["proxy_id"])


async def prober_loop() -> None:
    log.info("prober_loop started, interval=%ss batch=%s", PROBE_INTERVAL_SECONDS, PROBE_BATCH_SIZE)
    while not _shutdown.is_set():
        try:
            batch = await pools["prober"].fetch(
                f"select * from {SCHEMA}.probe_batch($1)", PROBE_BATCH_SIZE
            )
            if batch:
                await asyncio.gather(*(_probe_one_proxy(r) for r in batch))
        except Exception:
            log.exception("prober_loop iteration failed")
        await _sleep(PROBE_INTERVAL_SECONDS)


# --------------------------------------------------------------------------- #
# Cron loop — чистка протухших аренд + карантин по кросс-аккаунтным ошибкам.
# --------------------------------------------------------------------------- #
async def cron_loop() -> None:
    log.info("cron_loop started, interval=%ss", CRON_INTERVAL_SECONDS)
    while not _shutdown.is_set():
        try:
            closed = await pools["issuer"].fetchval(f"select {SCHEMA}.close_expired_leases()")
            quarantined = await pools["issuer"].fetchval(f"select {SCHEMA}.evaluate_cross_account_health()")
            if closed or quarantined:
                log.info("cron: closed_leases=%s quarantined=%s", closed, quarantined)
        except Exception:
            log.exception("cron_loop iteration failed")
        await _sleep(CRON_INTERVAL_SECONDS)
