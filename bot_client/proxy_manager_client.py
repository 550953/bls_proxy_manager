"""Client for the BLS proxy-manager lease API.

The Windows dashboard can save the client token in Supabase app_settings as a
machine-scoped DPAPI ciphertext. Environment variables and the legacy local
token file remain supported as fallbacks.
"""

from __future__ import annotations

import base64
import json
import os
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlsplit

DEFAULT_BASE_URL = "https://bls-proxy.shikinn.com"
TOKEN_CONFIG_PATH = Path(__file__).with_name("proxy_manager_token.local")
DEFAULT_TTL_SECONDS = 300
LEASE_RENEWAL_LEAD_SECONDS = 60.0
LEASE_SAFETY_SECONDS = 20.0
LEASE_RENEW_RETRY_SECONDS = 5.0
TOKEN_REFRESH_INTERVAL_SECONDS = 15.0
PROXY_MANAGER_TOKEN_DB_KEY = "proxy_manager_token_encrypted"
PROXY_MANAGER_TOKEN_DB_FORMAT = "windows_dpapi_machine_v1"
ALLOWED_SCHEMES = {"http", "https", "socks5", "socks5h"}

# Коды, при которых виноват сам прокси (он не пропускает трафик).  Совпадает с
# proxy_fault_codes на сервере.  Такой прокси клиент не берёт повторно сам,
# не дожидаясь сервера: первый раз на BAD_PROXY_HOLD_SECONDS, при повторе
# срок удваивается (до BAD_PROXY_HOLD_MAX_SECONDS).
BAD_PROXY_CODES = frozenset({
    "PROXY_CONNECT_FAILED",
    "PROXY_TIMEOUT",
    "ERR_PROXY_CONNECTION_FAILED",
    "ERR_TUNNEL_CONNECTION_FAILED",
})


def _env_seconds(name: str, default: float, low: float, high: float) -> float:
    try:
        value = float(os.environ.get(name, default))
    except (TypeError, ValueError):
        value = float(default)
    return min(high, max(low, value))


BAD_PROXY_HOLD_SECONDS = _env_seconds(
    "BLS_PROXY_MANAGER_BAD_PROXY_SECONDS", 3600.0, 60.0, 86400.0
)
BAD_PROXY_HOLD_MAX_SECONDS = _env_seconds(
    "BLS_PROXY_MANAGER_BAD_PROXY_MAX_SECONDS", 14400.0, 60.0, 86400.0
)
# Сколько помнить сам факт сбоя (для счётчика повторов), даже после окончания паузы.
BAD_PROXY_MEMORY_SECONDS = _env_seconds(
    "BLS_PROXY_MANAGER_BAD_PROXY_MEMORY_SECONDS", 21600.0, 300.0, 172800.0
)
_SETTINGS_DB = None
_SETTINGS_DB_LOCK = threading.Lock()


class ProxyManagerError(RuntimeError):
    def __init__(self, message: str, status_code: Optional[int] = None):
        super().__init__(message)
        self.status_code = status_code


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Never forward the bot token to a redirected service origin."""

    def redirect_request(self, _req, _fp, _code, _msg, _headers, _newurl):
        return None


def _read_local_proxy_manager_token() -> str:
    """Read the legacy private local config as a runtime fallback."""
    try:
        lines = TOKEN_CONFIG_PATH.read_text(encoding="utf-8-sig").splitlines()
    except FileNotFoundError:
        return ""
    except OSError:
        raise ProxyManagerError(
            "local proxy manager token file cannot be read"
        ) from None

    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        name, separator, value = line.partition("=")
        if separator and name.strip() == "BLS_PROXY_MANAGER_TOKEN":
            value = value.strip()
            if (
                len(value) >= 2
                and value[0] == value[-1]
                and value[0] in {"'", '"'}
            ):
                value = value[1:-1]
            return value.strip()
    return ""


def _settings_database():
    """Return one process-wide Supabase settings client, if configured."""
    global _SETTINGS_DB
    with _SETTINGS_DB_LOCK:
        if _SETTINGS_DB is None:
            try:
                from db_monitor import SupabaseMonitor

                _SETTINGS_DB = SupabaseMonitor(logger=lambda _message: None)
            except Exception:
                return None
        return _SETTINGS_DB


def _read_database_proxy_manager_token():
    database = _settings_database()
    if database is None or not getattr(database, "enabled", False):
        return {
            "available": False,
            "saved": False,
            "readable": False,
            "token": "",
        }
    try:
        record = database.read_app_settings(PROXY_MANAGER_TOKEN_DB_KEY)
    except Exception:
        return {
            "available": False,
            "saved": False,
            "readable": False,
            "token": "",
        }
    if getattr(database, "last_error", ""):
        return {
            "available": False,
            "saved": False,
            "readable": False,
            "token": "",
        }
    record = record if isinstance(record, dict) else {}
    ciphertext_b64 = str(record.get("ciphertext_b64") or "").strip()
    saved = bool(ciphertext_b64)
    if not saved:
        return {
            "available": True,
            "saved": False,
            "readable": True,
            "token": "",
        }
    if record.get("format") != PROXY_MANAGER_TOKEN_DB_FORMAT:
        return {
            "available": True,
            "saved": True,
            "readable": False,
            "token": "",
        }
    try:
        ciphertext = base64.b64decode(
            ciphertext_b64.encode("ascii"),
            validate=True,
        )
        from telegram_notifier import unprotect_machine_secret

        token = unprotect_machine_secret(ciphertext).strip()
    except Exception:
        return {
            "available": True,
            "saved": True,
            "readable": False,
            "token": "",
        }
    return {
        "available": True,
        "saved": True,
        "readable": bool(token),
        "token": token,
    }


def _fallback_proxy_manager_token():
    for name in ("BLS_PROXY_MANAGER_TOKEN", "BLS_BOT_TOKEN"):
        value = os.environ.get(name)
        if isinstance(value, str) and value.strip():
            return value.strip(), f"environment:{name}"
    try:
        value = _read_local_proxy_manager_token().strip()
    except ProxyManagerError:
        return "", "local_file_error"
    if value:
        return value, "local_file"
    return "", "none"


def _proxy_manager_token_state():
    database = _read_database_proxy_manager_token()
    if database["token"]:
        token, source = database["token"], "database"
    else:
        token, source = _fallback_proxy_manager_token()
        if (
            not token
            and database["saved"]
            and not database["readable"]
        ):
            source = "database_unreadable"
    return {
        **database,
        "token": token,
        "source": source,
    }


def proxy_manager_token_status():
    """Return non-secret token setup status for the local HTML dashboard."""
    state = _proxy_manager_token_state()
    return {
        "database_available": bool(state["available"]),
        "token_saved_in_database": bool(state["saved"]),
        "database_token_readable": bool(state["readable"]),
        "token_available": bool(state["token"]),
        "token_source": str(state["source"]),
        "local_file_present": TOKEN_CONFIG_PATH.is_file(),
    }


def _write_database_proxy_manager_token(record):
    database = _settings_database()
    if database is None or not getattr(database, "enabled", False):
        raise ProxyManagerError(
            "Supabase app_settings is unavailable on this machine"
        )
    try:
        database.write_app_settings(PROXY_MANAGER_TOKEN_DB_KEY, record)
        if getattr(database, "last_error", ""):
            raise RuntimeError("write failed")
        stored = database.read_app_settings(PROXY_MANAGER_TOKEN_DB_KEY)
        if getattr(database, "last_error", "") or stored != record:
            raise RuntimeError("verification failed")
    except Exception:
        raise ProxyManagerError(
            "Could not save and verify the encrypted token in Supabase"
        ) from None


def save_proxy_manager_token(token):
    """Encrypt and save the Windows Proxy Manager client token in Supabase."""
    value = str(token or "").strip()
    if not value:
        raise ProxyManagerError("Proxy Manager token is empty")
    if len(value) > 512:
        raise ProxyManagerError("Proxy Manager token is too long")
    try:
        from telegram_notifier import protect_machine_secret

        ciphertext = protect_machine_secret(
            value,
            "BLS Proxy Manager client token",
        )
    except Exception:
        raise ProxyManagerError(
            "Could not protect the Proxy Manager token on this Windows machine"
        ) from None
    record = {
        "format": PROXY_MANAGER_TOKEN_DB_FORMAT,
        "ciphertext_b64": base64.b64encode(ciphertext).decode("ascii"),
    }
    _write_database_proxy_manager_token(record)
    return True


def clear_proxy_manager_token():
    """Clear only the database token; environment/file fallbacks remain."""
    _write_database_proxy_manager_token(
        {
            "format": PROXY_MANAGER_TOKEN_DB_FORMAT,
            "ciphertext_b64": "",
        }
    )
    return True


def proxy_manager_enabled() -> bool:
    value = os.environ.get("BLS_PROXY_MANAGER_ENABLED")
    return value is None or str(value).strip().lower() not in {
        "0", "false", "no", "off"
    }


def _account(value: Any) -> str:
    return str(value or "").strip().lower()


def _safe_detail(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    allowed = {
        "stage", "result", "reason_code", "error_type", "source",
        "attempt", "duration_ms", "http_status", "page_type", "outcome",
    }
    result = {}
    for key in allowed:
        item = value.get(key)
        if isinstance(item, (bool, int)):
            result[key] = item
        elif isinstance(item, str) and item.strip():
            result[key] = " ".join(item.split())[:160]
    return result


class ProxyManagerClient:
    def __init__(
        self,
        base_url: Optional[str] = None,
        token: Optional[str] = None,
        logger=None,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
    ):
        self.base_url = str(
            base_url or os.environ.get("BLS_PROXY_MANAGER_URL") or DEFAULT_BASE_URL
        ).strip().rstrip("/")
        self._token_lock = threading.RLock()
        self._token_refresh_at = 0.0
        self._token_refresh_enabled = token is None
        if token is None:
            token_state = _proxy_manager_token_state()
            self.token = token_state["token"]
            self.token_source = token_state["source"]
            self._token_refresh_at = (
                time.monotonic() + TOKEN_REFRESH_INTERVAL_SECONDS
            )
        else:
            self.token = str(token).strip()
            self.token_source = "explicit"
        self.logger = logger or (lambda _message: None)
        try:
            self.ttl_seconds = min(3600, max(30, int(ttl_seconds)))
        except (TypeError, ValueError):
            self.ttl_seconds = DEFAULT_TTL_SECONDS
        try:
            timeout = float(os.environ.get(
                "BLS_PROXY_MANAGER_TIMEOUT_SECONDS", "10"
            ))
        except (TypeError, ValueError):
            timeout = 10.0
        self.timeout = min(30.0, max(2.0, timeout))
        self._lock = threading.RLock()
        self._leases: dict[str, dict[str, Any]] = {}
        self._rotation_exclusions: dict[str, set[str]] = {}
        # proxy_id -> {"fails": n, "until": monotonic, "last": monotonic}.
        # Общая для всех аккаунтов этого процесса: плохой прокси не должен
        # достаться другому аккаунту.  После перезапуска manager память
        # пуста, дальше защищает серверный кулдаун/карантин.
        self._bad_proxies: dict[str, dict[str, float]] = {}
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._renew_thread = None
        if self.token:
            self._log(
                f"[PROXY MANAGER] token source: {self.token_source}"
            )
        else:
            self._log(
                "[PROXY MANAGER] token is not configured "
                "(checked database, environment, and local file)"
            )

    def _log(self, message: str) -> None:
        try:
            self.logger(message)
        except Exception:
            pass

    def _refresh_token_if_due(self) -> None:
        if not self._token_refresh_enabled:
            return
        now = time.monotonic()
        with self._token_lock:
            if now < self._token_refresh_at:
                return
            self._token_refresh_at = now + TOKEN_REFRESH_INTERVAL_SECONDS
            state = _proxy_manager_token_state()
            if state["available"] or not self.token:
                previous_source = self.token_source
                self.token = state["token"]
                self.token_source = state["source"]
                if self.token and self.token_source != previous_source:
                    self._log(
                        f"[PROXY MANAGER] token source: {self.token_source}"
                    )

    def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        self._refresh_token_if_due()
        with self._token_lock:
            token = self.token
        if not token:
            raise ProxyManagerError("proxy manager token is not configured")
        try:
            parts = urlsplit(self.base_url)
        except ValueError:
            raise ProxyManagerError("proxy manager URL is invalid") from None
        if (
            parts.scheme not in {"http", "https"}
            or not parts.hostname
            or parts.username
            or parts.password
            or (parts.scheme != "https" and parts.hostname not in {
                "localhost", "127.0.0.1", "::1"
            })
        ):
            raise ProxyManagerError("proxy manager URL must use HTTPS")
        request = urllib.request.Request(
            self.base_url + "/" + path.lstrip("/"),
            data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "X-Bot-Token": token,
            },
            method="POST",
        )
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            _NoRedirectHandler(),
        )
        try:
            with opener.open(request, timeout=self.timeout) as response:
                raw = response.read(1_000_000)
                status = int(getattr(response, "status", 200))
        except urllib.error.HTTPError as exc:
            raise ProxyManagerError(
                f"proxy manager returned HTTP {int(exc.code)}", int(exc.code)
            ) from None
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise ProxyManagerError(
                f"proxy manager request failed ({type(exc).__name__})"
            ) from None
        if status < 200 or status >= 300:
            raise ProxyManagerError(f"proxy manager returned HTTP {status}", status)
        try:
            result = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ProxyManagerError("proxy manager returned invalid JSON") from None
        if not isinstance(result, dict):
            raise ProxyManagerError("proxy manager returned an unexpected response")
        return result

    def _validate_lease(self, value: Any) -> dict[str, Any]:
        if not isinstance(value, dict):
            raise ProxyManagerError("proxy manager returned an invalid lease")
        scheme = str(value.get("scheme") or "").strip().lower()
        try:
            port = int(value.get("port") or 0)
        except (TypeError, ValueError):
            port = 0
        if (
            not str(value.get("lease_id") or "").strip()
            or not str(value.get("proxy_id") or "").strip()
            or scheme not in ALLOWED_SCHEMES
            or not str(value.get("host") or "").strip()
            or not 1 <= port <= 65535
        ):
            raise ProxyManagerError("proxy manager lease is invalid")
        return {
            "lease_id": str(value["lease_id"]).strip(),
            "proxy_id": str(value["proxy_id"]).strip(),
            "scheme": scheme,
            "host": str(value["host"]).strip(),
            "port": port,
            "username": str(value.get("username") or ""),
            "password": str(value.get("password") or ""),
            "expires_at": str(value.get("expires_at") or ""),
            "_account_action": str(value.get("account_action") or "").strip(),
        }

    @staticmethod
    def _deadline(expires_at: Any, ttl: int) -> float:
        try:
            value = datetime.fromisoformat(
                str(expires_at).replace("Z", "+00:00")
            )
            if value.tzinfo is None:
                value = value.replace(tzinfo=timezone.utc)
            return time.monotonic() + max(
                0.0, (value - datetime.now(timezone.utc)).total_seconds()
            )
        except (TypeError, ValueError, OverflowError):
            return time.monotonic() + ttl

    def _prune_bad_locked(self, now: float) -> None:
        for proxy_id, record in list(self._bad_proxies.items()):
            if now - record["last"] > BAD_PROXY_MEMORY_SECONDS:
                self._bad_proxies.pop(proxy_id, None)

    def mark_bad_proxy(self, proxy_id: Any, reason: str = "") -> int:
        """Запомнить прокси как плохой; вернуть число сбоев за период памяти."""
        proxy = str(proxy_id or "").strip()
        if not proxy:
            return 0
        now = time.monotonic()
        with self._lock:
            self._prune_bad_locked(now)
            previous = self._bad_proxies.get(proxy)
            fails = int(previous["fails"]) + 1 if previous else 1
            hold = min(
                BAD_PROXY_HOLD_MAX_SECONDS,
                BAD_PROXY_HOLD_SECONDS * (2 ** (fails - 1)),
            )
            self._bad_proxies[proxy] = {
                "fails": float(fails),
                "until": now + hold,
                "last": now,
            }
        if fails >= 2:
            self._log(
                f"[PROXY MANAGER] прокси {proxy} сбоит повторно "
                f"(сбой #{fails} за {int(BAD_PROXY_MEMORY_SECONDS // 3600)} ч); "
                f"не выдаю его {int(hold // 60)} мин ({reason or 'proxy_error'})"
            )
        else:
            self._log(
                f"[PROXY MANAGER] прокси {proxy} признан плохим; "
                f"не выдаю его {int(hold // 60)} мин ({reason or 'proxy_error'})"
            )
        return fails

    def bad_proxy_ids(self) -> list[str]:
        """Прокси, которые сейчас нельзя брать (пауза ещё идёт)."""
        now = time.monotonic()
        with self._lock:
            self._prune_bad_locked(now)
            return sorted(
                proxy_id
                for proxy_id, record in self._bad_proxies.items()
                if record["until"] > now
            )

    def _log_known_bad_returned(self, proxy_id: str) -> None:
        """Пауза закончилась, и прокси с историей сбоев выдан снова."""
        with self._lock:
            record = self._bad_proxies.get(proxy_id)
            fails = int(record["fails"]) if record else 0
            ago = (time.monotonic() - record["last"]) if record else 0.0
        if fails:
            self._log(
                f"[PROXY MANAGER] прокси {proxy_id} с историей сбоев "
                f"({fails}) выдан снова через {int(ago // 60)} мин; "
                "при новом сбое пауза удвоится"
            )

    def get_lease(
        self,
        account_id: Any,
        *,
        extra_excluded=None,
        preserve_rotation_exclusions=False,
        replace=False,
    ) -> Optional[dict[str, Any]]:
        account = _account(account_id)
        if not account:
            raise ProxyManagerError("proxy manager requires an account id")
        with self._lock:
            current = self._leases.get(account)
            if current and not current["lost"]:
                return dict(current["lease"])
            excluded = set(self._rotation_exclusions.get(account, set()))
        if isinstance(extra_excluded, (str, bytes)):
            extra_excluded = [extra_excluded]
        if isinstance(extra_excluded, (list, tuple, set)):
            excluded.update(
                str(value).strip()
                for value in extra_excluded
                if str(value).strip()
            )
        # Плохие прокси исключаем всегда (для всех аккаунтов), но в
        # _rotation_exclusions они не пишутся: это отдельная память.
        bad_ids = set(self.bad_proxy_ids())
        payload_excluded = set(excluded) | bad_ids
        response = self._post("/acquire", {
            "account_id": account,
            "count": 1,
            "ttl_seconds": self.ttl_seconds,
            "purpose": os.environ.get("BLS_PROXY_MANAGER_PURPOSE", "bls")[:30],
            "client_id": os.environ.get(
                "BLS_PROXY_MANAGER_CLIENT_ID", "bls-clicker"
            )[:120],
            "exclude": sorted(payload_excluded),
            "replace": bool(replace),
        })
        rows = response.get("leases")
        if not isinstance(rows, list) or not rows:
            return None
        lease = self._validate_lease(rows[0])
        if lease["proxy_id"] in payload_excluded:
            if lease["proxy_id"] in bad_ids:
                self._log(
                    f"[PROXY MANAGER] сервер снова выдал плохой прокси "
                    f"{lease['proxy_id']}; отклонён"
                )
            self._post("/release", {
                "lease_id": lease["lease_id"],
                "reason": "acquire_returned_excluded_proxy",
                "detail": {
                    "stage": "lease_validation",
                    "reason_code": "excluded_proxy_returned",
                },
            })
            return None
        self._log_known_bad_returned(lease["proxy_id"])
        action = str(response.get("account_action") or "").strip()
        if action:
            lease["_account_action"] = action
        now = time.monotonic()
        deadline = self._deadline(lease.get("expires_at"), self.ttl_seconds)
        with self._lock:
            self._leases[account] = {
                "lease": lease,
                "deadline": deadline,
                "renew_at": now + max(
                    1.0, min(240.0, max(1.0, deadline - now - 60.0))
                ),
                "lost": False,
            }
            if preserve_rotation_exclusions:
                self._rotation_exclusions[account] = set(excluded)
            else:
                self._rotation_exclusions.pop(account, None)
        self._ensure_renew_thread()
        return dict(lease)

    def clear_rotation_exclusions(self, account_id: Any) -> None:
        account = _account(account_id)
        if not account:
            return
        with self._lock:
            self._rotation_exclusions.pop(account, None)

    def acknowledge_profile_reset(self, account_id: Any) -> bool:
        account = _account(account_id)
        if not account:
            return False
        self._post("/account/profile_reset", {"account_id": account})
        with self._lock:
            record = self._leases.get(account)
            if record:
                record["lease"].pop("_account_action", None)
        return True

    def rotate_for_account(
        self, account_id: Any, reason="proxy_error", error_code=None,
        phase=None, detail=None, exclude_proxy_ids=None,
    ) -> Optional[dict[str, Any]]:
        """Release the current lease and acquire a different proxy."""
        account = _account(account_id)
        if isinstance(exclude_proxy_ids, (str, bytes)):
            exclude_proxy_ids = [exclude_proxy_ids]
        supplied_exclusions = (
            {
                str(value).strip()[:200]
                for value in exclude_proxy_ids
                if str(value).strip()
            }
            if isinstance(exclude_proxy_ids, (list, tuple, set))
            else set()
        )
        preserve_exclusions = (
            str(error_code or "").strip().upper() == "HTTP_403"
        )
        with self._lock:
            record = self._leases.get(account)
            # Keep the last proxy identity even after a renewal failure.  A
            # lost lease still needs to be excluded from the replacement
            # request; otherwise the manager could hand the expired route
            # straight back to this account.
            current = dict(record["lease"]) if record else None
            excluded = set(self._rotation_exclusions.get(account, set()))
        excluded.update(supplied_exclusions)
        if not current:
            with self._lock:
                if excluded:
                    self._rotation_exclusions[account] = set(excluded)
            return self.get_lease(
                account,
                extra_excluded=excluded,
                preserve_rotation_exclusions=preserve_exclusions,
                replace=bool(excluded),
            )
        payload = {
            "lease_id": current["lease_id"],
            "reason": str(reason or "proxy_error")[:100],
            "detail": _safe_detail(detail),
        }
        if error_code:
            payload["error_code"] = str(error_code)[:100]
        if phase:
            payload["phase"] = str(phase)[:100]
        # Прокси сам не пропускает трафик: запоминаем сразу, чтобы не отдать
        # его ни этому, ни другому аккаунту (сервер получит код отдельно).
        if str(error_code or "").strip().upper() in BAD_PROXY_CODES:
            self.mark_bad_proxy(current.get("proxy_id"), str(reason or ""))
        # Release first, then explicitly exclude the old proxy on acquire.
        try:
            self._post("/release", payload)
        except ProxyManagerError as exc:
            # A lease that has already expired cannot be released, but its
            # proxy must still be excluded while acquiring the replacement.
            if exc.status_code not in {404, 410}:
                raise
            self._log(
                f"[PROXY MANAGER] lease already expired for {account}; "
                "acquiring a replacement while excluding its route"
            )
        # Do not let a later get_lease() hand the just-released route back if
        # the replacement pool is temporarily empty or the acquire call fails.
        with self._lock:
            record = self._leases.get(account)
            if (
                record
                and str(record["lease"].get("lease_id") or "")
                == str(current.get("lease_id") or "")
            ):
                self._leases.pop(account, None)
            excluded = self._rotation_exclusions.setdefault(account, set())
            excluded.add(str(current.get("proxy_id") or ""))
            excluded.discard("")
            excluded.update(supplied_exclusions)
            excluded = set(excluded)
        return self.get_lease(
            account,
            extra_excluded=excluded,
            preserve_rotation_exclusions=preserve_exclusions,
            replace=True,
        )

    def report_outcome(self, lease_id: Any, outcome: Any, http_status=None,
                       detail=None, phase=None) -> bool:
        lease = str(lease_id or "").strip()
        if not lease:
            return False
        status = int(http_status) if http_status is not None else None
        normalized = str(outcome or "error").strip().lower()
        ok = normalized in {
            "cycle_ok", "success", "restart_flow",
            "page_error_retry", "captcha_limit", "slot_taken",
        } and status not in {403, 429}
        self._post("/report", {
            "lease_id": lease,
            "event_type": "cycle_ok" if ok else "error",
            "error_code": (
                "HTTP_403" if status == 403 else
                "HTTP_429" if status == 429 else None
            ),
            "phase": str(phase or "worker_cycle")[:100],
            "detail": _safe_detail(detail),
        })
        return True

    def lease_lost(self, account_id: Any) -> bool:
        with self._lock:
            record = self._leases.get(_account(account_id))
            return bool(record and record["lost"])

    def _ensure_renew_thread(self):
        with self._lock:
            if self._renew_thread and self._renew_thread.is_alive():
                return
            self._stop.clear()
            self._renew_thread = threading.Thread(
                target=self._renew_loop, name="bls-proxy-renew", daemon=True
            )
            self._renew_thread.start()

    def _renew_loop(self):
        while not self._stop.is_set():
            now = time.monotonic()
            with self._lock:
                due = [
                    (account, dict(record))
                    for account, record in self._leases.items()
                    if not record["lost"] and record["renew_at"] <= now
                ]
            for account, record in due:
                try:
                    response = self._post("/renew", {
                        "lease_id": record["lease"]["lease_id"],
                        "ttl_seconds": self.ttl_seconds,
                    })
                    expires = str(response.get("expires_at") or "")
                    deadline = self._deadline(expires, self.ttl_seconds)
                    with self._lock:
                        current = self._leases.get(account)
                        if current and current["lease"]["lease_id"] == record["lease"]["lease_id"]:
                            current["lease"]["expires_at"] = expires
                            current["deadline"] = deadline
                            current["renew_failures"] = 0
                            current["renew_at"] = time.monotonic() + max(
                                1.0, min(240.0, max(1.0, deadline - time.monotonic() - 60.0))
                            )
                            renewed = True
                        else:
                            renewed = False
                    if renewed:
                        self._log(
                            f"[PROXY MANAGER] lease renewed for {account}; "
                            f"expires_at={expires}"
                        )
                except ProxyManagerError as exc:
                    retry_in = None
                    failed = False
                    with self._lock:
                        current = self._leases.get(account)
                        if (
                            current
                            and current["lease"]["lease_id"]
                            == record["lease"]["lease_id"]
                        ):
                            remaining = current["deadline"] - time.monotonic()
                            failures = int(
                                current.get("renew_failures") or 0
                            ) + 1
                            current["renew_failures"] = failures
                            if remaining > LEASE_SAFETY_SECONDS:
                                retry_in = min(
                                    LEASE_RENEW_RETRY_SECONDS,
                                    max(1.0, remaining - LEASE_SAFETY_SECONDS),
                                )
                                current["renew_at"] = (
                                    time.monotonic() + retry_in
                                )
                            else:
                                current["lost"] = True
                                failed = True
                    if retry_in is not None:
                        self._log(
                            f"[PROXY MANAGER] lease renewal failed for "
                            f"{account}; retrying in {retry_in:g}s: {exc}"
                        )
                    elif failed:
                        self._log(
                            f"[PROXY MANAGER] lease renewal failed for "
                            f"{account}; lease is no longer safe to use: {exc}"
                        )
                    else:
                        # A late failure from the previous route must not
                        # mark the newly acquired lease as lost.
                        self._log(
                            f"[PROXY MANAGER] ignored stale renewal failure "
                            f"for {account}: {exc}"
                        )
            self._wake.wait(1.0)
            self._wake.clear()

    def close(self):
        self._stop.set()
        self._wake.set()