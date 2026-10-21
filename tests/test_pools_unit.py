import ast, asyncio, secrets, logging, sys, time, hashlib
from typing import Optional
src = open(sys.argv[1], encoding="utf-8").read()
tree = ast.parse(src)
want = ["_token_hash", "_refresh_db_tokens", "_touch_db_token", "require_bot", "acquire"]
funcs = {n.name: ast.get_source_segment(src, n) for n in tree.body
         if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name in want}
assert set(funcs) == set(want), funcs.keys()

class HTTPException(Exception):
    def __init__(self, code, detail=""): self.code, self.detail = code, detail
class UndefinedFunctionError(Exception): pass
class asyncpg:  # заглушка модуля
    UndefinedFunctionError = UndefinedFunctionError
    PostgresError = Exception
def Header(default=""): return default
def Depends(x): return x
class Request:
    def __init__(self): self.state = type("S", (), {})()
class Req:
    def __init__(self, purpose="visaglobal"):
        self.account_id, self.count, self.ttl_seconds, self.purpose = "acc", 1, 60, purpose
        self.client_id, self.exclude, self.replace = None, [], True

class Row(dict): pass
class Issuer:
    def __init__(self): self.calls, self.scoped_missing = [], False
    async def fetch(self, q, *a):
        self.calls.append(("fetch", q, a))
        if "acquire_proxies_scoped" in q and self.scoped_missing: raise UndefinedFunctionError()
        return []
    async def fetchval(self, q, *a):
        self.calls.append(("fetchval", q, a)); return 77
class Reporter:
    def __init__(self): self.rows = []
    async def fetch(self, q, *a): return self.rows
    async def execute(self, q, *a): pass
issuer, reporter = Issuer(), Reporter()
g = dict(AcquireRequest=Req, HTTPException=HTTPException, Header=Header, Depends=Depends, Request=Request, secrets=secrets, hashlib=hashlib,
         asyncio=asyncio, time=time, SCHEMA="s", log=logging.getLogger("t"), asyncpg=asyncpg, Optional=Optional,
         BOT_TOKEN_PURPOSES={"visaglobal": "tok-vfs"}, BOT_CLIENT_TOKENS={},
         pools={"reporter": reporter, "issuer": issuer}, _db_tokens={}, _db_tokens_at=0.0, _db_tokens_try_at=0.0,
         _db_touch_at={}, DB_TOKENS_TTL_S=15.0, _db_tokens_lock=asyncio.Lock())
for n in want: exec(funcs[n], g)
H = g["_token_hash"]

async def auth(tok):
    r = Request()
    try: scope = await g["require_bot"](r, tok)
    except HTTPException as e: return (e.code, r)
    return (scope, r)

async def main():
    out = {}
    reporter.rows = [
        {"token_hash": H("bpm_all"),  "purpose": "visaglobal", "name": "all-pools", "pools": None},
        {"token_hash": H("bpm_ab"),   "purpose": "visaglobal", "name": "ab", "pools": ["A", "B"]},
        {"token_hash": H("bpm_old"),  "purpose": "visaglobal", "name": "old-format"},   # строка без колонки pools (миграция 26 не накатана)
    ]
    s, r = await auth("bpm_all"); out["токен без ограничения: pools=None"] = (s, r.state.bot_pools) == ("visaglobal", None)
    s, r = await auth("bpm_ab");  out["токен с пулами: список доходит до запроса"] = (s, r.state.bot_pools, r.state.bot_client) == ("visaglobal", ["A", "B"], "ab")
    s, r = await auth("bpm_old"); out["строка без колонки pools не ломает авторизацию"] = (s, r.state.bot_pools) == ("visaglobal", None)
    s, r = await auth("tok-vfs"); out["env-токен: pools=None"] = (s, r.state.bot_pools) == ("visaglobal", None)
    s, r = await auth("bad");     out["неверный токен -> 401"] = s == 401

    # acquire
    async def run_acquire(pools_allowed):
        issuer.calls.clear()
        r = Request(); r.state.bot_client = None; r.state.bot_pools = pools_allowed
        res = await g["acquire"](Req(), r, "visaglobal")
        return res
    res = await run_acquire(None)
    out["без ограничения: обычный acquire_proxies"] = any("acquire_proxies(" in c[1] and "scoped" not in c[1] for c in issuer.calls) \
        and not any("scoped" in c[1] for c in issuer.calls) and any("next_available_in($1)" in c[1] for c in issuer.calls)
    res = await run_acquire(["A", "B"])
    sc = [c for c in issuer.calls if "acquire_proxies_scoped" in c[1]]
    out["с пулами: acquire_proxies_scoped с нужным списком"] = len(sc) == 1 and sc[0][2][-1] == ["A", "B"]
    out["с пулами: пустой ответ считает ожидание по этим пулам"] = any("next_available_in_scoped" in c[1] and c[2][1] == ["A", "B"] for c in issuer.calls) \
        and res["leases"] == [] and res["retry_after_seconds"] == 77
    issuer.scoped_missing = True
    try: await run_acquire(["A"]); out["без миграции 26 ограниченный токен не получает чужие пулы (503)"] = False
    except HTTPException as e: out["без миграции 26 ограниченный токен не получает чужие пулы (503)"] = e.code == 503
    for k, v in out.items(): print("PASS" if v else "FAIL", k)
    assert all(out.values()); print("POOLS UNIT OK")
asyncio.run(main())
