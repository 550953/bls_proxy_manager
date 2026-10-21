import ast, asyncio, os, secrets, logging, sys, time, hashlib
src = open(sys.argv[1], encoding="utf-8").read()
tree = ast.parse(src)
want = ["_token_hash", "_refresh_db_tokens", "_touch_db_token", "require_bot"]
funcs = {n.name: ast.get_source_segment(src, n) for n in tree.body
         if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name in want}
assert set(funcs) == set(want), funcs.keys()

class HTTPException(Exception):
    def __init__(self, code, detail=""): self.code, self.detail = code, detail
def Header(default=""): return default
class Request:
    def __init__(self): self.state = type("S", (), {})()

class Pool:
    def __init__(self): self.rows, self.fail, self.fetches, self.touches = [], False, 0, 0
    async def fetch(self, q, *a):
        self.fetches += 1
        if self.fail: raise RuntimeError("db down")
        return self.rows
    async def execute(self, q, *a): self.touches += 1

pool = Pool()
g = dict(HTTPException=HTTPException, Header=Header, Request=Request, secrets=secrets, hashlib=hashlib,
         asyncio=asyncio, time=time, SCHEMA="s", log=logging.getLogger("t"),
         BOT_TOKEN_PURPOSES={"bls": "tok-bls", "visaglobal": "tok-vfs"}, BOT_CLIENT_TOKENS={"visaglobal": {"tok-env-alice": "alice"}},
         pools={"reporter": pool}, _db_tokens={}, _db_tokens_at=0.0, _db_tokens_try_at=0.0, _db_touch_at={},
         DB_TOKENS_TTL_S=15.0, _db_tokens_lock=asyncio.Lock())
for n in want: exec(funcs[n], g)
H = g["_token_hash"]

async def auth(tok):
    r = Request()
    try: return (await g["require_bot"](r, tok), r.state.bot_client)
    except HTTPException as e: return (e.code, None)

async def main():
    out = {}
    out["env общий токен visaglobal"] = await auth("tok-vfs") == ("visaglobal", None)
    out["env клиент alice"] = await auth("tok-env-alice") == ("visaglobal", "alice")
    out["env токены не ходят в базу"] = pool.fetches == 0
    pool.rows = [{"token_hash": H("bpm_new"), "purpose": "visaglobal", "name": "bob"}]
    out["токен из базы bob"] = await auth("bpm_new") == ("visaglobal", "bob")
    await asyncio.sleep(0.05)
    out["last_used обновлён в фоне"] = pool.touches == 1
    out["повторный запрос не пишет last_used чаще минуты"] = (await auth("bpm_new"), await asyncio.sleep(0.05))[0] == ("visaglobal", "bob") and pool.touches == 1
    before = pool.fetches
    out["неизвестный токен -> 401"] = (await auth("bpm_bad"))[0] == 401
    for _ in range(5): await auth("bpm_bad")
    out["спам неверными токенами: база не чаще 1 раза в секунду"] = pool.fetches - before <= 1
    pool.rows = []   # клиента отключили
    await g["_refresh_db_tokens"](force=True)
    out["отключённый токен -> 401 сразу после обновления"] = (await auth("bpm_new"))[0] == 401
    pool.rows = [{"token_hash": H("bpm_later"), "purpose": "bls", "name": "carol"}]
    await asyncio.sleep(1.05)
    out["токен, созданный только что, принимается без ожидания TTL"] = await auth("bpm_later") == ("bls", "carol")
    pool.fail = True; await asyncio.sleep(1.05)
    out["база упала: env-токены работают"] = await auth("tok-bls") == ("bls", None)
    out["база упала: неизвестный токен -> 401, не 500"] = (await auth("zzz"))[0] == 401
    out["пустой токен -> 401"] = (await auth(""))[0] == 401
    for k, v in out.items(): print("PASS" if v else "FAIL", k)
    assert all(out.values()); print("TOKENS UNIT OK")
asyncio.run(main())
