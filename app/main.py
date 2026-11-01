import json, os, re, sqlite3, time
from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from . import auth, engine

DB = os.getenv("DB_PATH", "sim.db")
LAB = set(os.getenv("LAB_TARGETS", "lab-win-01,lab-linux-01,lab-web-01").split(","))
ROLES = ("admin", "analyst", "viewer")
FAILS = {}  # username -> (failed attempts, locked until)
app = FastAPI(title="Adversary Emulation & Attack Simulation Platform")

def db():
    c = sqlite3.connect(DB, timeout=10); c.row_factory = sqlite3.Row
    c.execute("CREATE TABLE IF NOT EXISTS runs(id INTEGER PRIMARY KEY, ts REAL, data TEXT)")
    c.execute("CREATE TABLE IF NOT EXISTS rules(id TEXT PRIMARY KEY, enabled INT)")
    c.execute("CREATE TABLE IF NOT EXISTS users(username TEXT PRIMARY KEY, pw TEXT, role TEXT, created REAL)")
    if "last_login" not in [r[1] for r in c.execute("PRAGMA table_info(users)")]:
        c.execute("ALTER TABLE users ADD COLUMN last_login REAL")
    c.executemany("INSERT OR IGNORE INTO rules VALUES(?,?)", [(r[0], int(r[3])) for r in engine.RULES])
    if not c.execute("SELECT 1 FROM users").fetchone():
        pw = os.getenv("ADMIN_PASSWORD")
        if not pw:
            pw = "ChangeMe123!"; print("WARNING: ADMIN_PASSWORD not set, using demo password. Set it before deploying.")
        c.execute("INSERT INTO users(username,pw,role,created) VALUES(?,?,?,?)", (os.getenv("ADMIN_USER", "admin").lower(), auth.hash_pw(pw), "admin", time.time()))
    c.commit(); return c

class Creds(BaseModel):
    username: str
    password: str
class NewUser(Creds):
    role: str = "viewer"
class RunReq(BaseModel):
    profile: str
    target: str

def current(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "): raise HTTPException(401, "Please log in")
    d = auth.read_token(authorization[7:])
    if not d: raise HTTPException(401, "Session expired, please log in again")
    c = db(); row = c.execute("SELECT role FROM users WHERE username=?", (d["u"],)).fetchone(); c.close()
    if not row: raise HTTPException(401, "This account no longer exists")
    return dict(username=d["u"], role=row["role"])

def need(*roles):
    def dep(u=Depends(current)):
        if u["role"] not in roles: raise HTTPException(403, "This action needs the role: " + " or ".join(roles))
        return u
    return dep

def create_user(name, pw, role):
    name = name.strip().lower()
    if not re.fullmatch(r"[a-z0-9_]{3,32}", name): raise HTTPException(400, "Username: 3-32 letters, numbers or _")
    if len(pw) < 8: raise HTTPException(400, "Password must be at least 8 characters")
    c = db()
    try:
        c.execute("INSERT INTO users(username,pw,role,created) VALUES(?,?,?,?)", (name, auth.hash_pw(pw), role, time.time())); c.commit()
    except sqlite3.IntegrityError:
        c.rollback(); raise HTTPException(409, "Username already taken")
    finally:
        c.close()
    return dict(username=name, role=role)

@app.post("/api/auth/login")
def login(c: Creds):
    name = c.username.strip().lower(); n, until = FAILS.get(name, (0, 0))
    if until > time.time(): raise HTTPException(429, "Too many failed attempts. Try again in a minute.")
    row = db().execute("SELECT * FROM users WHERE username=?", (name,)).fetchone()
    if not row or not auth.check_pw(c.password, row["pw"]):
        FAILS[name] = (n + 1, time.time() + 60 if n + 1 >= 5 else 0)
        raise HTTPException(401, "Invalid username or password")
    FAILS.pop(name, None)
    c2 = db(); c2.execute("UPDATE users SET last_login=? WHERE username=?", (time.time(), name)); c2.commit(); c2.close()
    return dict(token=auth.make_token(name, row["role"]), username=name, role=row["role"])

@app.post("/api/auth/register")
def register(c: Creds): return create_user(c.username, c.password, "viewer")

@app.post("/api/users")
def add_user(u: NewUser, _=Depends(need("admin"))):
    if u.role not in ROLES: raise HTTPException(400, "Role must be one of " + ", ".join(ROLES))
    return create_user(u.username, u.password, u.role)

@app.get("/api/users")
def list_users(_=Depends(need("admin"))):
    c = db(); rows = [dict(r) for r in c.execute("SELECT username,role,created,last_login FROM users ORDER BY created")]; c.close()
    return rows

@app.patch("/api/users/{name}")
def set_role(name: str, role: str, me=Depends(need("admin"))):
    if role not in ROLES: raise HTTPException(400, "Role must be one of " + ", ".join(ROLES))
    if name == me["username"]: raise HTTPException(400, "You cannot change your own role")
    c = db(); n = c.execute("UPDATE users SET role=? WHERE username=?", (role, name)).rowcount; c.commit(); c.close()
    if not n: raise HTTPException(404, "No such user")
    return dict(username=name, role=role)

@app.delete("/api/users/{name}")
def del_user(name: str, me=Depends(need("admin"))):
    if name == me["username"]: raise HTTPException(400, "You cannot delete your own account")
    c = db(); n = c.execute("DELETE FROM users WHERE username=?", (name,)).rowcount; c.commit(); c.close()
    if not n: raise HTTPException(404, "No such user")
    return dict(deleted=name)

@app.get("/api/auth/me")
def me(user=Depends(current)): return user

def rules_state():
    en = {r["id"]: bool(r["enabled"]) for r in db().execute("SELECT * FROM rules")}
    return [dict(id=i, title=t, covers=c, enabled=en[i]) for i, t, c, _ in engine.RULES]

@app.get("/api/catalog")
def catalog(_=Depends(current)):
    return dict(tactics=engine.TACTICS, techniques=list(engine.TECHNIQUES.values()),
                profiles=[dict(id=k, **v) for k, v in engine.PROFILES.items()],
                targets=sorted(LAB), rules=rules_state())

@app.patch("/api/rules/{rid}")
def toggle(rid: str, enabled: bool, _=Depends(need("admin"))):
    c = db()
    if not c.execute("UPDATE rules SET enabled=? WHERE id=?", (int(enabled), rid)).rowcount: raise HTTPException(404, "Unknown rule")
    c.commit(); return rules_state()

@app.post("/api/runs")
def run(req: RunReq, user=Depends(need("admin", "analyst"))):
    if req.profile not in engine.PROFILES: raise HTTPException(404, "Unknown adversary profile")
    if req.target not in LAB: raise HTTPException(403, f"Target outside lab scope. Allowed: {sorted(LAB)}")
    res = engine.simulate(req.profile, req.target, {r["id"] for r in rules_state() if r["enabled"]})
    res["by"] = user["username"]
    c = db(); cur = c.execute("INSERT INTO runs(ts,data) VALUES(?,?)", (time.time(), json.dumps(res))); c.commit()
    return dict(id=cur.lastrowid, ts=time.time(), **res)

def load(rid):
    r = db().execute("SELECT * FROM runs WHERE id=?", (rid,)).fetchone()
    if not r: raise HTTPException(404, "Run not found")
    return dict(id=r["id"], ts=r["ts"], **json.loads(r["data"]))

@app.get("/api/runs")
def runs(_=Depends(current)):
    return [dict(id=r["id"], ts=r["ts"], **{k: v for k, v in json.loads(r["data"]).items() if k != "steps"})
            for r in db().execute("SELECT * FROM runs ORDER BY id DESC LIMIT 20")]

@app.get("/api/runs/{rid}")
def get_run(rid: int, _=Depends(current)): return load(rid)

@app.get("/api/runs/{rid}/report", response_class=PlainTextResponse)
def report(rid: int, _=Depends(current)): return engine.report_md(load(rid))

@app.get("/healthz")
def health(): return {"ok": True}

app.mount("/static", StaticFiles(directory="static"), name="static")
@app.get("/")
def index(): return FileResponse("static/index.html")
@app.get("/admin")
def admin_page(): return FileResponse("static/admin.html")
@app.get("/login")
def login_page(): return FileResponse("static/login.html")