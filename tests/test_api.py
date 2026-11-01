import os, tempfile
os.environ.update(DB_PATH=tempfile.mktemp(suffix=".db"), ADMIN_USER="admin", ADMIN_PASSWORD="TestPass123")
from fastapi.testclient import TestClient
from app.main import app
c = TestClient(app)

def hdr(u="admin", p="TestPass123"):
    r = c.post("/api/auth/login", json=dict(username=u, password=p))
    return {"Authorization": "Bearer " + r.json()["token"]}
RUN = dict(profile="ransomware-crew", target="lab-win-01")

def test_wrong_password_rejected():
    assert c.post("/api/auth/login", json=dict(username="admin", password="nope")).status_code == 401

def test_api_requires_login():
    assert c.get("/api/catalog").status_code == 401
    assert c.get("/api/catalog", headers={"Authorization": "Bearer fake.token"}).status_code == 401

def test_register_makes_viewer_who_cannot_run_or_toggle():
    assert c.post("/api/auth/register", json=dict(username="vera", password="longpass1")).json()["role"] == "viewer"
    h = hdr("vera", "longpass1")
    assert c.get("/api/catalog", headers=h).status_code == 200
    assert c.post("/api/runs", json=RUN, headers=h).status_code == 403
    assert c.patch("/api/rules/R4?enabled=true", headers=h).status_code == 403

def test_weak_or_duplicate_registration_rejected():
    assert c.post("/api/auth/register", json=dict(username="bob", password="short")).status_code == 400
    assert c.post("/api/auth/register", json=dict(username="admin", password="longpass1")).status_code == 409

def test_admin_can_create_analyst_who_can_run():
    assert c.post("/api/users", json=dict(username="ann", password="longpass1", role="analyst"), headers=hdr()).status_code == 200
    r = c.post("/api/runs", json=RUN, headers=hdr("ann", "longpass1")).json()
    assert r["by"] == "ann" and r["total"] == 7

def test_scope_guard_blocks_real_targets():
    assert c.post("/api/runs", json=dict(profile="ransomware-crew", target="example.com"), headers=hdr()).status_code == 403

def test_enabling_rules_gives_full_coverage_and_report_lists_gaps():
    h = hdr(); rid = c.post("/api/runs", json=RUN, headers=h).json()["id"]
    assert "MISSED" in c.get(f"/api/runs/{rid}/report", headers=h).text
    for r in ["R1", "R3", "R4", "R5", "R9", "R10"]: c.patch(f"/api/rules/{r}?enabled=true", headers=h)
    assert c.post("/api/runs", json=RUN, headers=h).json()["score"] == 100

def test_lockout_after_repeated_failures():
    for _ in range(5): c.post("/api/auth/login", json=dict(username="ghost", password="x"))
    assert c.post("/api/auth/login", json=dict(username="ghost", password="x")).status_code == 429
