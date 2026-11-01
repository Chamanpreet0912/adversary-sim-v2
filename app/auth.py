"""Password hashing and signed session tokens (standard library only)."""
import base64, hashlib, hmac, json, os, secrets, time
SECRET = os.getenv("SECRET_KEY") or secrets.token_hex(32)
TTL = 8 * 3600

def hash_pw(pw, salt=None):
    salt = salt or secrets.token_hex(16)
    return salt + "$" + hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), 200_000).hex()

def check_pw(pw, stored):
    salt, h = stored.split("$")
    return hmac.compare_digest(hash_pw(pw, salt).split("$")[1], h)

def _sig(body): return hmac.new(SECRET.encode(), body.encode(), "sha256").hexdigest()

def make_token(user, role):
    body = base64.urlsafe_b64encode(json.dumps({"u": user, "r": role, "e": int(time.time()) + TTL}).encode()).decode()
    return body + "." + _sig(body)

def read_token(tok):
    try:
        body, sig = tok.rsplit(".", 1)
        if not hmac.compare_digest(sig, _sig(body)): return None
        d = json.loads(base64.urlsafe_b64decode(body))
        return d if d["e"] > time.time() else None
    except Exception:
        return None
