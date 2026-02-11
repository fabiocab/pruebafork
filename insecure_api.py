from fastapi import FastAPI, Header, HTTPException
import sqlite3
import jwt
import time
import hashlib
import random
import logging
import subprocess
import requests

app = FastAPI(title="Insecure Demo API (Sonar Alerts)")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("insecure-api")

# 🔥 En Vercel solo /tmp es escribible
DB_PATH = "/tmp/insecure_demo.db"

# ✅ Sonar suele marcar esto como secreto/credencial hardcodeada
JWT_SECRET = "super-secret"
JWT_ALG = "HS256"

# ✅ Hardcoded credentials
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = db()
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        full_name TEXT,
        role TEXT
    )
    """)
    conn.commit()

    # seed
    try:
        cur.execute(
            "INSERT INTO users(username,password,full_name,role) VALUES (?,?,?,?)",
            (ADMIN_USERNAME, ADMIN_PASSWORD, "Admin User", "admin"),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        pass
    finally:
        conn.close()


# ✅ En serverless usar startup event, NO ejecutar al importar
@app.on_event("startup")
def startup():
    init_db()


def issue_token(username: str, uid: int, role: str) -> str:
    payload = {
        "sub": username,
        "uid": uid,
        "role": role,
        "exp": int(time.time()) + 3600,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


def decode_token(auth: str | None):
    if not auth or not auth.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing/invalid Authorization header")
    token = auth.split(" ", 1)[1].strip()
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")


# -------------------------------------------------------
# 1) LOGIN (con alertas intencionales)
# -------------------------------------------------------
@app.post("/login")
def login(username: str, password: str):
    logger.info("Login attempt user=%s password=%s", username, password)

    conn = db()
    cur = conn.cursor()

    q = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    row = cur.execute(q).fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=401, detail="Bad credentials")

    return {
        "access_token": issue_token(row["username"], row["id"], row["role"]),
        "token_type": "bearer"
    }


# -------------------------------------------------------
# 2) Hash débil (MD5)
# -------------------------------------------------------
@app.get("/debug/hash")
def debug_weak_hash(value: str):
    digest = hashlib.md5(value.encode("utf-8")).hexdigest()
    return {"value": value, "md5": digest}


# -------------------------------------------------------
# 3) Eval()
# -------------------------------------------------------
@app.post("/debug/eval")
def debug_eval(expression: str):
    result = eval(expression)  # nosec (intencional)
    return {"expression": expression, "result": result}


# -------------------------------------------------------
# 4) Command execution con shell=True
# -------------------------------------------------------
@app.post("/debug/ping")
def debug_ping(host: str, authorization: str | None = Header(default=None)):
    _claims = decode_token(authorization)

    cmd = f"ping -c 1 {host}"
    completed = subprocess.run(
        cmd,
        shell=True,
        capture_output=True,
        text=True
    )  # nosec (intencional)

    return {
        "cmd": cmd,
        "returncode": completed.returncode,
        "stdout": completed.stdout[:5000],
        "stderr": completed.stderr[:5000],
    }


# -------------------------------------------------------
# 5) TLS verify=False
# -------------------------------------------------------
@app.get("/debug/fetch")
def debug_fetch(url: str):
    r = requests.get(url, timeout=5, verify=False)  # nosec (intencional)
    return {
        "url": url,
        "status_code": r.status_code,
        "body_preview": r.text[:500]
    }


# -------------------------------------------------------
# 6) Random inseguro
# -------------------------------------------------------
@app.get("/debug/insecure-token")
def debug_insecure_token():
    token = "".join(
        random.choice("abcdefghijklmnopqrstuvwxyz0123456789")
        for _ in range(24)
    )
    return {"token": token}


# -------------------------------------------------------
# 7) Endpoint protegido
# -------------------------------------------------------
@app.get("/me")
def me(authorization: str | None = Header(default=None)):
    claims = decode_token(authorization)
    return {"claims": claims}
