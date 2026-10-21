"""Pixelsphere - tiny self-hosted server (Python 3.8+, standard library only).

    python3 server.py                  -> http://localhost:8080
    python3 server.py --host 0.0.0.0   -> reachable from your network
    python3 server.py --port 9000

Everything is stored in ./data  (users.json, posts.json, sessions.json, uploads/).
"""
import argparse, base64, hashlib, hmac, json, os, re, secrets, threading, time
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse, parse_qs

ROOT = Path(__file__).resolve().parent
DATA, STATIC = ROOT / "data", ROOT / "static"
UPLOADS = DATA / "uploads"
UPLOADS.mkdir(parents=True, exist_ok=True)

LOCK = threading.RLock()
MAX_BODY = 8 * 1024 * 1024
MAX_IMG = 3 * 1024 * 1024
SESSION_TTL = 30 * 86400
USER_RE = re.compile(r"^[A-Za-z0-9_]{3,20}$")
FILE_RE = re.compile(r"^[0-9a-f]{24}\.jpg$")
FAILS = {}  # ip -> [timestamps] of failed logins


def load(name, default):
    try:
        return json.loads((DATA / name).read_text("utf-8"))
    except (FileNotFoundError, ValueError):
        return default


def save(name, obj):
    tmp = DATA / (name + ".tmp")
    tmp.write_text(json.dumps(obj), "utf-8")
    os.replace(tmp, DATA / name)


users = load("users.json", {})        # uid -> user dict
posts = load("posts.json", [])        # list of post dicts
sessions = load("sessions.json", {})  # sha256(token) -> {uid, exp}
sessions = {k: v for k, v in sessions.items() if v["exp"] > time.time() and v["uid"] in users}


class ApiError(Exception):
    def __init__(self, code, msg):
        self.code, self.msg = code, msg


def hash_pw(pw, salt_hex):
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt_hex), 200_000).hex()


def make_pw(pw):
    salt = secrets.token_hex(16)
    return {"salt": salt, "hash": hash_pw(pw, salt)}


def check_pw(u, pw):
    return hmac.compare_digest(hash_pw(pw, u["salt"]), u["hash"])


def find_user(name):
    n = name.lower()
    return next((u for u in users.values() if u["username"].lower() == n), None)


def save_image(data_url):
    m = re.match(r"^data:image/jpeg;base64,([A-Za-z0-9+/=]+)$", data_url or "")
    if not m:
        raise ApiError(400, "Image must be a JPEG.")
    raw = base64.b64decode(m.group(1))
    if len(raw) > MAX_IMG or not raw.startswith(b"\xff\xd8\xff"):
        raise ApiError(400, "Invalid or too large image.")
    name = secrets.token_hex(12) + ".jpg"
    (UPLOADS / name).write_bytes(raw)
    return name


def drop_file(name):
    if name and FILE_RE.match(name):
        try:
            (UPLOADS / name).unlink()
        except FileNotFoundError:
            pass


def pub(u):
    return {"username": u["username"], "name": u["name"], "bio": u["bio"],
            "avatar": "/uploads/" + u["avatar"] if u["avatar"] else "", "logo": u["logo"]}


def fmt(p, me):
    a = users.get(p["uid"])
    return {"id": p["id"], "user": pub(a) if a else {"username": "deleted", "name": "Deleted user", "bio": "", "avatar": "", "logo": None},
            "text": p["text"], "img": "/uploads/" + p["img"], "ts": p["ts"],
            "likes": len(p["likes"]), "liked": me["id"] in p["likes"]}


def clean_str(v, n):
    return v.strip()[:n] if isinstance(v, str) else ""


def valid_color(c):
    return isinstance(c, str) and re.match(r"^#[0-9a-fA-F]{6}$", c)


class H(BaseHTTPRequestHandler):
    server_version = "Pixelsphere"

    def log_message(self, *a):
        pass

    # ---- plumbing ----
    def send_json(self, code, obj, cookie=None):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(body)

    def cookie_str(self, token, ttl):
        s = f"ps={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={ttl}"
        if self.headers.get("X-Forwarded-Proto") == "https":
            s += "; Secure"
        return s

    def token(self):
        for part in self.headers.get("Cookie", "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == "ps":
                return v
        return ""

    def current_user(self):
        t = self.token()
        s = sessions.get(hashlib.sha256(t.encode()).hexdigest()) if t else None
        if s and s["exp"] > time.time():
            return users.get(s["uid"])
        return None

    def static(self, path):
        if path == "/":
            f, ctype = STATIC / "index.html", "text/html; charset=utf-8"
        elif path.startswith("/uploads/") and FILE_RE.match(path[9:]):
            f, ctype = UPLOADS / path[9:], "image/jpeg"
        else:
            return self.send_json(404, {"error": "Not found"})
        try:
            body = f.read_bytes()
        except FileNotFoundError:
            return self.send_json(404, {"error": "Not found"})
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cache-Control", "public, max-age=31536000, immutable" if ctype == "image/jpeg" else "no-cache")
        self.end_headers()
        self.wfile.write(body)

    def route(self, method):
        parsed = urlparse(self.path)
        path = parsed.path
        if method == "GET" and not path.startswith("/api/"):
            return self.static(path)
        if not path.startswith("/api/"):
            return self.send_json(404, {"error": "Not found"})
        body = {}
        if method != "GET":
            if "application/json" not in self.headers.get("Content-Type", ""):
                return self.send_json(400, {"error": "JSON required"})
            n = int(self.headers.get("Content-Length") or 0)
            if n > MAX_BODY:
                return self.send_json(413, {"error": "Too large"})
            try:
                body = json.loads(self.rfile.read(n) or b"{}")
                assert isinstance(body, dict)
            except Exception:
                return self.send_json(400, {"error": "Bad JSON"})
        with LOCK:
            try:
                self.api(method, path, parse_qs(parsed.query), body)
            except ApiError as e:
                self.send_json(e.code, {"error": e.msg})

    do_GET = lambda s: s.route("GET")
    do_POST = lambda s: s.route("POST")
    do_PUT = lambda s: s.route("PUT")
    do_DELETE = lambda s: s.route("DELETE")

    # ---- API ----
    def start_session(self, uid, code=200):
        tok = secrets.token_urlsafe(32)
        sessions[hashlib.sha256(tok.encode()).hexdigest()] = {"uid": uid, "exp": time.time() + SESSION_TTL}
        save("sessions.json", sessions)
        self.send_json(code, {"me": pub(users[uid])}, self.cookie_str(tok, SESSION_TTL))

    def api(self, method, path, q, b):
        me = self.current_user()
        ip = self.client_address[0]

        if (method, path) == ("GET", "/api/me"):
            return self.send_json(200, {"me": pub(me) if me else None})

        if (method, path) == ("POST", "/api/signup"):
            un, pw = clean_str(b.get("username"), 20), b.get("password")
            if not USER_RE.match(un):
                raise ApiError(400, "Username: 3-20 letters, numbers or underscores.")
            if not isinstance(pw, str) or not 8 <= len(pw) <= 200:
                raise ApiError(400, "Password must be at least 8 characters.")
            if find_user(un):
                raise ApiError(409, "That username is taken.")
            uid = secrets.token_hex(8)
            users[uid] = {"id": uid, "username": un, "name": un, "bio": "", "avatar": "", "created": time.time(),
                          "logo": {"start": "#7928ca", "end": "#00dfd8"}, **make_pw(pw)}
            save("users.json", users)
            return self.start_session(uid, 201)

        if (method, path) == ("POST", "/api/login"):
            now = time.time()
            FAILS[ip] = [t for t in FAILS.get(ip, []) if now - t < 300]
            if len(FAILS[ip]) >= 8:
                raise ApiError(429, "Too many attempts. Try again in a few minutes.")
            u, pw = find_user(clean_str(b.get("username"), 20)), b.get("password")
            if not u or not isinstance(pw, str) or not check_pw(u, pw):
                FAILS[ip].append(now)
                raise ApiError(401, "Incorrect username or password.")
            return self.start_session(u["id"])

        if (method, path) == ("POST", "/api/logout"):
            sessions.pop(hashlib.sha256(self.token().encode()).hexdigest(), None)
            save("sessions.json", sessions)
            return self.send_json(200, {"ok": True}, self.cookie_str("", 0))

        if not me:
            raise ApiError(401, "Please log in.")

        if (method, path) == ("GET", "/api/posts"):
            who = find_user(q["user"][0]) if "user" in q else None
            lst = [p for p in posts if not who or p["uid"] == who["id"]]
            lst = sorted(lst, key=lambda p: -p["ts"])[:100]
            return self.send_json(200, {"posts": [fmt(p, me) for p in lst]})

        m = re.match(r"^/api/users/([A-Za-z0-9_]{3,20})$", path)
        if method == "GET" and m:
            u = find_user(m.group(1))
            if not u:
                raise ApiError(404, "No such user.")
            mine = sorted([p for p in posts if p["uid"] == u["id"]], key=lambda p: -p["ts"])
            return self.send_json(200, {"user": pub(u), "posts": [fmt(p, me) for p in mine]})

        if (method, path) == ("POST", "/api/posts"):
            img = save_image(b.get("image"))
            posts.append({"id": secrets.token_hex(6), "uid": me["id"], "text": clean_str(b.get("text"), 500),
                          "img": img, "ts": int(time.time() * 1000), "likes": []})
            save("posts.json", posts)
            return self.send_json(201, {"ok": True})

        m = re.match(r"^/api/posts/([0-9a-f]{12})(/like)?$", path)
        if m:
            p = next((x for x in posts if x["id"] == m.group(1)), None)
            if not p:
                raise ApiError(404, "No such post.")
            if method == "POST" and m.group(2):
                p["likes"].remove(me["id"]) if me["id"] in p["likes"] else p["likes"].append(me["id"])
                save("posts.json", posts)
                return self.send_json(200, {"likes": len(p["likes"]), "liked": me["id"] in p["likes"]})
            if method == "DELETE" and not m.group(2):
                if p["uid"] != me["id"]:
                    raise ApiError(403, "Not your post.")
                posts.remove(p)
                drop_file(p["img"])
                save("posts.json", posts)
                return self.send_json(200, {"ok": True})

        if (method, path) == ("PUT", "/api/profile"):
            un = clean_str(b.get("username"), 20)
            if not USER_RE.match(un):
                raise ApiError(400, "Username: 3-20 letters, numbers or underscores.")
            other = find_user(un)
            if other and other["id"] != me["id"]:
                raise ApiError(409, "That username is taken.")
            logo = b.get("logo") or {}
            if valid_color(logo.get("start")) and valid_color(logo.get("end")):
                me["logo"] = {"start": logo["start"], "end": logo["end"]}
            me["username"], me["name"], me["bio"] = un, clean_str(b.get("name"), 40) or un, clean_str(b.get("bio"), 160)
            av = b.get("avatar")
            if av == "":
                drop_file(me["avatar"]); me["avatar"] = ""
            elif isinstance(av, str):
                new = save_image(av); drop_file(me["avatar"]); me["avatar"] = new
            save("users.json", users)
            return self.send_json(200, {"me": pub(me)})

        if (method, path) == ("POST", "/api/password"):
            if not check_pw(me, b.get("old") if isinstance(b.get("old"), str) else ""):
                raise ApiError(403, "Current password is incorrect.")
            new = b.get("new")
            if not isinstance(new, str) or not 8 <= len(new) <= 200:
                raise ApiError(400, "New password must be at least 8 characters.")
            me.update(make_pw(new))
            for k in [k for k, s in sessions.items() if s["uid"] == me["id"] and k != hashlib.sha256(self.token().encode()).hexdigest()]:
                del sessions[k]
            save("users.json", users); save("sessions.json", sessions)
            return self.send_json(200, {"ok": True})

        if (method, path) == ("DELETE", "/api/account"):
            if not check_pw(me, b.get("password") if isinstance(b.get("password"), str) else ""):
                raise ApiError(403, "Password is incorrect.")
            for p in [p for p in posts if p["uid"] == me["id"]]:
                posts.remove(p); drop_file(p["img"])
            for p in posts:
                if me["id"] in p["likes"]:
                    p["likes"].remove(me["id"])
            drop_file(me["avatar"])
            del users[me["id"]]
            for k in [k for k, s in sessions.items() if s["uid"] == me["id"]]:
                del sessions[k]
            save("users.json", users); save("posts.json", posts); save("sessions.json", sessions)
            return self.send_json(200, {"ok": True}, self.cookie_str("", 0))

        raise ApiError(404, "Not found")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Pixelsphere server")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8080)
    a = ap.parse_args()
    print(f"Pixelsphere running at http://{'localhost' if a.host in ('127.0.0.1', '0.0.0.0') else a.host}:{a.port}  (data in {DATA})")
    try:
        ThreadingHTTPServer((a.host, a.port), H).serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
