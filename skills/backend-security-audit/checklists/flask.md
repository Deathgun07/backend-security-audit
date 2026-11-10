# Flask / FastAPI / Python checklist

Files to read first: `app.py`, `__init__.py` (factory), `config.py`, `wsgi.py`, `routes/`, `views/`, `models.py`, `auth*.py`, Jinja templates, `Dockerfile`, `Procfile`.

## F1. `debug=True` in production — Critical (A05)
The Werkzeug debugger allows arbitrary Python code execution from the browser.
```python
# ❌
app.run(host="0.0.0.0", debug=True)
# ✅
app.run(debug=os.environ.get("FLASK_DEBUG") == "1")   # and in prod: gunicorn, never app.run
```
- Status "Confirmed" if this is the entry point used in prod (Dockerfile/Procfile); otherwise "to verify manually".

## F2. Weak or hardcoded `SECRET_KEY` — High (A02)
Allows forging signed session cookies (`flask-unsign`) → impersonation of any account.
```python
# ❌
app.config["SECRET_KEY"] = "dev"
app.secret_key = "secret123"
# ✅
app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]   # generated with: python -c "import secrets; print(secrets.token_hex(32))"
```

## F3. Raw SQL with f-string / format / % — Critical (A03)
```python
# ❌
cur.execute(f"SELECT * FROM users WHERE email = '{email}'")
cur.execute("SELECT * FROM users WHERE id = %s" % user_id)
db.session.execute(text(f"DELETE FROM posts WHERE id = {pid}"))
# ✅
cur.execute("SELECT * FROM users WHERE email = %s", (email,))       # psycopg / mysqlclient
cur.execute("SELECT * FROM users WHERE email = ?", (email,))        # sqlite3
db.session.execute(text("DELETE FROM posts WHERE id = :id"), {"id": pid})
```

## F4. SSTI via `render_template_string` — Critical (A03)
```python
# ❌  ?name={{config.__class__.__init__.__globals__['os'].popen('id').read()}}
return render_template_string(f"<h1>Hello {request.args['name']}</h1>")
# ✅
return render_template_string("<h1>Hello {{ name }}</h1>", name=request.args.get("name", ""))
```
- `render_template_string` with a **constant** string and variables passed in the context = OK (Info).

## F5. Unsafe deserialization — Critical (A08)
```python
# ❌
data = pickle.loads(request.data)
cfg = yaml.load(request.data)                 # PyYAML < 6: full Loader by default
# ✅
data = json.loads(request.data)
cfg = yaml.safe_load(request.data)
```
- `pickle` on trusted local files (bundled ML model) = Info.

## F6. CORS `*` — Medium to High (A05)
```python
# ❌
CORS(app)                                                   # all origins, all routes
CORS(app, origins="*", supports_credentials=True)           # High
# ✅
CORS(app, resources={r"/api/*": {"origins": ["https://mon-domaine.ci"]}}, supports_credentials=True)
```

## F7. Authentication and access control — High (A01)
- Sensitive routes without `@login_required` / role check.
- IDOR: `Post.query.get(id)` without a `user_id=current_user.id` filter.
```python
# ✅
post = Post.query.filter_by(id=pid, user_id=current_user.id).first_or_404()
```
- Passwords: `werkzeug.security.generate_password_hash` / `bcrypt` / `argon2`, never `hashlib.md5/sha1`.

## F8. CSRF — Medium (A01)
Forms without `Flask-WTF` / `CSRFProtect(app)`; `WTF_CSRF_ENABLED = False` outside tests.

## F9. Command injection — Critical (A03)
```python
# ❌
os.system(f"convert {filename} out.png")
subprocess.run(cmd, shell=True)
# ✅
subprocess.run(["convert", filename, "out.png"], check=True)
```

## F10. File access / path traversal — High (A01)
```python
# ❌
return send_file(os.path.join("uploads", request.args["f"]))
# ✅
return send_from_directory(app.config["UPLOAD_DIR"], secure_filename(request.args["f"]))
```
- Upload: `secure_filename`, extension allowlist, `MAX_CONTENT_LENGTH`.

## F11. XSS — Medium (A03)
`|safe`, `Markup(...)`, `{% autoescape false %}` with user content; templates rendered from `.txt` (no autoescape).

## F12. Session cookies — Low (A07)
`SESSION_COOKIE_SECURE = True`, `SESSION_COOKIE_HTTPONLY = True` (default), `SESSION_COOKIE_SAMESITE = "Lax"`, reasonable `PERMANENT_SESSION_LIFETIME`.

## F13. SSRF — High (A10)
`requests.get(request.args["url"])` without a domain allowlist; `verify=False` disables TLS (Medium).

## F14. Rate limiting — Medium (A07)
`/login`, `/reset`, `/otp` without `flask-limiter`:
```python
limiter = Limiter(get_remote_address, app=app)
@app.post("/login")
@limiter.limit("5 per minute")
def login(): ...
```

---

# FastAPI (in addition to F3, F5, F9, F10, F13 above, which also apply)

## FA1. Endpoints without an auth dependency — Critical (A01)
```python
# ❌
@app.delete("/orders/{order_id}")
async def delete_order(order_id: int, db: Session = Depends(get_db)):
    db.query(Order).filter(Order.id == order_id).delete()
# ✅
@app.delete("/orders/{order_id}")
async def delete_order(order_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    n = db.query(Order).filter(Order.id == order_id, Order.user_id == user.id).delete()
    if not n: raise HTTPException(404)
```
- Prefer `APIRouter(dependencies=[Depends(get_current_user)])` to protect a whole group.

## FA2. JWT — Critical (A07)
`jwt.decode(token, options={"verify_signature": False})`, `algorithms` missing or containing `"none"`, hardcoded secret → Critical/High.
```python
payload = jwt.decode(token, os.environ["JWT_SECRET"], algorithms=["HS256"])
```

## FA3. Pydantic models and mass assignment — High (A01)
Same model for input and output (`UserIn` containing `is_admin`, `role`); missing `response_model` → `hashed_password` returned. Separate `UserCreate` / `UserUpdate` / `UserOut`.

## FA4. CORS — Medium (A05)
`CORSMiddleware(allow_origins=["*"], allow_credentials=True)` → High (Starlette reflects the origin).

## FA5. Exposed docs — Low (A05)
`/docs` and `/openapi.json` public in prod: `FastAPI(docs_url=None, redoc_url=None, openapi_url=None)` if the API is private.

## FA6. Rate limiting — Medium (A07)
`slowapi` or equivalent on `/token`, `/login`, OTP.
