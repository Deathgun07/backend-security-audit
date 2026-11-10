# Checklist Flask / FastAPI / Python

Fichiers à lire en priorité : `app.py`, `__init__.py` (factory), `config.py`, `wsgi.py`, `routes/`, `views/`, `models.py`, `auth*.py`, templates Jinja, `Dockerfile`, `Procfile`.

## F1. `debug=True` en production — Critique (A05)
Le débogueur Werkzeug permet l'exécution de code Python arbitraire depuis le navigateur.
```python
# ❌
app.run(host="0.0.0.0", debug=True)
# ✅
app.run(debug=os.environ.get("FLASK_DEBUG") == "1")   # et en prod : gunicorn, jamais app.run
```
- Statut « confirmé » si c'est le point d'entrée utilisé en prod (Dockerfile/Procfile) ; sinon « à vérifier ».

## F2. `SECRET_KEY` faible ou en dur — Haute (A02)
Permet de forger des cookies de session signés (`flask-unsign`) → usurpation de n'importe quel compte.
```python
# ❌
app.config["SECRET_KEY"] = "dev"
app.secret_key = "secret123"
# ✅
app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]   # générée : python -c "import secrets; print(secrets.token_hex(32))"
```

## F3. SQL brut avec f-string / format / % — Critique (A03)
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

## F4. SSTI via `render_template_string` — Critique (A03)
```python
# ❌  ?nom={{config.__class__.__init__.__globals__['os'].popen('id').read()}}
return render_template_string(f"<h1>Bonjour {request.args['nom']}</h1>")
# ✅
return render_template_string("<h1>Bonjour {{ nom }}</h1>", nom=request.args.get("nom", ""))
```
- `render_template_string` avec une chaîne **constante** et des variables passées en contexte = OK (Info).

## F5. Désérialisation non sûre — Critique (A08)
```python
# ❌
data = pickle.loads(request.data)
cfg = yaml.load(request.data)                 # PyYAML < 6 : Loader complet par défaut
# ✅
data = json.loads(request.data)
cfg = yaml.safe_load(request.data)
```
- `pickle` sur des fichiers locaux de confiance (modèle ML embarqué) = Info.

## F6. CORS `*` — Moyenne à Haute (A05)
```python
# ❌
CORS(app)                                                   # toutes origines, toutes routes
CORS(app, origins="*", supports_credentials=True)           # Haute
# ✅
CORS(app, resources={r"/api/*": {"origins": ["https://mon-domaine.ci"]}}, supports_credentials=True)
```

## F7. Authentification et contrôle d'accès — Haute (A01)
- Routes sensibles sans `@login_required` / vérification de rôle.
- IDOR : `Post.query.get(id)` sans filtre `user_id=current_user.id`.
```python
# ✅
post = Post.query.filter_by(id=pid, user_id=current_user.id).first_or_404()
```
- Mots de passe : `werkzeug.security.generate_password_hash` / `bcrypt` / `argon2`, jamais `hashlib.md5/sha1`.

## F8. CSRF — Moyenne (A01)
Formulaires sans `Flask-WTF` / `CSRFProtect(app)` ; `WTF_CSRF_ENABLED = False` hors tests.

## F9. Injection de commande — Critique (A03)
```python
# ❌
os.system(f"convert {filename} out.png")
subprocess.run(cmd, shell=True)
# ✅
subprocess.run(["convert", filename, "out.png"], check=True)
```

## F10. Accès fichiers / path traversal — Haute (A01)
```python
# ❌
return send_file(os.path.join("uploads", request.args["f"]))
# ✅
return send_from_directory(app.config["UPLOAD_DIR"], secure_filename(request.args["f"]))
```
- Upload : `secure_filename`, liste blanche d'extensions, `MAX_CONTENT_LENGTH`.

## F11. XSS — Moyenne (A03)
`|safe`, `Markup(...)`, `{% autoescape false %}` avec contenu utilisateur ; templates rendus depuis `.txt` (pas d'autoescape).

## F12. Cookies de session — Basse (A07)
`SESSION_COOKIE_SECURE = True`, `SESSION_COOKIE_HTTPONLY = True` (défaut), `SESSION_COOKIE_SAMESITE = "Lax"`, `PERMANENT_SESSION_LIFETIME` raisonnable.

## F13. SSRF — Haute (A10)
`requests.get(request.args["url"])` sans liste blanche de domaines ; `verify=False` désactive TLS (Moyenne).

## F14. Rate limiting — Moyenne (A07)
`/login`, `/reset`, `/otp` sans `flask-limiter` :
```python
limiter = Limiter(get_remote_address, app=app)
@app.post("/login")
@limiter.limit("5 per minute")
def login(): ...
```

---

# FastAPI (en plus des points F3, F5, F9, F10, F13 ci-dessus qui s'appliquent aussi)

## FA1. Endpoints sans dépendance d'auth — Critique (A01)
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
- Préférer `APIRouter(dependencies=[Depends(get_current_user)])` pour protéger un groupe entier.

## FA2. JWT — Critique (A07)
`jwt.decode(token, options={"verify_signature": False})`, `algorithms` absent ou contenant `"none"`, secret en dur → Critique/Haute.
```python
payload = jwt.decode(token, os.environ["JWT_SECRET"], algorithms=["HS256"])
```

## FA3. Modèles Pydantic et mass assignment — Haute (A01)
Même modèle en entrée et en sortie (`UserIn` contenant `is_admin`, `role`) ; `response_model` absent → renvoi de `hashed_password`. Séparer `UserCreate` / `UserUpdate` / `UserOut`.

## FA4. CORS — Moyenne (A05)
`CORSMiddleware(allow_origins=["*"], allow_credentials=True)` → Haute (Starlette reflète l'origine).

## FA5. Docs exposées — Basse (A05)
`/docs` et `/openapi.json` publics en prod : `FastAPI(docs_url=None, redoc_url=None, openapi_url=None)` si l'API est privée.

## FA6. Rate limiting — Moyenne (A07)
`slowapi` ou équivalent sur `/token`, `/login`, OTP.
