# Checklist Django (et Django REST Framework)

Fichiers à lire en priorité : `settings.py` (ou `settings/`), `urls.py`, `views.py`, `serializers.py`, `forms.py`, `models.py`, templates, `middleware`, `Dockerfile`, `.env`.

## D1. `DEBUG = True` en production — Haute (A05)
Pages d'erreur avec settings, variables d'environnement partielles, requêtes SQL, chemins.
```python
# ❌
DEBUG = True
# ✅
DEBUG = os.environ.get("DJANGO_DEBUG") == "1"
```
- « Confirmé » si c'est le fichier de settings de prod ; sinon « à vérifier » (fichiers `settings/dev.py` vs `prod.py`).

## D2. `SECRET_KEY` en dur — Haute (A02)
`SECRET_KEY = 'django-insecure-…'` commité → forge de sessions signées, tokens de reset de mot de passe, cookies signés.
```python
# ✅
SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]
```

## D3. `ALLOWED_HOSTS = ['*']` — Moyenne (A05)
Empoisonnement de l'en-tête Host → liens de réinitialisation de mot de passe vers un domaine pirate. Lister les domaines.

## D4. Injection SQL — Critique (A03)
```python
# ❌
User.objects.raw(f"SELECT * FROM auth_user WHERE username = '{name}'")
cursor.execute("SELECT * FROM t WHERE id = %s" % pk)
qs.extra(where=[f"name = '{name}'"])
RawSQL(f"... {x}", [])
# ✅
User.objects.raw("SELECT * FROM auth_user WHERE username = %s", [name])
cursor.execute("SELECT * FROM t WHERE id = %s", [pk])
User.objects.filter(username=name)
```
- `order_by(request.GET["sort"])` : liste blanche des champs (fuite via tri sur champs privés).

## D5. Contrôle d'accès / IDOR — Haute (A01)
```python
# ❌
def invoice(request, pk):
    return render(request, "invoice.html", {"inv": Invoice.objects.get(pk=pk)})
# ✅
@login_required
def invoice(request, pk):
    inv = get_object_or_404(Invoice, pk=pk, owner=request.user)
    return render(request, "invoice.html", {"inv": inv})
```
- DRF : `get_queryset()` doit filtrer par `self.request.user` ; `queryset = Model.objects.all()` + `ModelViewSet` sans filtre = IDOR.
- `permission_classes = [AllowAny]` ou `DEFAULT_PERMISSION_CLASSES` absent/`AllowAny` → Haute.
- Vues admin custom sans `@staff_member_required` / `user.is_staff`.

## D6. Mass assignment — Haute (A01)
```python
# ❌
class UserSerializer(serializers.ModelSerializer):
    class Meta: model = User; fields = "__all__"        # is_staff, is_superuser modifiables
# ✅
    class Meta: model = User; fields = ["id", "first_name", "last_name"]; read_only_fields = ["id"]
```
Idem `ModelForm` avec `fields = "__all__"` ou `exclude`.

## D7. CSRF désactivé — Moyenne (A01)
`@csrf_exempt` sur une vue qui modifie l'état avec auth par cookie ; `django.middleware.csrf.CsrfViewMiddleware` retiré de `MIDDLEWARE`.
- Exception acceptable : webhook vérifiant une signature HMAC.

## D8. XSS — Moyenne (A03)
`mark_safe(user_input)`, `|safe`, `{% autoescape off %}`, `format_html` mal utilisé (`format_html(f"...{x}")`).

## D9. Réglages HTTPS / cookies — Basse à Moyenne (A05)
```python
SECURE_SSL_REDIRECT = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_HSTS_SECONDS = 31536000
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")   # si derrière un proxy
```
`python manage.py check --deploy` liste ces points : le proposer à l'utilisateur (commande locale, lecture seule).

## D10. CORS — Moyenne (A05)
`CORS_ALLOW_ALL_ORIGINS = True` (ou `CORS_ORIGIN_ALLOW_ALL`) avec `CORS_ALLOW_CREDENTIALS = True` → Haute.

## D11. Hachage des mots de passe — Haute (A02)
`PASSWORD_HASHERS` contenant `MD5PasswordHasher`, `UnsaltedMD5PasswordHasher`, `SHA1PasswordHasher` en premier. Garder `PBKDF2`/`Argon2`.

## D12. Fichiers et uploads — Moyenne à Haute (A04)
`MEDIA_ROOT` servi par Django en prod (`static()` dans `urls.py` hors `DEBUG`), `FileField` sans validation d'extension/taille, `open(os.path.join(BASE, request.GET["f"]))` → path traversal (Haute).

## D13. Désérialisation / commandes — Critique (A08/A03)
`pickle.loads`, `yaml.load`, `subprocess(..., shell=True)`, `eval` avec entrée utilisateur (mêmes règles que Flask).

## D14. Rate limiting — Moyenne (A07)
Login, reset password, OTP sans `django-ratelimit` / `django-axes` / throttling DRF (`DEFAULT_THROTTLE_CLASSES`).
