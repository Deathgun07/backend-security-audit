# Django checklist (and Django REST Framework)

Files to read first: `settings.py` (or `settings/`), `urls.py`, `views.py`, `serializers.py`, `forms.py`, `models.py`, templates, `middleware`, `Dockerfile`, `.env`.

## D1. `DEBUG = True` in production — High (A05)
Error pages leak settings, partial environment variables, SQL queries, and paths.
```python
# ❌
DEBUG = True
# ✅
DEBUG = os.environ.get("DJANGO_DEBUG") == "1"
```
- "Confirmed" if it is the production settings file; otherwise "to verify manually" (`settings/dev.py` vs `prod.py`).

## D2. Hardcoded `SECRET_KEY` — High (A02)
A committed `SECRET_KEY = 'django-insecure-…'` allows forging signed sessions, password reset tokens, and signed cookies.
```python
# ✅
SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]
```

## D3. `ALLOWED_HOSTS = ['*']` — Medium (A05)
Host header poisoning → password reset links pointing to an attacker's domain. List the domains explicitly.

## D4. SQL injection — Critical (A03)
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
- `order_by(request.GET["sort"])`: allowlist the fields (leak through sorting on private fields).

## D5. Access control / IDOR — High (A01)
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
- DRF: `get_queryset()` must filter by `self.request.user`; `queryset = Model.objects.all()` + an unfiltered `ModelViewSet` = IDOR.
- `permission_classes = [AllowAny]` or `DEFAULT_PERMISSION_CLASSES` missing/`AllowAny` → High.
- Custom admin views without `@staff_member_required` / `user.is_staff`.

## D6. Mass assignment — High (A01)
```python
# ❌
class UserSerializer(serializers.ModelSerializer):
    class Meta: model = User; fields = "__all__"        # is_staff, is_superuser are writable
# ✅
    class Meta: model = User; fields = ["id", "first_name", "last_name"]; read_only_fields = ["id"]
```
Same for `ModelForm` with `fields = "__all__"` or `exclude`.

## D7. CSRF disabled — Medium (A01)
`@csrf_exempt` on a state-changing view with cookie auth; `django.middleware.csrf.CsrfViewMiddleware` removed from `MIDDLEWARE`.
- Acceptable exception: a webhook that verifies an HMAC signature.

## D8. XSS — Medium (A03)
`mark_safe(user_input)`, `|safe`, `{% autoescape off %}`, misused `format_html` (`format_html(f"...{x}")`).

## D9. HTTPS / cookie settings — Low to Medium (A05)
```python
SECURE_SSL_REDIRECT = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_HSTS_SECONDS = 31536000
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")   # if behind a proxy
```
`python manage.py check --deploy` lists these points: suggest it to the user (local, read-only command).

## D10. CORS — Medium (A05)
`CORS_ALLOW_ALL_ORIGINS = True` (or `CORS_ORIGIN_ALLOW_ALL`) with `CORS_ALLOW_CREDENTIALS = True` → High.

## D11. Password hashing — High (A02)
`PASSWORD_HASHERS` listing `MD5PasswordHasher`, `UnsaltedMD5PasswordHasher`, or `SHA1PasswordHasher` first. Keep `PBKDF2`/`Argon2`.

## D12. Files and uploads — Medium to High (A04)
`MEDIA_ROOT` served by Django in production (`static()` in `urls.py` outside `DEBUG`), `FileField` without extension/size validation, `open(os.path.join(BASE, request.GET["f"]))` → path traversal (High).

## D13. Deserialization / commands — Critical (A08/A03)
`pickle.loads`, `yaml.load`, `subprocess(..., shell=True)`, `eval` with user input (same rules as Flask).

## D14. Rate limiting — Medium (A07)
Login, password reset, OTP without `django-ratelimit` / `django-axes` / DRF throttling (`DEFAULT_THROTTLE_CLASSES`).
