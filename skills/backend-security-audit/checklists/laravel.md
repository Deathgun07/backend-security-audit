# Checklist Laravel

Complète `php-mysql.md` (toujours chargée avec celle-ci). Fichiers à lire : `routes/web.php`, `routes/api.php`, `app/Http/Controllers/`, `app/Http/Middleware/`, `bootstrap/app.php` (Laravel 11+), `app/Http/Kernel.php` (≤ 10), `app/Models/`, `app/Policies/`, `config/`, `.env`.

## L1. `APP_DEBUG=true` / `.env` exposé — Critique (A05)
Page d'erreur Ignition : variables d'environnement, `APP_KEY`, identifiants BDD ; anciennes versions d'Ignition (< 2.5.2) vulnérables à une RCE (CVE-2021-3129).
```diff
-APP_ENV=local
-APP_DEBUG=true
+APP_ENV=production
+APP_DEBUG=false
```
- `APP_KEY` commité → déchiffrement des cookies/sessions, et RCE possible via désérialisation de cookies chiffrés (Critique).

## L2. Requêtes brutes — Critique (A03)
```php
// ❌
DB::select("SELECT * FROM users WHERE email = '$email'");
User::whereRaw("name = '" . $request->name . "'")->get();
$q->orderByRaw($request->sort);
// ✅
DB::select('SELECT * FROM users WHERE email = ?', [$email]);
User::where('name', $request->name)->get();
$q->orderBy(in_array($request->sort, ['name', 'created_at'], true) ? $request->sort : 'created_at');
```
`DB::raw`, `selectRaw`, `whereRaw`, `havingRaw`, `orderByRaw`, `DB::statement`, `DB::unprepared` avec variable → à tracer jusqu'à la source.

## L3. Mass assignment — Haute (A01)
```php
// ❌
protected $guarded = [];
User::create($request->all());
$user->update($request->all());
// ✅
protected $fillable = ['name', 'email'];
$user->update($request->validated());     // FormRequest avec règles
```

## L4. Autorisation / IDOR — Haute (A01)
```php
// ❌
public function show(Invoice $invoice) { return $invoice; }
// ✅
public function show(Invoice $invoice) {
    $this->authorize('view', $invoice);            // InvoicePolicy::view => $user->id === $invoice->user_id
    return $invoice;
}
```
- Routes hors du groupe `middleware('auth')` / `auth:sanctum` ; `withoutMiddleware('auth')`.
- Route model binding sans scoping (`->scopeBindings()`) pour les ressources imbriquées.

## L5. XSS — Moyenne (A03)
`{!! $variable !!}` avec contenu utilisateur ; `{{ }}` échappe, `{!! !!}` non. Contenus riches : HTMLPurifier (`mews/purifier`).

## L6. CSRF — Moyenne (A01)
Exclusions trop larges dans `VerifyCsrfToken::$except` (ou `validateCsrfTokens(except: [...])`), par exemple `'*'` ou `'api/*'` pour des routes à auth par cookie.

## L7. Upload — Haute (A04)
```php
// ✅
$request->validate(['photo' => 'required|file|mimes:jpg,png|max:5120']);
$path = $request->file('photo')->store('photos');        // nom généré, disque privé
```
- `storeAs('public', $file->getClientOriginalName())` → nom contrôlé par l'utilisateur dans un dossier public (Haute).

## L8. Désérialisation / exécution — Critique (A08)
`unserialize($request->...)`, `eval`, `Process::run("... $input")`, `shell_exec` (voir php-mysql.md).

## L9. Rate limiting — Moyenne (A07)
Routes de login sans `throttle:` (Breeze/Fortify le font par défaut ; vérifier les routes custom).

## L10. Configuration — Basse à Moyenne (A05)
`config/cors.php` avec `'allowed_origins' => ['*']` + `'supports_credentials' => true` (Haute) ; `SESSION_SECURE_COOKIE=false` en prod ; Telescope/Horizon/Debugbar accessibles en prod sans gate.

## L11. Dépendances — variable (A06)
`composer audit` (lecture du `composer.lock`).
