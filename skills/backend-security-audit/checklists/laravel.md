# Laravel checklist

Complements `php-mysql.md` (always loaded alongside this one). Files to read: `routes/web.php`, `routes/api.php`, `app/Http/Controllers/`, `app/Http/Middleware/`, `bootstrap/app.php` (Laravel 11+), `app/Http/Kernel.php` (≤ 10), `app/Models/`, `app/Policies/`, `config/`, `.env`.

## L1. `APP_DEBUG=true` / exposed `.env` — Critical (A05)
Ignition error page: environment variables, `APP_KEY`, DB credentials; older Ignition versions (< 2.5.2) are vulnerable to RCE (CVE-2021-3129).
```diff
-APP_ENV=local
-APP_DEBUG=true
+APP_ENV=production
+APP_DEBUG=false
```
- Committed `APP_KEY` → decryption of cookies/sessions, and possible RCE through deserialization of encrypted cookies (Critical).

## L2. Raw queries — Critical (A03)
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
`DB::raw`, `selectRaw`, `whereRaw`, `havingRaw`, `orderByRaw`, `DB::statement`, `DB::unprepared` with a variable → trace to the source.

## L3. Mass assignment — High (A01)
```php
// ❌
protected $guarded = [];
User::create($request->all());
$user->update($request->all());
// ✅
protected $fillable = ['name', 'email'];
$user->update($request->validated());     // FormRequest with rules
```

## L4. Authorization / IDOR — High (A01)
```php
// ❌
public function show(Invoice $invoice) { return $invoice; }
// ✅
public function show(Invoice $invoice) {
    $this->authorize('view', $invoice);            // InvoicePolicy::view => $user->id === $invoice->user_id
    return $invoice;
}
```
- Routes outside the `middleware('auth')` / `auth:sanctum` group; `withoutMiddleware('auth')`.
- Route model binding without scoping (`->scopeBindings()`) for nested resources.

## L5. XSS — Medium (A03)
`{!! $variable !!}` with user content; `{{ }}` escapes, `{!! !!}` does not. Rich content: HTMLPurifier (`mews/purifier`).

## L6. CSRF — Medium (A01)
Overly broad exclusions in `VerifyCsrfToken::$except` (or `validateCsrfTokens(except: [...])`), for example `'*'` or `'api/*'` for routes with cookie auth.

## L7. Upload — High (A04)
```php
// ✅
$request->validate(['photo' => 'required|file|mimes:jpg,png|max:5120']);
$path = $request->file('photo')->store('photos');        // generated name, private disk
```
- `storeAs('public', $file->getClientOriginalName())` → user-controlled name in a public folder (High).

## L8. Deserialization / execution — Critical (A08)
`unserialize($request->...)`, `eval`, `Process::run("... $input")`, `shell_exec` (see php-mysql.md).

## L9. Rate limiting — Medium (A07)
Login routes without `throttle:` (Breeze/Fortify add it by default; verify custom routes).

## L10. Configuration — Low to Medium (A05)
`config/cors.php` with `'allowed_origins' => ['*']` + `'supports_credentials' => true` (High); `SESSION_SECURE_COOKIE=false` in production; Telescope/Horizon/Debugbar reachable in production without a gate.

## L11. Dependencies — variable (A06)
`composer audit` (reads `composer.lock`).
