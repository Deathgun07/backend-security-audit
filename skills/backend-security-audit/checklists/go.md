# Checklist Go (net/http, Gin, Echo, Fiber, Chi)

Fichiers à lire en priorité : `main.go`, `cmd/`, `internal/handler*`, `internal/middleware*`, `routes*.go`, `*repository*.go` / `*store*.go` (SQL), `config*.go`, `go.mod`.

## G1. Injection SQL — Critique (A03)
```go
// ❌
q := fmt.Sprintf("SELECT * FROM users WHERE email = '%s'", email)
rows, _ := db.Query(q)
db.Query("SELECT * FROM users WHERE id = " + id)
gormDB.Where(fmt.Sprintf("name = '%s'", name)).Find(&users)
gormDB.Raw("SELECT * FROM t WHERE x = " + x).Scan(&r)
// ✅
rows, err := db.QueryContext(ctx, "SELECT * FROM users WHERE email = $1", email) // ? pour MySQL
gormDB.Where("name = ?", name).Find(&users)
```
- `ORDER BY` / noms de colonnes dynamiques : liste blanche (`map[string]string`).
- sqlx `In`/`Named` : OK ; `sqlx.Rebind` sur une chaîne construite : vérifier.

## G2. Authentification / autorisation — Critique (A01)
- Routes montées hors du groupe protégé (`r.GET("/admin/users", h)` au lieu de `admin := r.Group("/admin", AuthMiddleware())`).
- IDOR : `id := c.Param("id")` puis lecture sans `AND user_id = $2`.
```go
// ✅
userID := c.MustGet("userID").(string)
err := db.QueryRowContext(ctx, "SELECT ... FROM invoices WHERE id = $1 AND user_id = $2", c.Param("id"), userID).Scan(...)
```
- Middleware qui écrit une erreur mais oublie `return` / `c.Abort()` → le handler s'exécute quand même (Critique).
```go
// ❌
if token == "" { http.Error(w, "unauthorized", 401) }   // pas de return
next.ServeHTTP(w, r)
```

## G3. JWT — Critique (A07)
```go
// ❌ algorithme non vérifié / secret en dur
token, _ := jwt.Parse(s, func(t *jwt.Token) (interface{}, error) { return []byte("secret"), nil })
// ✅
token, err := jwt.Parse(s, func(t *jwt.Token) (interface{}, error) {
    if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok { return nil, fmt.Errorf("alg inattendu") }
    return []byte(os.Getenv("JWT_SECRET")), nil
}, jwt.WithValidMethods([]string{"HS256"}))
if err != nil || !token.Valid { /* 401 */ }
```
- `jwt.UnsafeAllowNoneSignatureType`, erreur de `Parse` ignorée (`_`) → Critique.

## G4. Injection de commande — Critique (A03)
`exec.Command("sh", "-c", "convert " + name)` → passer les arguments séparément : `exec.Command("convert", name, "out.png")`.

## G5. Path traversal — Haute (A01)
```go
// ❌
http.ServeFile(w, r, filepath.Join("uploads", r.URL.Query().Get("f")))
// ✅ (Go ≥ 1.24)
root, _ := os.OpenRoot("uploads"); f, err := root.Open(name)
// ou : filepath.Clean + vérifier strings.HasPrefix(abs, baseAbs+string(os.PathSeparator))
```
- `c.File(c.Param("path"))`, `c.SaveUploadedFile(file, "uploads/"+file.Filename)` → Haute.

## G6. XSS / templates — Moyenne (A03)
`text/template` utilisé pour du HTML (pas d'échappement) ; `template.HTML(userInput)` ; `w.Write([]byte("<p>" + name))`.

## G7. SSRF — Haute (A10)
`http.Get(r.URL.Query().Get("url"))` → liste blanche de domaines, refuser les IP privées, `CheckRedirect`.

## G8. TLS et serveur HTTP — Moyenne (A05)
- `InsecureSkipVerify: true` → Moyenne.
- `http.ListenAndServe(":8080", mux)` sans `ReadHeaderTimeout` → Slowloris (Basse) :
```go
srv := &http.Server{Addr: ":8080", Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second}
```
- Taille de corps illimitée : `http.MaxBytesReader(w, r.Body, 1<<20)` (Basse).

## G9. CORS — Moyenne (A05)
`AllowOrigins: []string{"*"}` avec `AllowCredentials: true`, ou origine reflétée (`w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))`) → Haute.

## G10. Crypto — Moyenne à Haute (A02)
- Mots de passe : `bcrypt.GenerateFromPassword` / `argon2id`, jamais `md5`/`sha1`/`sha256` simple (Haute).
- Tokens : `crypto/rand`, jamais `math/rand` (Moyenne).
- Comparaison de secrets : `subtle.ConstantTimeCompare` (Basse).

## G11. Gestion d'erreurs et logs — Basse (A09)
`c.JSON(500, gin.H{"error": err.Error()})` expose les erreurs SQL ; `gin.SetMode(gin.DebugMode)` en prod ; logs de tokens.

## G12. Dépendances — variable (A06)
`govulncheck ./...` si disponible (lecture seule) ; sinon « à vérifier » avec la commande.

## G13. Rate limiting — Moyenne (A07)
Login/OTP sans `golang.org/x/time/rate`, `ulule/limiter`, `httprate` ou middleware équivalent.
