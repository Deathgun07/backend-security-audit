# Go checklist (net/http, Gin, Echo, Fiber, Chi)

Files to read first: `main.go`, `cmd/`, `internal/handler*`, `internal/middleware*`, `routes*.go`, `*repository*.go` / `*store*.go` (SQL), `config*.go`, `go.mod`.

## G1. SQL injection — Critical (A03)
```go
// ❌
q := fmt.Sprintf("SELECT * FROM users WHERE email = '%s'", email)
rows, _ := db.Query(q)
db.Query("SELECT * FROM users WHERE id = " + id)
gormDB.Where(fmt.Sprintf("name = '%s'", name)).Find(&users)
gormDB.Raw("SELECT * FROM t WHERE x = " + x).Scan(&r)
// ✅
rows, err := db.QueryContext(ctx, "SELECT * FROM users WHERE email = $1", email) // ? for MySQL
gormDB.Where("name = ?", name).Find(&users)
```
- Dynamic `ORDER BY` / column names: allowlist (`map[string]string`).
- sqlx `In`/`Named`: OK; `sqlx.Rebind` on a built string: verify.

## G2. Authentication / authorization — Critical (A01)
- Routes mounted outside the protected group (`r.GET("/admin/users", h)` instead of `admin := r.Group("/admin", AuthMiddleware())`).
- IDOR: `id := c.Param("id")` then a read without `AND user_id = $2`.
```go
// ✅
userID := c.MustGet("userID").(string)
err := db.QueryRowContext(ctx, "SELECT ... FROM invoices WHERE id = $1 AND user_id = $2", c.Param("id"), userID).Scan(...)
```
- Middleware that writes an error but forgets `return` / `c.Abort()` → the handler runs anyway (Critical).
```go
// ❌
if token == "" { http.Error(w, "unauthorized", 401) }   // no return
next.ServeHTTP(w, r)
```

## G3. JWT — Critical (A07)
```go
// ❌ algorithm not verified / hardcoded secret
token, _ := jwt.Parse(s, func(t *jwt.Token) (interface{}, error) { return []byte("secret"), nil })
// ✅
token, err := jwt.Parse(s, func(t *jwt.Token) (interface{}, error) {
    if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok { return nil, fmt.Errorf("unexpected alg") }
    return []byte(os.Getenv("JWT_SECRET")), nil
}, jwt.WithValidMethods([]string{"HS256"}))
if err != nil || !token.Valid { /* 401 */ }
```
- `jwt.UnsafeAllowNoneSignatureType`, `Parse` error ignored (`_`) → Critical.

## G4. Command injection — Critical (A03)
`exec.Command("sh", "-c", "convert " + name)` → pass arguments separately: `exec.Command("convert", name, "out.png")`.

## G5. Path traversal — High (A01)
```go
// ❌
http.ServeFile(w, r, filepath.Join("uploads", r.URL.Query().Get("f")))
// ✅ (Go ≥ 1.24)
root, _ := os.OpenRoot("uploads"); f, err := root.Open(name)
// or: filepath.Clean + check strings.HasPrefix(abs, baseAbs+string(os.PathSeparator))
```
- `c.File(c.Param("path"))`, `c.SaveUploadedFile(file, "uploads/"+file.Filename)` → High.

## G6. XSS / templates — Medium (A03)
`text/template` used for HTML (no escaping); `template.HTML(userInput)`; `w.Write([]byte("<p>" + name))`.

## G7. SSRF — High (A10)
`http.Get(r.URL.Query().Get("url"))` → domain allowlist, reject private IPs, `CheckRedirect`.

## G8. TLS and HTTP server — Medium (A05)
- `InsecureSkipVerify: true` → Medium.
- `http.ListenAndServe(":8080", mux)` without `ReadHeaderTimeout` → Slowloris (Low):
```go
srv := &http.Server{Addr: ":8080", Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second}
```
- Unbounded body size: `http.MaxBytesReader(w, r.Body, 1<<20)` (Low).

## G9. CORS — Medium (A05)
`AllowOrigins: []string{"*"}` with `AllowCredentials: true`, or a reflected origin (`w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))`) → High.

## G10. Crypto — Medium to High (A02)
- Passwords: `bcrypt.GenerateFromPassword` / `argon2id`, never plain `md5`/`sha1`/`sha256` (High).
- Tokens: `crypto/rand`, never `math/rand` (Medium).
- Secret comparison: `subtle.ConstantTimeCompare` (Low).

## G11. Error handling and logs — Low (A09)
`c.JSON(500, gin.H{"error": err.Error()})` exposes SQL errors; `gin.SetMode(gin.DebugMode)` in production; token logging.

## G12. Dependencies — variable (A06)
`govulncheck ./...` if available (read-only); otherwise "to verify manually" with the command.

## G13. Rate limiting — Medium (A07)
Login/OTP without `golang.org/x/time/rate`, `ulule/limiter`, `httprate`, or an equivalent middleware.
