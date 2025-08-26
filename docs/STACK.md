# Technology Stack Recommendation

## Stack Chosen

### Core Technologies
- **Backend**: Go 1.23+ with standard library focus
- **Frontend**: HTMX + Alpine.js + Tailwind CSS
- **Database**: PostgreSQL 16+ with pgx driver
- **Authentication**: Passkeys (WebAuthn) with session-based fallback
- **Deployment**: Single binary + Docker container
- **Reverse Proxy**: Caddy (automatic HTTPS)
- **Observability**: OpenTelemetry with Prometheus metrics
- **Testing**: Go's built-in testing + Playwright for E2E

### Supporting Tools
- **Email**: Postmark for transactional emails
- **File Storage**: Local filesystem → S3-compatible when scaling
- **Background Jobs**: Built-in goroutines → River (Postgres-based) when needed
- **Caching**: In-memory map → Redis when scaling
- **Search**: PostgreSQL full-text → Meilisearch when needed

## Executive Summary

This stack is designed around a fundamental principle: **maximize developer velocity while maintaining professional standards**. Every choice prioritizes what a solo Go developer can realistically build and maintain.

### Why This Stack Works

**1. HTML-over-the-wire Architecture (HTMX)**
- Eliminates the frontend build step entirely
- Uses Go templates you already know
- Delivers modern interactivity without JavaScript frameworks
- Progressive enhancement means it works everywhere
- Zero npm dependencies to manage

**2. PostgreSQL as the Foundation**
- One database for everything initially (JSONB for documents, arrays for queues)
- Rock-solid reliability with 30+ years of battle testing
- Excellent Go driver (pgx) with type safety
- Built-in full-text search delays need for separate search infrastructure
- Can handle millions of users before needing alternatives

**3. Passkeys-First Authentication**
- More secure than passwords by default
- Eliminates password reset flows (major complexity reduction)
- Users want it (especially tech-savvy early adopters)
- Fallback to magic links for compatibility
- No need for 2FA complexity

**4. Caddy for Reverse Proxy**
- Automatic HTTPS with Let's Encrypt
- Simple configuration (10 lines vs nginx's 100)
- Built in Go (you can read the source)
- Handles WebSocket upgrades automatically
- Production-ready with minimal configuration

**5. Single Binary Deployment**
- Ship one file that includes everything
- No dependency hell
- Easy rollbacks (just swap the binary)
- Perfect for early-stage iteration speed
- Containers when you need them, not before

### The 12-Month Horizon

This stack will handle your first 10,000 users without architectural changes. When you need to scale:
- Add Redis for caching (not before you measure need)
- Move to S3 for file storage (local is fine initially)
- Add River for background jobs (goroutines work initially)
- Consider read replicas before microservices
- Add Meilisearch only when PostgreSQL FTS shows limits

## Detailed Breakdown By Component

### Backend: Go with Standard Library Focus

**Why Go:**
- You already know it
- Incredible standard library reduces dependencies
- Single binary deployment
- Excellent concurrency for real-time features
- Fast enough for 99% of use cases

**Implementation Approach:**
```go
// Your entire web framework in 50 lines
type App struct {
    db     *pgx.Pool
    config Config
}

func (app *App) routes() http.Handler {
    mux := http.NewServeMux()
    
    // Middleware chain
    mux.HandleFunc("/", app.authMiddleware(app.homeHandler))
    
    // Static files
    mux.Handle("/static/", http.FileServer(http.FS(staticFiles)))
    
    return app.securityHeaders(mux)
}
```

**Key Libraries (minimal, focused):**
- `pgx/v5`: PostgreSQL driver (faster than database/sql)
- `golang-jwt/jwt`: If you need JWTs (prefer sessions)
- `go-webauthn/webauthn`: Passkey authentication
- `templ`: Type-safe templates (optional but recommended)

**What NOT to Use:**
- Heavy frameworks (Gin, Echo) - unnecessary abstraction
- ORMs (GORM) - learn SQL, it's more maintainable
- Dependency injection frameworks - Go's simplicity is the feature

### Frontend: HTMX + Alpine.js + Tailwind CSS

**Why HTMX:**
- Returns HTML fragments from your Go handlers
- No JavaScript build step or toolchain
- Progressively enhance existing server-rendered pages
- 14KB gzipped does what React does in megabytes
- Mental model matches server-side rendering

**Example Integration:**
```html
<!-- This replaces an entire React component -->
<form hx-post="/api/items" hx-target="#items" hx-swap="afterbegin">
    <input name="title" required>
    <button type="submit">Add Item</button>
</form>

<div id="items">
    <!-- Go template renders items here -->
    {{ range .Items }}
        <div>{{ .Title }}</div>
    {{ end }}
</div>
```

**Why Alpine.js:**
- Covers the 10% of cases where you need client-side state
- 17KB provides just enough reactivity
- Syntax is learnable in an hour
- No build step, just include via CDN

**Why Tailwind CSS:**
- Never write CSS again
- Enforces consistency without meetings
- Excellent documentation with copy-paste examples
- JIT compiler means tiny production CSS
- One-time setup, then forget about styling

**Setup Approach:**
```html
<!-- In your base template -->
<script src="https://unpkg.com/htmx.org@1.9.10"></script>
<script src="https://unpkg.com/alpinejs@3.x.x/dist/cdn.min.js" defer></script>
<script src="https://cdn.tailwindcss.com"></script> <!-- Dev only, use CLI for prod -->
```

### Database: PostgreSQL

**Why PostgreSQL:**
- One database for everything initially
- JSONB for document storage when needed
- Arrays and JSON for queue-like operations
- Row-level security if you need multi-tenancy
- Boring, stable, well-documented

**Schema Philosophy:**
```sql
-- Start simple, normalize later
CREATE TABLE users (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email      TEXT UNIQUE NOT NULL,
    auth_data  JSONB NOT NULL, -- Passkey credentials
    metadata   JSONB DEFAULT '{}', -- Flexible fields
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Use PostgreSQL features instead of adding services
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_metadata ON users USING GIN (metadata);
```

**Migration Strategy:**
- Start with raw SQL files numbered sequentially
- Use `golang-migrate` when you need rollbacks
- Keep migrations idempotent when possible

### Authentication: Passkeys with Session Fallback

**Why Passkeys:**
- Eliminates password complexity entirely
- No password resets, no 2FA setup
- More secure by default
- Growing platform support

**Implementation Approach:**
```go
// Simplified flow
func (app *App) RegisterHandler(w http.ResponseWriter, r *http.Request) {
    // 1. Start WebAuthn registration
    options, session := app.webauthn.BeginRegistration(user)
    
    // 2. Store session temporarily
    app.cache.Set(sessionID, session, 5*time.Minute)
    
    // 3. Return options to frontend
    json.NewEncoder(w).Encode(options)
}
```

**Fallback Strategy:**
- Magic links for users without passkey support
- Session cookies for post-authentication (secure, httpOnly, sameSite)
- JWT only for API-to-API communication

### Deployment: Single Binary First

**Development to Production Path:**

**Phase 1: Single Binary (Months 1-6)**
```bash
# Build
CGO_ENABLED=0 go build -o app ./cmd/web

# Deploy
scp app server:/opt/myapp/
ssh server 'systemctl restart myapp'
```

**Phase 2: Docker When Needed (Months 6+)**
```dockerfile
FROM golang:1.23-alpine AS builder
WORKDIR /app
COPY . .
RUN go build -o app ./cmd/web

FROM alpine:latest
RUN apk --no-cache add ca-certificates
COPY --from=builder /app/app /app
ENTRYPOINT ["/app"]
```

**Why Caddy for Reverse Proxy:**
```caddyfile
# Entire production configuration
myapp.com {
    reverse_proxy localhost:8080
    encode gzip
    header X-Content-Type-Options nosniff
    header X-Frame-Options DENY
}
```

### Observability: OpenTelemetry + Prometheus

**Start Simple:**
```go
// Just enough observability
type Metrics struct {
    RequestDuration *prometheus.HistogramVec
    RequestCount    *prometheus.CounterVec
}

func (app *App) instrumentHandler(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        start := time.Now()
        next.ServeHTTP(w, r)
        app.metrics.RequestDuration.Observe(time.Since(start).Seconds())
    })
}
```

**What to Monitor Initially:**
- Request latencies (P50, P95, P99)
- Error rates
- Database query times
- Background job failures

### Testing Strategy

**Unit Tests:**
```go
// Test your business logic, not your framework
func TestCalculatePrice(t *testing.T) {
    price := CalculatePrice(100, 0.1)
    assert.Equal(t, 90.0, price)
}
```

**Integration Tests:**
```go
// Test with real PostgreSQL using testcontainers
func TestUserCreation(t *testing.T) {
    db := setupTestDB(t)
    defer db.Close()
    
    user := CreateUser(db, "test@example.com")
    assert.NotNil(t, user.ID)
}
```

**E2E Tests (Playwright):**
```javascript
// Only for critical user paths
test('user can sign up and create item', async ({ page }) => {
    await page.goto('/signup');
    await page.fill('input[name="email"]', 'test@example.com');
    await page.click('button[type="submit"]');
    // Assert success
});
```

## Security Considerations

### Without Enterprise Complexity

**Essential Security Checklist:**
1. **HTTPS everywhere** (Caddy handles this)
2. **Passkeys or secure sessions** (no JWT in cookies)
3. **SQL injection prevention** (use parameterized queries)
4. **XSS prevention** (Go's html/template auto-escapes)
5. **CSRF tokens** (for state-changing operations)
6. **Rate limiting** (simple in-memory initially)
7. **Security headers** (via middleware)

**Security Middleware:**
```go
func securityHeaders(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("X-Content-Type-Options", "nosniff")
        w.Header().Set("X-Frame-Options", "DENY")
        w.Header().Set("X-XSS-Protection", "1; mode=block")
        w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
        next.ServeHTTP(w, r)
    })
}
```

## Migration Paths

### When You Hit Limits

**1. Performance Bottlenecks:**
- First: Add appropriate indexes
- Second: Implement caching (Redis)
- Third: Read replicas
- Last: Microservices

**2. Feature Complexity:**
- First: Better code organization (packages)
- Second: Extract background workers (River)
- Third: Service boundaries (still monorepo)
- Last: Separate services

**3. Team Growth:**
- First: Better documentation
- Second: API contracts (OpenAPI)
- Third: Feature flags
- Last: Separate repositories

## Common Pitfalls to Avoid

### Don't Do This:
1. **Starting with microservices** - You don't need them yet
2. **Using Kubernetes** - A VPS with systemd is fine initially
3. **Complex authentication** - Passkeys or magic links, not OAuth initially
4. **NoSQL as primary database** - PostgreSQL can do documents too
5. **React/Vue/Angular** - HTMX delivers the same UX with 10% of the complexity
6. **GraphQL** - REST is fine, you control both ends
7. **Message queues** - PostgreSQL LISTEN/NOTIFY or goroutines first

### Do This Instead:
1. **Monolith first** - Easy to reason about and deploy
2. **Boring technology** - Proven, documented, hiring-friendly
3. **Buy when you can** - Use Postmark, don't build email
4. **Measure before optimizing** - Premature optimization kills startups
5. **Security basics well** - Better than enterprise features poorly

## Conclusion

This stack optimizes for **developer velocity** while maintaining **professional standards**. Every technology choice has been made with a solo developer in mind who needs to ship features quickly without sacrificing security or user experience.

The path from prototype to production is clear, and each component has a natural upgrade path when you hit its limits. More importantly, you won't hit those limits until you have real users and likely funding to address them properly.

Remember: Your goal is to build something users want, not to impress other engineers with your architecture. This stack gets you there with minimal cognitive overhead and maximum maintainability.

**Success Metric:** If you can explain every part of your stack in one sentence and deploy a fix in under 5 minutes, you've got it right.