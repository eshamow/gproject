# Technology Stack Recommendation

## Project Context

**What We're Building:** A product and project management layer on top of Google Issues, designed to enhance the basic issue tracking with enterprise-grade features including epics, themes, and comprehensive reporting capabilities. This tool synchronizes with Google Issues as the source of truth while adding the strategic planning and analytics features that development teams need but Google Issues lacks.

**Team & Goals:** This is a single-developer project with FOSS and pre-revenue startup constraints. Our goals are to:
- Ship an MVP rapidly that can compete with tools like Jira/Linear in functionality
- Maintain the simplicity of Google Issues while adding power-user features
- Build something that can be self-hosted by small teams or run as a SaaS
- Keep operational complexity minimal so the solo developer can focus on features, not infrastructure

## Executive Summary

This stack is designed around a fundamental principle: **maximize developer velocity while maintaining professional standards**. Every choice prioritizes what a solo Go developer can realistically build and maintain.

For a Google Issues frontend with product management features, this stack delivers:
- **Zero operational overhead** with SQLite embedded database
- **HTML-over-the-wire** architecture eliminating frontend complexity
- **Single binary deployment** for true FOSS distribution
- **Built-in analytics** with zero-latency reporting
- **Passkeys authentication** eliminating password management

### Why This Stack Works

**1. HTML-over-the-wire Architecture (HTMX)**
- Eliminates the frontend build step entirely
- Uses Go templates you already know
- Delivers modern interactivity without JavaScript frameworks
- Progressive enhancement means it works everywhere
- Zero npm dependencies to manage

**2. SQLite as the Foundation**
- Embedded database - no separate process to manage
- Perfect for sync-heavy workloads with single writer pattern
- Excellent pure-Go driver (modernc.org/sqlite) - no CGO needed
- Built-in full-text search (FTS5) rivals dedicated search engines
- Scales to billions of rows and hundreds of GB

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
- Consider PostgreSQL migration only if you need true multi-writer concurrency
- SQLite's FTS5 eliminates need for separate search for most use cases
- Distribute read-only copies for scaling reads horizontally

## Stack Chosen

### Core Technologies
- **Backend**: Go 1.23+ with standard library focus
- **Frontend**: HTMX + Alpine.js + Tailwind CSS
- **Database**: SQLite with modernc.org/sqlite driver (pure Go, no CGO)
- **Authentication**: Passkeys (WebAuthn) with session-based fallback
- **Deployment**: Single binary + Docker container
- **Reverse Proxy**: Caddy (automatic HTTPS)
- **Observability**: OpenTelemetry with Prometheus metrics
- **Testing**: Go's built-in testing + Playwright for E2E

### Supporting Tools
- **Email**: Postmark for transactional emails
- **File Storage**: Local filesystem → S3-compatible when scaling
- **Background Jobs**: Built-in goroutines with channels for coordination
- **Caching**: In-memory map → Redis when scaling
- **Search**: SQLite FTS5 (built-in, excellent performance)

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
- `modernc.org/sqlite`: Pure Go SQLite driver (no CGO required)
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

### Database: SQLite

#### Why SQLite Over PostgreSQL for This Specific Product

After careful analysis of this product's requirements - a Google Issues frontend with product management features - **SQLite is the pragmatically correct choice**. Here's why:

**1. Perfect Fit for the Data Model**
- This is fundamentally a **cache with enrichments** - Google Issues is the source of truth
- You're storing issue metadata, epics, themes, and computed reports
- The write pattern is primarily from sync operations (single writer pattern)
- Reads dominate writes by orders of magnitude (viewing reports, dashboards)

**2. Deployment Simplicity That Matters**
- Ship as a true single binary with embedded database
- Zero operational overhead - no PostgreSQL to provision, monitor, or backup
- Perfect for FOSS distribution - users just download and run
- Can even run as a desktop app if needed

**3. Sync Architecture Benefits**
- SQLite's single-writer model actually HELPS here - prevents sync conflicts
- Use WAL mode for concurrent reads during sync operations
- Transaction boundaries map perfectly to API sync batches
- Built-in backup while running (`.backup` command or API)

**4. Superior Performance for Your Use Case**
- Analytical queries (reports) are FASTER than PostgreSQL for small-medium datasets
- No network roundtrip - queries execute in-process
- Full-text search built-in and excellent
- Common Table Expressions (CTEs) for complex reporting queries

**5. The Killer Advantage: Embedded Analytics**

For a reporting-focused tool, SQLite offers something PostgreSQL cannot: **zero-latency analytics**. Your Go code can:
- Execute complex analytical queries in microseconds
- Build materialized views in memory
- Compute aggregations without network overhead
- Cache computed results right in the database

#### Schema Design
```sql
-- Pragmas for optimal performance
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA cache_size = -64000; -- 64MB cache
PRAGMA temp_store = MEMORY;
PRAGMA mmap_size = 30000000000; -- 30GB mmap

-- Schema optimized for sync + reporting
CREATE TABLE issues (
    id            TEXT PRIMARY KEY,
    google_id     TEXT UNIQUE NOT NULL,
    title         TEXT NOT NULL,
    description   TEXT,
    status        TEXT,
    labels        JSON,
    epic_id       TEXT REFERENCES epics(id),
    theme_id      TEXT REFERENCES themes(id),
    synced_at     DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
    metadata      JSON -- Flexible fields
);

CREATE TABLE epics (
    id           TEXT PRIMARY KEY,
    title        TEXT NOT NULL,
    description  TEXT,
    theme_id     TEXT REFERENCES themes(id),
    created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at   DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for common queries
CREATE INDEX idx_issues_epic ON issues(epic_id);
CREATE INDEX idx_issues_status ON issues(status);
CREATE INDEX idx_issues_synced ON issues(synced_at);

-- Full-text search
CREATE VIRTUAL TABLE issues_fts USING fts5(
    title, description, content=issues, content_rowid=rowid
);

-- Triggers to keep FTS updated
CREATE TRIGGER issues_fts_insert AFTER INSERT ON issues BEGIN
    INSERT INTO issues_fts(rowid, title, description) 
    VALUES (new.rowid, new.title, new.description);
END;
```

**Go Implementation Pattern:**
```go
import "modernc.org/sqlite"

type DB struct {
    *sql.DB
    syncMutex sync.Mutex // Serialize sync operations
}

func NewDB(path string) (*DB, error) {
    dsn := fmt.Sprintf("file:%s?_journal=WAL&_timeout=5000&_sync=NORMAL&_cache=shared", path)
    db, err := sql.Open("sqlite", dsn)
    if err != nil {
        return nil, err
    }
    
    // Set connection pool appropriately for SQLite
    db.SetMaxOpenConns(1) // For write operations
    db.SetMaxIdleConns(1)
    
    return &DB{DB: db}, nil
}

// Sync pattern that leverages SQLite's strengths
func (db *DB) SyncIssues(issues []Issue) error {
    db.syncMutex.Lock()
    defer db.syncMutex.Unlock()
    
    tx, err := db.Begin()
    if err != nil {
        return err
    }
    defer tx.Rollback()
    
    // Clear and reload pattern - perfect for SQLite
    _, err = tx.Exec("DELETE FROM issues WHERE source = 'google'")
    if err != nil {
        return err
    }
    
    stmt, err := tx.Prepare(`
        INSERT INTO issues (google_id, title, description, status, labels)
        VALUES (?, ?, ?, ?, ?)
    `)
    if err != nil {
        return err
    }
    defer stmt.Close()
    
    for _, issue := range issues {
        _, err = stmt.Exec(issue.GoogleID, issue.Title, issue.Description, issue.Status, issue.Labels)
        if err != nil {
            return err
        }
    }
    
    return tx.Commit()
}
```

#### Addressing Common SQLite Concerns

**"But what about concurrent writes?"**
- You have ONE writer: the sync process
- Users create epics/themes infrequently 
- WAL mode handles read concurrency perfectly
- Queue writes through channels if needed

**"But what about scale?"**
- SQLite handles billions of rows efficiently
- Comfortable with databases up to 100GB
- If you have 100GB of issue metadata, you've already IPO'd
- Migration path exists: replicate to PostgreSQL when needed

**"But what about backups?"**
- Built-in online backup API
- Can backup while running
- Simple file copy when using WAL mode correctly
- Version control the database file for FOSS distribution

#### Configuration and Connection Patterns

```go
// Connection String Patterns
// Development
"file:./data/dev.db?_journal=WAL&_timeout=5000"

// Production
"file:/var/lib/myapp/prod.db?_journal=WAL&_timeout=5000&_sync=NORMAL"

// Testing
"file::memory:?_journal=WAL"
```

#### Migration Strategy

- Embed migrations in binary using embed package
- Run migrations on startup
- Use simple numbered SQL files
- Version the database schema in a table

#### Backup Strategy

```go
func (db *DB) Backup(destPath string) error {
    destDB, err := sql.Open("sqlite", destPath)
    if err != nil {
        return err
    }
    defer destDB.Close()
    
    return db.ExecContext(ctx, fmt.Sprintf("VACUUM INTO '%s'", destPath))
}
```

#### Migration Path: SQLite to PostgreSQL (If Ever Needed)

**When to Consider Migration:**
- Multiple concurrent writers become critical (not just nice-to-have)
- Geographic distribution requires true replication
- Need for advanced PostgreSQL-only features (e.g., pub/sub with LISTEN/NOTIFY)
- Team growth requires familiar technology

**Migration is Straightforward:**
1. Both databases use standard SQL
2. Export data using SQLite's `.dump` command
3. Transform SQLite-specific syntax (minimal differences)
4. Import into PostgreSQL
5. Update connection string and driver

**Key Differences to Handle:**
```sql
-- SQLite
AUTOINCREMENT
datetime('now')
JSON type

-- PostgreSQL  
SERIAL/BIGSERIAL
NOW()
JSONB type
```

The beauty is you can defer this decision until you have real data proving you need it. Most applications never do.

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
// Test with in-memory SQLite - no containers needed
func TestUserCreation(t *testing.T) {
    db := setupTestDB(t) // Uses ":memory:" database
    defer db.Close()
    
    user := CreateUser(db, "test@example.com")
    assert.NotNil(t, user.ID)
}

func setupTestDB(t *testing.T) *sql.DB {
    db, err := sql.Open("sqlite", ":memory:")
    require.NoError(t, err)
    
    // Run migrations
    RunMigrations(db)
    return db
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

### When You Hit SQLite Limits (Unlikely for This Use Case)

**1. Performance Bottlenecks:**
- First: Optimize queries and add appropriate indexes
- Second: Implement query result caching in-memory
- Third: Distribute read-only copies for read scaling
- Last: Migrate to PostgreSQL if you need true multi-writer concurrency

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
4. **NoSQL as primary database** - SQLite with JSON support handles documents
5. **React/Vue/Angular** - HTMX delivers the same UX with 10% of the complexity
6. **GraphQL** - REST is fine, you control both ends
7. **Message queues** - Channels and goroutines first
8. **PostgreSQL for single-user/small team tools** - SQLite is superior here

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