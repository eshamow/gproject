# GitHub Issues Frontend - 6-Week Implementation Plan

**Goal**: Ship a working GitHub Issues sync frontend that adds real value in 6 weeks.
**Approach**: Start simple, iterate fast, defer complexity until proven necessary.
**Reality Check**: One developer. Limited time. Ship working software, not perfect architecture.

## Core Philosophy: Foundation Hygiene vs Premature Optimization

**Foundation Hygiene** (Do from Day 1):
- Security: CSRF, secure sessions, SQL injection prevention
- Data integrity: Constraints, transactions, proper error handling  
- User trust: Auth that works, sessions that persist, errors that help
- These are like using seatbelts - not optional, not negotiable

**Premature Optimization** (Defer until needed):
- Abstractions: Repository patterns, dependency injection
- Performance: Caching, connection pooling, query optimization
- Scale: Microservices, message queues, load balancers
- These are like adding a turbocharger - nice, but not for your first car

**The Litmus Test**: Will deferring this make users vulnerable, lose data, or lose trust? If yes, do it now. Otherwise, it can wait.

## Testing Philosophy: Confidence Without Paralysis

**Test for Confidence, Not Coverage**:
- 6 foundation tests on Day 1 (security, data, critical path)
- Add tests when bugs occur (test the exact failure)
- Add tests before refactoring (preserve behavior)
- Stop at ~40-60 total tests for this project size

**The Testing Pyramid (Inverted for Speed)**:
```
        Integration Tests (6-10)
       /                        \
      Critical Path Tests (10-15) 
     /                            \
    Security & Data Tests (10-15)
   /                              \
  Unit Tests (only for complex logic)
```

**Test Timing Rules**:
1. **Before Day 1 ships**: 6 foundation tests only
2. **When a bug is found**: Add regression test immediately
3. **Before refactoring**: Test the code you're changing
4. **When worried**: Test what keeps you up at night
5. **Never**: Test simple CRUD, getters/setters, or obvious code

**Signs You Have Enough Tests**:
- Deployment doesn't require manual testing
- Refactoring doesn't cause anxiety
- Bug reports decrease over time
- All tests run in < 30 seconds

**Signs You Have Too Many Tests**:
- Tests test mocks, not behavior
- Test setup is more complex than the code
- Tests break when implementation (not behavior) changes
- You spend more time fixing tests than features

## Quick Start (Day 1)

**Goal**: Have a working web app with GitHub OAuth in 4 hours.

**Day 1 Foundation Checklist**:
✅ Secure session management (not optional)
✅ CSRF protection (not optional)
✅ Environment variables for secrets (not optional)
✅ Parameterized SQL queries (not optional)
✅ Basic error handling (not optional)
❌ Repository pattern (defer)
❌ Perfect test coverage (defer)
❌ Docker setup (defer)

### Step 1: Project Setup (30 minutes)

```bash
# Create minimal structure
mkdir -p /Users/eshamow/proj/gproject/{cmd/web,internal/app,web/templates,data}
cd /Users/eshamow/proj/gproject

# Initialize Go module
go mod init github.com/yourusername/gproject

# Create .env file
cat > .env << 'EOF'
PORT=8080
DATABASE_URL=file:./data/gproject.db
GITHUB_CLIENT_ID=your-client-id
GITHUB_CLIENT_SECRET=your-client-secret
GITHUB_REDIRECT_URL=http://localhost:8080/auth/callback
SESSION_SECRET=generate-random-32-byte-string-here
GITHUB_REPO_OWNER=your-github-username
GITHUB_REPO_NAME=your-repo-name
ENVIRONMENT=development
EOF

# Create minimal Makefile
cat > Makefile << 'EOF'
.PHONY: run dev test

run:
	go run cmd/web/main.go

dev:
	air -c .air.toml || go run cmd/web/main.go

test:
	go test -v ./...

db-reset:
	rm -f data/gproject.db
	go run cmd/web/main.go migrate
EOF
```

### Step 2: Main Application (1 hour)

```go
// /Users/eshamow/proj/gproject/cmd/web/main.go
package main

import (
    "database/sql"
    "embed"
    "html/template"
    "log"
    "net/http"
    "os"
    
    _ "modernc.org/sqlite"
    "github.com/joho/godotenv"
)

//go:embed all:../../web/templates/*
var templateFS embed.FS

type App struct {
    db       *sql.DB
    tmpl     *template.Template
    config   Config
}

type Config struct {
    Port               string
    DatabaseURL        string
    GitHubClientID     string
    GitHubClientSecret string
    GitHubRedirectURL  string
    SessionSecret      string
    GitHubRepoOwner    string
    GitHubRepoName     string
}

func main() {
    // Load environment
    godotenv.Load()
    
    config := Config{
        Port:               getEnv("PORT", "8080"),
        DatabaseURL:        getEnv("DATABASE_URL", "file:./data/gproject.db"),
        GitHubClientID:     mustGetEnv("GITHUB_CLIENT_ID"),
        GitHubClientSecret: mustGetEnv("GITHUB_CLIENT_SECRET"),
        GitHubRedirectURL:  getEnv("GITHUB_REDIRECT_URL", "http://localhost:8080/auth/callback"),
        SessionSecret:      mustGetEnv("SESSION_SECRET"),
        GitHubRepoOwner:    mustGetEnv("GITHUB_REPO_OWNER"),
        GitHubRepoName:     mustGetEnv("GITHUB_REPO_NAME"),
    }
    
    // Open database
    db, err := sql.Open("sqlite", config.DatabaseURL)
    if err != nil {
        log.Fatal(err)
    }
    defer db.Close()
    
    // Initialize database
    if len(os.Args) > 1 && os.Args[1] == "migrate" {
        runMigrations(db)
        return
    }
    
    // Parse templates
    tmpl := template.Must(template.ParseFS(templateFS, "web/templates/*.html"))
    
    app := &App{
        db:     db,
        tmpl:   tmpl,
        config: config,
    }
    
    // Setup routes
    mux := http.NewServeMux()
    mux.HandleFunc("/", app.handleHome)
    mux.HandleFunc("/login", app.handleLogin)
    mux.HandleFunc("/auth/callback", app.handleCallback)
    mux.HandleFunc("/issues", app.handleIssues)
    mux.HandleFunc("/sync", app.handleSync)
    
    // Start server
    log.Printf("Starting server on http://localhost:%s", config.Port)
    log.Fatal(http.ListenAndServe(":"+config.Port, mux))
}

func getEnv(key, fallback string) string {
    if value := os.Getenv(key); value != "" {
        return value
    }
    return fallback
}

func mustGetEnv(key string) string {
    value := os.Getenv(key)
    if value == "" {
        log.Fatalf("Required environment variable %s not set", key)
    }
    return value
}

func runMigrations(db *sql.DB) {
    schema := `
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        github_id INTEGER UNIQUE,
        github_login TEXT UNIQUE,
        name TEXT,
        avatar_url TEXT,
        access_token TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    
    CREATE TABLE IF NOT EXISTS sessions (
        id TEXT PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        expires_at DATETIME NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    
    CREATE TABLE IF NOT EXISTS issues (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        github_id INTEGER UNIQUE,
        number INTEGER,
        title TEXT NOT NULL,
        body TEXT,
        state TEXT DEFAULT 'open',
        labels TEXT, -- JSON array
        assignee TEXT,
        author TEXT,
        milestone TEXT,
        created_at DATETIME,
        updated_at DATETIME,
        closed_at DATETIME,
        synced_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    
    CREATE TABLE IF NOT EXISTS repositories (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        owner TEXT NOT NULL,
        name TEXT NOT NULL,
        full_name TEXT UNIQUE,
        description TEXT,
        default_branch TEXT,
        synced_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(owner, name)
    );
    
    CREATE INDEX IF NOT EXISTS idx_issues_state ON issues(state);
    CREATE INDEX IF NOT EXISTS idx_issues_number ON issues(number);
    CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
    `
    
    if _, err := db.Exec(schema); err != nil {
        log.Fatal(err)
    }
    
    log.Println("Migrations completed")
}
```

### Step 3: Basic Templates (1 hour)

```html
<!-- /Users/eshamow/proj/gproject/web/templates/base.html -->
<!DOCTYPE html>
<html>
<head>
    <title>GProject - GitHub Issues Frontend</title>
    <script src="https://unpkg.com/htmx.org@1.9.10"></script>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-50">
    <nav class="bg-white shadow">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div class="flex justify-between h-16">
                <div class="flex items-center">
                    <a href="/" class="text-xl font-bold">GProject</a>
                </div>
                {{if .User}}
                <div class="flex items-center space-x-4">
                    <img src="{{.User.AvatarURL}}" alt="{{.User.Login}}" class="w-8 h-8 rounded-full">
                    <span>{{.User.Login}}</span>
                    <a href="/logout" class="text-red-600">Logout</a>
                </div>
                {{else}}
                <div class="flex items-center">
                    <a href="/login" class="bg-gray-900 text-white px-4 py-2 rounded flex items-center gap-2">
                        <svg class="w-5 h-5" fill="currentColor" viewBox="0 0 24 24">
                            <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/>
                        </svg>
                        Login with GitHub
                    </a>
                </div>
                {{end}}
            </div>
        </div>
    </nav>
    
    <main class="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">
        {{template "content" .}}
    </main>
</body>
</html>
```

```html
<!-- /Users/eshamow/proj/gproject/web/templates/home.html -->
{{define "content"}}
<div class="bg-white shadow rounded-lg p-6">
    <h1 class="text-2xl font-bold mb-4">Dashboard</h1>
    
    {{if .User}}
        <div class="mb-6">
            <div class="flex items-center gap-4">
                <button hx-post="/sync" 
                        hx-target="#sync-status"
                        class="bg-blue-500 text-white px-4 py-2 rounded">
                    Sync with GitHub Issues
                </button>
                <div class="text-sm text-gray-600">
                    Repository: {{.RepoOwner}}/{{.RepoName}}
                </div>
            </div>
            <div id="sync-status" class="mt-2"></div>
        </div>
        
        <div class="grid grid-cols-3 gap-4 mb-6">
            <div class="bg-gray-50 p-4 rounded">
                <div class="text-2xl font-bold">{{.Stats.TotalIssues}}</div>
                <div class="text-gray-600">Total Issues</div>
            </div>
            <div class="bg-green-50 p-4 rounded">
                <div class="text-2xl font-bold text-green-600">{{.Stats.OpenIssues}}</div>
                <div class="text-gray-600">Open Issues</div>
            </div>
            <div class="bg-purple-50 p-4 rounded">
                <div class="text-2xl font-bold text-purple-600">{{.Stats.ClosedIssues}}</div>
                <div class="text-gray-600">Closed Issues</div>
            </div>
        </div>
        
        <div>
            <a href="/issues" class="text-blue-600">View All Issues →</a>
        </div>
    {{else}}
        <p class="text-gray-600">Please login with GitHub to see your issues.</p>
    {{end}}
</div>
{{end}}
```

### Step 4: GitHub OAuth (1.5 hours)

```go
// /Users/eshamow/proj/gproject/internal/app/auth.go
package app

import (
    "context"
    "encoding/json"
    "net/http"
    "strconv"
    
    "golang.org/x/oauth2"
    "golang.org/x/oauth2/github"
)

func (app *App) getOAuthConfig() *oauth2.Config {
    return &oauth2.Config{
        ClientID:     app.config.GitHubClientID,
        ClientSecret: app.config.GitHubClientSecret,
        RedirectURL:  app.config.GitHubRedirectURL,
        Scopes: []string{
            "user:email",
            "repo",        // Full control of private repositories
            "read:org",    // Read org and team membership
        },
        Endpoint: github.Endpoint,
    }
}

func (app *App) handleLogin(w http.ResponseWriter, r *http.Request) {
    config := app.getOAuthConfig()
    // Generate random state for CSRF protection
    state := generateRandomString(32)
    
    // Store state in session/cookie for validation
    http.SetCookie(w, &http.Cookie{
        Name:     "oauth_state",
        Value:    state,
        Path:     "/",
        MaxAge:   600, // 10 minutes
        HttpOnly: true,
        SameSite: http.SameSiteLaxMode,
    })
    
    url := config.AuthCodeURL(state, oauth2.AccessTypeOnline)
    http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func (app *App) handleCallback(w http.ResponseWriter, r *http.Request) {
    // Verify state for CSRF protection
    stateCookie, err := r.Cookie("oauth_state")
    if err != nil || stateCookie.Value != r.URL.Query().Get("state") {
        http.Error(w, "Invalid state parameter", http.StatusBadRequest)
        return
    }
    
    code := r.URL.Query().Get("code")
    config := app.getOAuthConfig()
    
    token, err := config.Exchange(context.Background(), code)
    if err != nil {
        http.Error(w, "Failed to exchange code for token", http.StatusInternalServerError)
        return
    }
    
    // Get user info from GitHub API
    client := config.Client(context.Background(), token)
    resp, err := client.Get("https://api.github.com/user")
    if err != nil {
        http.Error(w, "Failed to get user info", http.StatusInternalServerError)
        return
    }
    defer resp.Body.Close()
    
    var githubUser struct {
        ID        int    `json:"id"`
        Login     string `json:"login"`
        Email     string `json:"email"`
        Name      string `json:"name"`
        AvatarURL string `json:"avatar_url"`
    }
    
    if err := json.NewDecoder(resp.Body).Decode(&githubUser); err != nil {
        http.Error(w, "Failed to parse user info", http.StatusInternalServerError)
        return
    }
    
    // If email is private, fetch it separately
    if githubUser.Email == "" {
        emailResp, err := client.Get("https://api.github.com/user/emails")
        if err == nil {
            defer emailResp.Body.Close()
            var emails []struct {
                Email    string `json:"email"`
                Primary  bool   `json:"primary"`
                Verified bool   `json:"verified"`
            }
            if json.NewDecoder(emailResp.Body).Decode(&emails) == nil {
                for _, e := range emails {
                    if e.Primary && e.Verified {
                        githubUser.Email = e.Email
                        break
                    }
                }
            }
        }
    }
    
    // Create or update user in database
    result, err := app.db.Exec(`
        INSERT INTO users (email, github_id, github_login, name, avatar_url, access_token) 
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(github_id) DO UPDATE SET
            email = excluded.email,
            github_login = excluded.github_login,
            name = excluded.name,
            avatar_url = excluded.avatar_url,
            access_token = excluded.access_token
    `, githubUser.Email, githubUser.ID, githubUser.Login, 
       githubUser.Name, githubUser.AvatarURL, token.AccessToken)
    
    if err != nil {
        http.Error(w, "Failed to save user", http.StatusInternalServerError)
        return
    }
    
    // Get user ID
    var userID int64
    err = app.db.QueryRow("SELECT id FROM users WHERE github_id = ?", githubUser.ID).Scan(&userID)
    if err != nil {
        http.Error(w, "Failed to get user ID", http.StatusInternalServerError)
        return
    }
    
    // Create session
    sessionID := generateRandomString(32)
    _, err = app.db.Exec(`
        INSERT INTO sessions (id, user_id, expires_at)
        VALUES (?, ?, datetime('now', '+7 days'))
    `, sessionID, userID)
    
    if err != nil {
        http.Error(w, "Failed to create session", http.StatusInternalServerError)
        return
    }
    
    // Set session cookie
    http.SetCookie(w, &http.Cookie{
        Name:     "session",
        Value:    sessionID,
        Path:     "/",
        MaxAge:   7 * 24 * 60 * 60, // 7 days
        HttpOnly: true,
        SameSite: http.SameSiteLaxMode,
        Secure:   app.config.Environment == "production",
    })
    
    // Clear OAuth state cookie
    http.SetCookie(w, &http.Cookie{
        Name:   "oauth_state",
        Value:  "",
        Path:   "/",
        MaxAge: -1,
    })
    
    http.Redirect(w, r, "/", http.StatusSeeOther)
}

func generateRandomString(length int) string {
    const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    b := make([]byte, length)
    for i := range b {
        b[i] = charset[rand.Intn(len(charset))]
    }
    return string(b)
}
```

### Day 1 Deliverables

By end of Day 1, you have:
- ✅ Working web server
- ✅ GitHub OAuth login with proper CSRF protection
- ✅ Secure session management (httpOnly, secure, sameSite cookies)
- ✅ SQLite database with proper constraints and transactions
- ✅ Basic UI with Tailwind (can be ugly, must be secure)
- ✅ HTMX for interactivity
- ✅ Error handling that doesn't leak sensitive info
- ✅ Project structure established (simple is fine)
- ✅ **6 Foundation Tests** (auth, session, CSRF, SQL injection, critical path, data integrity)

**What Day 1 is NOT**:
- ❌ Perfectly architected (single main.go is fine)
- ❌ Fully tested (just the 6 foundation tests)
- ❌ Production-optimized (but security-ready)
- ❌ Feature-complete (but foundation-complete)

**The Day 1 Principle**: 
It's okay if it's ugly, slow, or monolithic. It's NOT okay if it's insecure, loses data, or breaks user trust. Ship fast doesn't mean ship carelessly.

**Day 1 Foundation Tests (Write these before shipping):**
```go
// /Users/eshamow/proj/gproject/cmd/web/main_test.go
func TestOAuthFlowWorks(t *testing.T) {
    // Test that users can complete GitHub OAuth
}

func TestSessionPersistence(t *testing.T) {
    // Test that sessions survive server restart
}

func TestCSRFProtection(t *testing.T) {
    // Test that state-changing operations require valid CSRF token
}

func TestSQLInjectionBlocked(t *testing.T) {
    // Test that malicious input doesn't break queries
}

func TestCriticalPath(t *testing.T) {
    // Test that users can login → sync → view issues
}

func TestDataIntegrity(t *testing.T) {
    // Test that failed operations rollback correctly
}
```

**Run it now:**
```bash
go mod tidy
go test ./... # Run your 6 foundation tests
make run
# Visit http://localhost:8080
```

## Phase 1: Working Skeleton (Week 1)

**Goal**: Complete auth, basic CRUD, and UI foundation.

### Day 2: Proper Session Management

```go
// /Users/eshamow/proj/gproject/internal/auth/sessions.go
package auth

import (
    "crypto/rand"
    "database/sql"
    "encoding/hex"
    "net/http"
    "time"
)

type SessionManager struct {
    db *sql.DB
}

type User struct {
    ID          int64
    Email       string
    GitHubID    int
    GitHubLogin string
    Name        string
    AvatarURL   string
    AccessToken string
}

func NewSessionManager(db *sql.DB) *SessionManager {
    return &SessionManager{db: db}
}

func (sm *SessionManager) Create(userID int64) (string, error) {
    sessionID := generateSecureToken(32)
    
    _, err := sm.db.Exec(`
        INSERT INTO sessions (id, user_id, expires_at)
        VALUES (?, ?, ?)
    `, sessionID, userID, time.Now().Add(7*24*time.Hour))
    
    return sessionID, err
}

func (sm *SessionManager) Validate(sessionID string) (*User, error) {
    var user User
    err := sm.db.QueryRow(`
        SELECT u.id, u.email, u.github_id, u.github_login, u.name, u.avatar_url, u.access_token
        FROM users u
        JOIN sessions s ON s.user_id = u.id
        WHERE s.id = ? AND s.expires_at > datetime('now')
    `, sessionID).Scan(&user.ID, &user.Email, &user.GitHubID, 
                       &user.GitHubLogin, &user.Name, &user.AvatarURL, &user.AccessToken)
    
    if err != nil {
        return nil, err
    }
    return &user, nil
}

func (sm *SessionManager) Middleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        cookie, err := r.Cookie("session")
        if err != nil {
            next.ServeHTTP(w, r)
            return
        }
        
        user, err := sm.Validate(cookie.Value)
        if err != nil {
            next.ServeHTTP(w, r)
            return
        }
        
        // Add user to context
        ctx := context.WithValue(r.Context(), "user", user)
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}

func (sm *SessionManager) RequireAuth(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        user := r.Context().Value("user")
        if user == nil {
            http.Redirect(w, r, "/login", http.StatusSeeOther)
            return
        }
        next(w, r)
    }
}

func generateSecureToken(length int) string {
    b := make([]byte, length)
    rand.Read(b)
    return hex.EncodeToString(b)
}
```

### Day 3: GitHub API Client

```go
// /Users/eshamow/proj/gproject/internal/github/client.go
package github

import (
    "context"
    "encoding/json"
    "fmt"
    "net/http"
    "time"
)

type Client struct {
    httpClient *http.Client
    token      string
    baseURL    string
}

type Issue struct {
    ID        int64     `json:"id"`
    Number    int       `json:"number"`
    Title     string    `json:"title"`
    Body      string    `json:"body"`
    State     string    `json:"state"`
    Labels    []Label   `json:"labels"`
    Assignee  *User     `json:"assignee"`
    User      User      `json:"user"` // Author
    Milestone *Milestone `json:"milestone"`
    CreatedAt time.Time `json:"created_at"`
    UpdatedAt time.Time `json:"updated_at"`
    ClosedAt  *time.Time `json:"closed_at"`
}

type Label struct {
    Name        string `json:"name"`
    Color       string `json:"color"`
    Description string `json:"description"`
}

type User struct {
    Login     string `json:"login"`
    AvatarURL string `json:"avatar_url"`
}

type Milestone struct {
    Title       string    `json:"title"`
    Description string    `json:"description"`
    DueOn       *time.Time `json:"due_on"`
}

func NewClient(token string) *Client {
    return &Client{
        httpClient: &http.Client{Timeout: 30 * time.Second},
        token:      token,
        baseURL:    "https://api.github.com",
    }
}

func (c *Client) ListIssues(owner, repo string, options map[string]string) ([]Issue, error) {
    url := fmt.Sprintf("%s/repos/%s/%s/issues", c.baseURL, owner, repo)
    
    // Add query parameters
    if len(options) > 0 {
        url += "?"
        for k, v := range options {
            url += fmt.Sprintf("%s=%s&", k, v)
        }
    }
    
    req, err := http.NewRequest("GET", url, nil)
    if err != nil {
        return nil, err
    }
    
    req.Header.Set("Authorization", "Bearer "+c.token)
    req.Header.Set("Accept", "application/vnd.github.v3+json")
    
    resp, err := c.httpClient.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    
    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("GitHub API error: %d", resp.StatusCode)
    }
    
    var issues []Issue
    if err := json.NewDecoder(resp.Body).Decode(&issues); err != nil {
        return nil, err
    }
    
    return issues, nil
}

func (c *Client) GetIssue(owner, repo string, number int) (*Issue, error) {
    url := fmt.Sprintf("%s/repos/%s/%s/issues/%d", c.baseURL, owner, repo, number)
    
    req, err := http.NewRequest("GET", url, nil)
    if err != nil {
        return nil, err
    }
    
    req.Header.Set("Authorization", "Bearer "+c.token)
    req.Header.Set("Accept", "application/vnd.github.v3+json")
    
    resp, err := c.httpClient.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    
    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("GitHub API error: %d", resp.StatusCode)
    }
    
    var issue Issue
    if err := json.NewDecoder(resp.Body).Decode(&issue); err != nil {
        return nil, err
    }
    
    return &issue, nil
}

// GraphQL alternative for more efficient queries
func (c *Client) GraphQLQuery(query string, variables map[string]interface{}) (map[string]interface{}, error) {
    url := "https://api.github.com/graphql"
    
    payload := map[string]interface{}{
        "query":     query,
        "variables": variables,
    }
    
    jsonPayload, err := json.Marshal(payload)
    if err != nil {
        return nil, err
    }
    
    req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonPayload))
    if err != nil {
        return nil, err
    }
    
    req.Header.Set("Authorization", "Bearer "+c.token)
    req.Header.Set("Content-Type", "application/json")
    
    resp, err := c.httpClient.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    
    var result map[string]interface{}
    if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
        return nil, err
    }
    
    return result, nil
}

// Batch fetch issues using GraphQL for efficiency
func (c *Client) BatchFetchIssues(owner, repo string, count int) ([]Issue, error) {
    query := `
    query($owner: String!, $repo: String!, $count: Int!) {
        repository(owner: $owner, name: $repo) {
            issues(first: $count, orderBy: {field: UPDATED_AT, direction: DESC}) {
                nodes {
                    id
                    number
                    title
                    body
                    state
                    createdAt
                    updatedAt
                    closedAt
                    author {
                        login
                        avatarUrl
                    }
                    assignees(first: 1) {
                        nodes {
                            login
                            avatarUrl
                        }
                    }
                    labels(first: 10) {
                        nodes {
                            name
                            color
                            description
                        }
                    }
                    milestone {
                        title
                        description
                        dueOn
                    }
                }
            }
        }
    }
    `
    
    variables := map[string]interface{}{
        "owner": owner,
        "repo":  repo,
        "count": count,
    }
    
    result, err := c.GraphQLQuery(query, variables)
    if err != nil {
        return nil, err
    }
    
    // Parse GraphQL response into Issue structs
    // Implementation details omitted for brevity
    
    return issues, nil
}
```

### Day 4: Issue Sync & Display

```go
// /Users/eshamow/proj/gproject/internal/sync/sync.go
package sync

import (
    "database/sql"
    "encoding/json"
    "log"
    "time"
    
    "github.com/yourusername/gproject/internal/github"
)

type Syncer struct {
    db     *sql.DB
    client *github.Client
}

func NewSyncer(db *sql.DB, client *github.Client) *Syncer {
    return &Syncer{db: db, client: client}
}

func (s *Syncer) SyncRepository(owner, repo string) error {
    log.Printf("Starting sync for %s/%s", owner, repo)
    
    // Update repository info
    _, err := s.db.Exec(`
        INSERT INTO repositories (owner, name, full_name, synced_at)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(owner, name) DO UPDATE SET
            synced_at = excluded.synced_at
    `, owner, repo, fmt.Sprintf("%s/%s", owner, repo), time.Now())
    
    if err != nil {
        return err
    }
    
    // Fetch all issues (including closed ones)
    options := map[string]string{
        "state":     "all",
        "per_page":  "100",
        "sort":      "updated",
        "direction": "desc",
    }
    
    issues, err := s.client.ListIssues(owner, repo, options)
    if err != nil {
        return err
    }
    
    tx, err := s.db.Begin()
    if err != nil {
        return err
    }
    defer tx.Rollback()
    
    for _, issue := range issues {
        // Convert labels to JSON
        labels, _ := json.Marshal(issue.Labels)
        
        // Get assignee login
        var assignee string
        if issue.Assignee != nil {
            assignee = issue.Assignee.Login
        }
        
        // Get milestone title
        var milestone string
        if issue.Milestone != nil {
            milestone = issue.Milestone.Title
        }
        
        _, err = tx.Exec(`
            INSERT INTO issues (
                github_id, number, title, body, state, labels, 
                assignee, author, milestone, created_at, updated_at, 
                closed_at, synced_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(github_id) DO UPDATE SET
                number = excluded.number,
                title = excluded.title,
                body = excluded.body,
                state = excluded.state,
                labels = excluded.labels,
                assignee = excluded.assignee,
                milestone = excluded.milestone,
                updated_at = excluded.updated_at,
                closed_at = excluded.closed_at,
                synced_at = excluded.synced_at
        `, issue.ID, issue.Number, issue.Title, issue.Body, issue.State,
           string(labels), assignee, issue.User.Login, milestone,
           issue.CreatedAt, issue.UpdatedAt, issue.ClosedAt, time.Now())
        
        if err != nil {
            log.Printf("Error syncing issue #%d: %v", issue.Number, err)
            continue
        }
    }
    
    if err := tx.Commit(); err != nil {
        return err
    }
    
    log.Printf("Synced %d issues for %s/%s", len(issues), owner, repo)
    return nil
}

func (s *Syncer) GetSyncStats(owner, repo string) (map[string]interface{}, error) {
    stats := make(map[string]interface{})
    
    // Get issue counts
    err := s.db.QueryRow(`
        SELECT 
            COUNT(*) as total,
            COUNT(CASE WHEN state = 'open' THEN 1 END) as open,
            COUNT(CASE WHEN state = 'closed' THEN 1 END) as closed
        FROM issues
    `).Scan(&stats["total"], &stats["open"], &stats["closed"])
    
    if err != nil {
        return nil, err
    }
    
    // Get last sync time
    var lastSync *time.Time
    err = s.db.QueryRow(`
        SELECT synced_at FROM repositories WHERE owner = ? AND name = ?
    `, owner, repo).Scan(&lastSync)
    
    if err == nil && lastSync != nil {
        stats["last_sync"] = lastSync.Format("2006-01-02 15:04:05")
    }
    
    return stats, nil
}
```

### Day 5: Issues List UI

```html
<!-- /Users/eshamow/proj/gproject/web/templates/issues.html -->
{{define "content"}}
<div class="bg-white shadow rounded-lg">
    <div class="px-6 py-4 border-b">
        <div class="flex justify-between items-center">
            <h1 class="text-xl font-bold">Issues</h1>
            <div class="flex gap-2">
                <input type="search" 
                       placeholder="Search issues..." 
                       class="px-3 py-1 border rounded"
                       hx-get="/issues"
                       hx-trigger="keyup changed delay:500ms"
                       hx-target="#issues-list"
                       name="q">
                <select hx-get="/issues" 
                        hx-target="#issues-list"
                        name="state"
                        class="px-3 py-1 border rounded">
                    <option value="">All</option>
                    <option value="open">Open</option>
                    <option value="closed">Closed</option>
                </select>
                <select hx-get="/issues" 
                        hx-target="#issues-list"
                        name="label"
                        class="px-3 py-1 border rounded">
                    <option value="">All Labels</option>
                    {{range .Labels}}
                    <option value="{{.}}">{{.}}</option>
                    {{end}}
                </select>
            </div>
        </div>
    </div>
    
    <div id="issues-list">
        {{range .Issues}}
        <div class="px-6 py-4 border-b hover:bg-gray-50">
            <div class="flex justify-between">
                <div class="flex-1">
                    <a href="/issues/{{.Number}}" class="text-blue-600 font-medium hover:underline">
                        #{{.Number}} {{.Title}}
                    </a>
                    <div class="text-sm text-gray-600 mt-1">
                        {{if eq .State "open"}}
                            <span class="text-green-600">● Open</span>
                        {{else}}
                            <span class="text-purple-600">✓ Closed</span>
                        {{end}}
                        • Opened {{.CreatedAt.Format "Jan 2"}} by {{.Author}}
                        {{if .Assignee}}• Assigned to {{.Assignee}}{{end}}
                    </div>
                </div>
                <div class="flex gap-2 items-start">
                    {{range .ParsedLabels}}
                    <span class="px-2 py-1 text-xs rounded" 
                          style="background-color: #{{.Color}}20; color: #{{.Color}}">
                        {{.Name}}
                    </span>
                    {{end}}
                </div>
            </div>
        </div>
        {{else}}
        <div class="px-6 py-8 text-center text-gray-500">
            No issues found. Click "Sync" to import from GitHub.
        </div>
        {{end}}
    </div>
</div>
{{end}}
```

### Week 1 Deliverables

- ✅ Complete authentication system with GitHub OAuth
- ✅ GitHub REST & GraphQL API integration
- ✅ Issue sync functionality
- ✅ Issues list with search/filter
- ✅ Basic UI working end-to-end
- ✅ **Foundation Tests**: ~10-15 tests total covering critical paths

## Phase 2: GitHub Sync & Webhooks (Week 2)

**Goal**: Robust sync, real-time updates via webhooks, and issue management.

### Day 6-7: GitHub Webhooks

```go
// /Users/eshamow/proj/gproject/internal/webhooks/github.go
package webhooks

import (
    "crypto/hmac"
    "crypto/sha256"
    "encoding/hex"
    "encoding/json"
    "io"
    "net/http"
)

type WebhookHandler struct {
    db     *sql.DB
    secret string
    syncer *sync.Syncer
}

func NewWebhookHandler(db *sql.DB, secret string, syncer *sync.Syncer) *WebhookHandler {
    return &WebhookHandler{
        db:     db,
        secret: secret,
        syncer: syncer,
    }
}

func (h *WebhookHandler) Handle(w http.ResponseWriter, r *http.Request) {
    // Verify GitHub signature
    signature := r.Header.Get("X-Hub-Signature-256")
    if signature == "" {
        http.Error(w, "No signature", http.StatusUnauthorized)
        return
    }
    
    body, err := io.ReadAll(r.Body)
    if err != nil {
        http.Error(w, "Cannot read body", http.StatusBadRequest)
        return
    }
    
    if !h.verifySignature(signature, body) {
        http.Error(w, "Invalid signature", http.StatusUnauthorized)
        return
    }
    
    // Parse event type
    eventType := r.Header.Get("X-GitHub-Event")
    
    switch eventType {
    case "issues":
        h.handleIssueEvent(body)
    case "issue_comment":
        h.handleIssueCommentEvent(body)
    case "ping":
        w.WriteHeader(http.StatusOK)
        w.Write([]byte("pong"))
    default:
        log.Printf("Unhandled webhook event: %s", eventType)
    }
    
    w.WriteHeader(http.StatusOK)
}

func (h *WebhookHandler) verifySignature(signature string, body []byte) bool {
    mac := hmac.New(sha256.New, []byte(h.secret))
    mac.Write(body)
    expectedMAC := mac.Sum(nil)
    expectedSig := "sha256=" + hex.EncodeToString(expectedMAC)
    return hmac.Equal([]byte(signature), []byte(expectedSig))
}

func (h *WebhookHandler) handleIssueEvent(body []byte) {
    var event struct {
        Action string        `json:"action"`
        Issue  github.Issue  `json:"issue"`
        Repository struct {
            Owner struct {
                Login string `json:"login"`
            } `json:"owner"`
            Name string `json:"name"`
        } `json:"repository"`
    }
    
    if err := json.Unmarshal(body, &event); err != nil {
        log.Printf("Failed to parse issue event: %v", err)
        return
    }
    
    log.Printf("Issue %s: #%d %s", event.Action, event.Issue.Number, event.Issue.Title)
    
    // Update issue in database
    labels, _ := json.Marshal(event.Issue.Labels)
    
    var assignee string
    if event.Issue.Assignee != nil {
        assignee = event.Issue.Assignee.Login
    }
    
    _, err := h.db.Exec(`
        INSERT INTO issues (
            github_id, number, title, body, state, labels, 
            assignee, author, created_at, updated_at, closed_at, synced_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(github_id) DO UPDATE SET
            title = excluded.title,
            body = excluded.body,
            state = excluded.state,
            labels = excluded.labels,
            assignee = excluded.assignee,
            updated_at = excluded.updated_at,
            closed_at = excluded.closed_at,
            synced_at = excluded.synced_at
    `, event.Issue.ID, event.Issue.Number, event.Issue.Title, 
       event.Issue.Body, event.Issue.State, string(labels), 
       assignee, event.Issue.User.Login,
       event.Issue.CreatedAt, event.Issue.UpdatedAt, 
       event.Issue.ClosedAt, time.Now())
    
    if err != nil {
        log.Printf("Failed to update issue: %v", err)
    }
    
    // Broadcast update to connected clients
    h.broadcastUpdate(fmt.Sprintf("issue-%s", event.Action), event.Issue)
}

// Setup webhook in GitHub repository
func (h *WebhookHandler) RegisterWebhook(owner, repo, url string) error {
    // This would use GitHub API to register the webhook
    // Implementation depends on your deployment URL
    return nil
}
```

### Day 8-9: Background Sync Worker

```go
// /Users/eshamow/proj/gproject/internal/workers/sync_worker.go
package workers

import (
    "context"
    "database/sql"
    "log"
    "time"
)

type SyncWorker struct {
    db       *sql.DB
    syncer   *sync.Syncer
    interval time.Duration
}

func NewSyncWorker(db *sql.DB, syncer *sync.Syncer) *SyncWorker {
    return &SyncWorker{
        db:       db,
        syncer:   syncer,
        interval: 15 * time.Minute, // Less frequent since we have webhooks
    }
}

func (w *SyncWorker) Start(ctx context.Context) {
    ticker := time.NewTicker(w.interval)
    defer ticker.Stop()
    
    // Initial sync
    w.runSync()
    
    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            w.runSync()
        }
    }
}

func (w *SyncWorker) runSync() {
    log.Println("Starting scheduled sync...")
    
    // Get all repositories to sync
    rows, err := w.db.Query(`
        SELECT DISTINCT owner, name FROM repositories
    `)
    if err != nil {
        log.Printf("Sync error: %v", err)
        return
    }
    defer rows.Close()
    
    type repo struct {
        owner string
        name  string
    }
    
    var repos []repo
    for rows.Next() {
        var r repo
        rows.Scan(&r.owner, &r.name)
        repos = append(repos, r)
    }
    
    // Sync each repository
    for _, r := range repos {
        if err := w.syncer.SyncRepository(r.owner, r.name); err != nil {
            log.Printf("Error syncing %s/%s: %v", r.owner, r.name, err)
        }
        
        // Rate limit friendly - GitHub allows 5000 requests per hour
        time.Sleep(2 * time.Second)
    }
    
    log.Println("Scheduled sync completed")
}
```

### Day 10: Real-time Updates with SSE

```go
// /Users/eshamow/proj/gproject/internal/realtime/sse.go
package realtime

import (
    "encoding/json"
    "fmt"
    "net/http"
    "sync"
)

type SSEBroker struct {
    clients map[chan string]bool
    mu      sync.RWMutex
}

func NewSSEBroker() *SSEBroker {
    return &SSEBroker{
        clients: make(map[chan string]bool),
    }
}

func (b *SSEBroker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "text/event-stream")
    w.Header().Set("Cache-Control", "no-cache")
    w.Header().Set("Connection", "keep-alive")
    w.Header().Set("Access-Control-Allow-Origin", "*")
    
    client := make(chan string, 10)
    
    b.mu.Lock()
    b.clients[client] = true
    b.mu.Unlock()
    
    defer func() {
        b.mu.Lock()
        delete(b.clients, client)
        b.mu.Unlock()
        close(client)
    }()
    
    flusher, ok := w.(http.Flusher)
    if !ok {
        http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
        return
    }
    
    // Send initial connection message
    fmt.Fprintf(w, "event: connected\ndata: {\"message\":\"Connected to updates\"}\n\n")
    flusher.Flush()
    
    for {
        select {
        case event := <-client:
            fmt.Fprintf(w, "%s\n\n", event)
            flusher.Flush()
            
        case <-r.Context().Done():
            return
        }
    }
}

func (b *SSEBroker) Publish(eventType string, data interface{}) {
    jsonData, err := json.Marshal(data)
    if err != nil {
        log.Printf("Failed to marshal SSE data: %v", err)
        return
    }
    
    event := fmt.Sprintf("event: %s\ndata: %s", eventType, jsonData)
    
    b.mu.RLock()
    defer b.mu.RUnlock()
    
    for client := range b.clients {
        select {
        case client <- event:
        default:
            // Client buffer is full, skip
        }
    }
}

// Client-side JavaScript for SSE
const sseScript = `
<script>
const eventSource = new EventSource('/events');

eventSource.addEventListener('issue-opened', (e) => {
    const issue = JSON.parse(e.data);
    showNotification('New Issue', '#' + issue.number + ' ' + issue.title);
    // Update UI with HTMX trigger
    htmx.trigger('#issues-list', 'refresh');
});

eventSource.addEventListener('issue-closed', (e) => {
    const issue = JSON.parse(e.data);
    showNotification('Issue Closed', '#' + issue.number + ' ' + issue.title);
    htmx.trigger('#issues-list', 'refresh');
});

eventSource.addEventListener('issue-updated', (e) => {
    htmx.trigger('#issues-list', 'refresh');
});

function showNotification(title, body) {
    if (Notification.permission === 'granted') {
        new Notification(title, { body: body, icon: '/favicon.ico' });
    }
}

// Request notification permission
if (Notification.permission === 'default') {
    Notification.requestPermission();
}
</script>
`
```

### Week 2 Deliverables

- ✅ GitHub webhooks for real-time updates
- ✅ Background sync worker with rate limiting
- ✅ Real-time updates via SSE
- ✅ Browser notifications for issue changes
- ✅ Automatic UI updates without refresh
- ✅ **Testing Additions**: +5-10 tests for webhook validation and sync integrity (20-25 total)
- ✅ +5-10 tests for new critical paths

**Week 2 Testing Additions:**
- [ ] Test webhook data doesn't corrupt existing issues
- [ ] Test concurrent sync operations don't conflict
- [ ] Test incremental sync preserves all data
- [ ] Test webhook signature validation
- [ ] Regression tests for Week 2 bugs
- [ ] Total: 20-25 tests cumulative

## Phase 3: Product Features (Week 3-4)

**Goal**: Add value beyond GitHub Issues - epics, themes, reports.

### Day 11-12: Epic Management

```sql
-- Add to migrations
CREATE TABLE epics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT,
    status TEXT DEFAULT 'active',
    color TEXT DEFAULT '#3B82F6',
    owner TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE issue_epics (
    issue_id INTEGER REFERENCES issues(id),
    epic_id INTEGER REFERENCES epics(id),
    PRIMARY KEY (issue_id, epic_id)
);
```

### Day 13-14: Themes & Roadmap

```sql
-- Add to migrations
CREATE TABLE themes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    quarter TEXT, -- e.g., "2024-Q1"
    status TEXT DEFAULT 'planned',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE epic_themes (
    epic_id INTEGER REFERENCES epics(id),
    theme_id INTEGER REFERENCES themes(id),
    PRIMARY KEY (epic_id, theme_id)
);
```

### Day 15-17: Analytics & Reports

```go
// /Users/eshamow/proj/gproject/internal/reports/analytics.go
package reports

import (
    "database/sql"
    "time"
)

type Analytics struct {
    db *sql.DB
}

func (a *Analytics) GetVelocityData(days int) ([]VelocityPoint, error) {
    query := `
        SELECT 
            date(created_at) as day,
            COUNT(*) as opened,
            0 as closed
        FROM issues
        WHERE created_at > datetime('now', '-' || ? || ' days')
        GROUP BY date(created_at)
        
        UNION ALL
        
        SELECT 
            date(closed_at) as day,
            0 as opened,
            COUNT(*) as closed
        FROM issues
        WHERE closed_at > datetime('now', '-' || ? || ' days')
            AND closed_at IS NOT NULL
        GROUP BY date(closed_at)
        
        ORDER BY day
    `
    
    rows, err := a.db.Query(query, days, days)
    if err != nil {
        return nil, err
    }
    defer rows.Close()
    
    // Aggregate by day
    dayMap := make(map[string]*VelocityPoint)
    for rows.Next() {
        var day string
        var opened, closed int
        rows.Scan(&day, &opened, &closed)
        
        if point, exists := dayMap[day]; exists {
            point.Opened += opened
            point.Closed += closed
        } else {
            dayMap[day] = &VelocityPoint{
                Date:   day,
                Opened: opened,
                Closed: closed,
            }
        }
    }
    
    // Convert to sorted slice
    var points []VelocityPoint
    for _, point := range dayMap {
        points = append(points, *point)
    }
    
    sort.Slice(points, func(i, j int) bool {
        return points[i].Date < points[j].Date
    })
    
    return points, nil
}

func (a *Analytics) GetLabelDistribution() ([]LabelCount, error) {
    query := `
        SELECT 
            json_extract(label.value, '$.name') as name,
            json_extract(label.value, '$.color') as color,
            COUNT(*) as count
        FROM issues,
             json_each(issues.labels) as label
        WHERE issues.state = 'open'
        GROUP BY name
        ORDER BY count DESC
    `
    
    rows, err := a.db.Query(query)
    if err != nil {
        return nil, err
    }
    defer rows.Close()
    
    var distribution []LabelCount
    for rows.Next() {
        var lc LabelCount
        rows.Scan(&lc.Name, &lc.Color, &lc.Count)
        distribution = append(distribution, lc)
    }
    
    return distribution, nil
}
```

## Phase 4: Polish & Deploy (Week 5-6)

### Week 5: Testing Gaps & Performance

**Focus: Fill testing gaps based on actual usage, not coverage metrics**

**Priority Order for Adding Tests**:
1. **User-reported bugs** - Test the exact failure case
2. **Your worries** - Test what keeps you up at night
3. **Refactoring targets** - Test before changing
4. **Complex business logic** - Test calculations and rules
5. **Never** - Don't test simple CRUD or framework code

**Skip These Tests**:
- Testing every edge case
- Testing getter/setter methods
- Testing the database itself
- Testing third-party libraries
- Testing UI appearance

**Performance Testing Only If**:
- Users complain about speed
- You measure and find a bottleneck
- You're about to optimize something

### Week 5: Pragmatic Testing Examples

```go
// /Users/eshamow/proj/gproject/internal/app/app_test.go
package app

import (
    "net/http"
    "net/http/httptest"
    "testing"
)

func TestGitHubAuth(t *testing.T) {
    app := setupTestApp(t)
    
    req := httptest.NewRequest("GET", "/login", nil)
    w := httptest.NewRecorder()
    
    app.handleLogin(w, req)
    
    if w.Code != http.StatusTemporaryRedirect {
        t.Errorf("Expected redirect, got %d", w.Code)
    }
    
    location := w.Header().Get("Location")
    if !strings.Contains(location, "github.com/login/oauth/authorize") {
        t.Error("Should redirect to GitHub OAuth")
    }
}

func TestIssueSync(t *testing.T) {
    app := setupTestApp(t)
    
    // Mock GitHub API response
    mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        json.NewEncoder(w).Encode([]github.Issue{
            {
                ID:     123,
                Number: 1,
                Title:  "Test Issue",
                State:  "open",
            },
        })
    }))
    defer mockServer.Close()
    
    // Run sync
    syncer := sync.NewSyncer(app.db, github.NewClient("test-token"))
    err := syncer.SyncRepository("test", "repo")
    
    if err != nil {
        t.Errorf("Sync failed: %v", err)
    }
    
    // Verify issue was saved
    var count int
    app.db.QueryRow("SELECT COUNT(*) FROM issues").Scan(&count)
    
    if count != 1 {
        t.Errorf("Expected 1 issue, got %d", count)
    }
}

// By Week 5, you should have ~40-60 tests total:
// - 6 foundation tests (Day 1)
// - 10-20 feature tests (added during development)
// - 10-20 regression tests (from bugs users found)
// - 5-10 integration tests (for complex workflows)
// - That's enough. Ship it.
```

### Week 6: Deployment

```dockerfile
# Dockerfile
FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=1 GOOS=linux go build -a -installsuffix cgo -o main cmd/web/main.go

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/

COPY --from=builder /app/main .
COPY --from=builder /app/web ./web
COPY --from=builder /app/data ./data

EXPOSE 8080
CMD ["./main"]
```

```yaml
# docker-compose.yml
version: '3.8'

services:
  web:
    build: .
    ports:
      - "8080:8080"
    environment:
      - PORT=8080
      - DATABASE_URL=file:./data/gproject.db
      - GITHUB_CLIENT_ID=${GITHUB_CLIENT_ID}
      - GITHUB_CLIENT_SECRET=${GITHUB_CLIENT_SECRET}
      - GITHUB_REDIRECT_URL=${GITHUB_REDIRECT_URL}
      - SESSION_SECRET=${SESSION_SECRET}
      - GITHUB_REPO_OWNER=${GITHUB_REPO_OWNER}
      - GITHUB_REPO_NAME=${GITHUB_REPO_NAME}
    volumes:
      - ./data:/root/data
    restart: unless-stopped
```

### Production Deployment Script

```bash
#!/bin/bash
# deploy.sh

# Build and push Docker image
docker build -t gproject:latest .
docker tag gproject:latest your-registry/gproject:latest
docker push your-registry/gproject:latest

# Deploy to server (example using SSH)
ssh user@your-server << 'ENDSSH'
cd /opt/gproject
docker pull your-registry/gproject:latest
docker-compose down
docker-compose up -d
ENDSSH

echo "Deployment complete!"
```

## Final Deliverables

By week 6, you have shipped:

### Core Features
- ✅ GitHub OAuth authentication
- ✅ Full GitHub Issues sync (REST & GraphQL)
- ✅ Real-time updates via webhooks
- ✅ Issue search and filtering
- ✅ Epic management
- ✅ Theme-based roadmapping
- ✅ Analytics and velocity tracking

### Technical Excellence
- ✅ SQLite for simple deployment
- ✅ HTMX for reactive UI without complexity
- ✅ Server-sent events for real-time updates
- ✅ Docker deployment ready
- ✅ Comprehensive test coverage
- ✅ Rate-limit aware GitHub API usage

### Architecture Decisions
- **Monolithic by design**: Single binary, embedded assets
- **SQLite over PostgreSQL**: Simplicity wins for MVP
- **HTMX over React**: Ship faster, less complexity
- **Webhooks + SSE**: Real-time without WebSocket complexity
- **GitHub as source of truth**: No bidirectional sync complexity

### What We Deferred
- Multi-repo support (easy to add later)
- User permissions (GitHub handles this)
- Issue creation/editing (use GitHub directly)
- Advanced search (can add Elasticsearch later)
- Mobile app (responsive web is sufficient)

## Post-Launch Iterations

### Quick Wins (Week 7-8)
- Add more repository support
- Implement issue templates
- Add comment syncing
- Create dashboard widgets

### Medium-term (Month 2-3)
- GitHub Actions integration
- Pull request tracking
- Advanced analytics
- Team performance metrics

### Long-term (Month 4-6)
- Multi-organization support
- Custom workflows
- API for integrations
- Advanced reporting

## Success Metrics

Track these from day 1:
- Daily active users
- Issues synced per day
- Average session duration
- Feature usage analytics
- Sync performance metrics

## Pragmatic Principles Applied

1. **Ship Early**: Working OAuth + issue list by Day 1
2. **Ship Secure**: CSRF, sessions, validation from Day 1 (not later)
3. **Iterate Based on Usage**: Don't build features users don't need
4. **Boring Technology**: Go, SQLite, HTMX - all proven, stable
5. **Monolith First**: Don't distribute until you must
6. **GitHub as Source**: Don't replicate GitHub's features
7. **Progressive Enhancement**: SSE/webhooks enhance but aren't required
8. **Operational Simplicity**: Single binary, single database file

## The Golden Rules

### Always Do From Day 1
- **Security hygiene**: Like washing your hands, just do it
- **Data integrity**: Constraints and transactions aren't optional
- **User basics**: Auth, sessions, and error handling that works
- **Code hygiene**: Parameterized queries, environment variables
- **Foundation tests**: 6 tests for security/data/critical paths

### Defer Until Proven Necessary
- **Abstractions**: Let patterns emerge from real code
- **Optimizations**: Measure first, optimize second
- **Architecture**: Monolith until it hurts
- **Testing**: Test the paths users actually use

### The 300-Line Rule
If 300 lines of code protects 100% of your users (like CSRF protection), that's not premature optimization - that's doing your job. If 300 lines of code makes the app 10% faster for power users, that can wait.

### The 30-Second Test Rule
All tests should run in under 30 seconds. If they take longer:
- Use test database fixtures, not full production data
- Mock external API calls after testing them once
- Run slow tests separately (mark with `// +build slow`)
- Remember: Fast tests get run, slow tests get skipped

### Never Debate Working Security Code
The real productivity killer isn't writing security code - it's debating whether to remove it. If security is working, leave it alone and move on.

### Testing Confidence Checklist

**You're ready to ship when**:
✅ OAuth flow has a test
✅ Session security has a test
✅ CSRF protection has a test
✅ SQL injection prevention has a test
✅ Critical user path has a test
✅ Data integrity has a test
✅ Any user-reported bugs have regression tests
✅ Tests run in < 30 seconds
✅ You can deploy without fear

**You're NOT ready when**:
❌ You have 100% coverage but no users
❌ Tests break when refactoring
❌ Test maintenance exceeds feature development
❌ You're testing the framework instead of your code

### Ship Thursday Rule
If it's Thursday and you haven't shipped this week, stop writing tests and ship. You can add tests on Monday. Users can't use tests, they can use features.

Remember: **"Ship fast" means skip the unnecessary, not the essential.** Security, data integrity, user trust, and foundation tests are essential from Day 1. Everything else can iterate.

This plan gets you from zero to production in 6 weeks with a secure, maintainable, extensible codebase that grows with your needs without compromising user safety or developer confidence.