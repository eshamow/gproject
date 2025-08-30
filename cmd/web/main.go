package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"html"
	"fmt"
	"html/template"
	"io"
	"log"
	"regexp"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/joho/godotenv"
	_ "modernc.org/sqlite"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

//go:embed templates/*.html
var templateFS embed.FS

type App struct {
	db          *sql.DB
	tmpl        *template.Template // deprecated - use templates instead
	templates   map[string]*template.Template
	config      Config
	rateLimiter *RateLimiter
	sseClients  map[chan SSEMessage]bool // SSE clients for real-time updates
	sseMutex    sync.RWMutex             // Protect SSE clients map
	syncStatus  *SyncStatus              // Current sync status
}

// RateLimiter implements a simple in-memory rate limiter with automatic cleanup
type RateLimiter struct {
	attempts map[string][]time.Time
	mu       sync.RWMutex
	stopChan chan struct{}
}

func NewRateLimiter() *RateLimiter {
	rl := &RateLimiter{
		attempts: make(map[string][]time.Time),
		stopChan: make(chan struct{}),
	}
	// Start cleanup goroutine to prevent memory leak
	go rl.cleanupRoutine()
	return rl
}

// Stop gracefully shuts down the rate limiter
func (rl *RateLimiter) Stop() {
	close(rl.stopChan)
}

// cleanupRoutine periodically removes old entries to prevent memory leak
func (rl *RateLimiter) cleanupRoutine() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			rl.cleanup()
		case <-rl.stopChan:
			return
		}
	}
}

// cleanup removes entries older than 1 hour
func (rl *RateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	
	cutoff := time.Now().Add(-1 * time.Hour)
	for key, attempts := range rl.attempts {
		var valid []time.Time
		for _, t := range attempts {
			if t.After(cutoff) {
				valid = append(valid, t)
			}
		}
		if len(valid) == 0 {
			delete(rl.attempts, key)
		} else {
			rl.attempts[key] = valid
		}
	}
}

func (rl *RateLimiter) Allow(key string, limit int, window time.Duration) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	
	now := time.Now()
	cutoff := now.Add(-window)
	
	// Clean old attempts for this key
	if attempts, exists := rl.attempts[key]; exists {
		var valid []time.Time
		for _, t := range attempts {
			if t.After(cutoff) {
				valid = append(valid, t)
			}
		}
		rl.attempts[key] = valid
	}
	
	// Check limit
	if len(rl.attempts[key]) >= limit {
		return false
	}
	
	// Add new attempt
	rl.attempts[key] = append(rl.attempts[key], now)
	return true
}

type Config struct {
	Port               string
	DatabaseURL        string
	GitHubClientID     string
	GitHubClientSecret string
	GitHubRedirectURL  string
	SessionSecret      string
	GitHubRepoOwner    string
	EncryptionKey      string // Separate key for token encryption
	GitHubRepoName     string
	Environment        string
	WebhookSecret      string // GitHub webhook secret for signature validation
}

type User struct {
	ID          int64
	Email       string
	GitHubID    int
	GitHubLogin string
	Name        string
	AvatarURL   string
}

// SSEMessage represents a server-sent event message
type SSEMessage struct {
	Event string      `json:"event"`
	Data  interface{} `json:"data"`
}

// SyncStatus tracks the current state of GitHub synchronization
type SyncStatus struct {
	mu           sync.RWMutex
	InProgress   bool      `json:"in_progress"`
	LastSyncAt   time.Time `json:"last_sync_at"`
	IssuesSynced int       `json:"issues_synced"`
	Error        string    `json:"error,omitempty"`
}

// WebhookPayload represents a GitHub webhook payload
type WebhookPayload struct {
	Action string          `json:"action"`
	Issue  json.RawMessage `json:"issue"`
	Repo   json.RawMessage `json:"repository"`
}

func main() {
	// Load environment
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found")
	}

	config := Config{
		Port:               getEnv("PORT", "8080"),
		DatabaseURL:        getEnv("DATABASE_URL", "file:./data/gproject.db"),
		GitHubClientID:     mustGetEnv("GITHUB_CLIENT_ID"),
		GitHubClientSecret: mustGetEnv("GITHUB_CLIENT_SECRET"),
		GitHubRedirectURL:  getEnv("GITHUB_REDIRECT_URL", "http://localhost:8080/auth/callback"),
		SessionSecret:      mustGetEnv("SESSION_SECRET"),
		EncryptionKey:      getEnv("ENCRYPTION_KEY", mustGetEnv("SESSION_SECRET")), // Falls back to SESSION_SECRET for backward compatibility
		GitHubRepoOwner:    mustGetEnv("GITHUB_REPO_OWNER"),
		GitHubRepoName:     mustGetEnv("GITHUB_REPO_NAME"),
		Environment:        getEnv("ENVIRONMENT", "development"),
		WebhookSecret:      getEnv("GITHUB_WEBHOOK_SECRET", ""),
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

	// Run migrations on startup
	runMigrations(db)

	// Parse templates - create a separate template instance for each page
	// to avoid block name conflicts between dashboard and issues templates
	templates := make(map[string]*template.Template)
	
	// List of page templates
	pages := []string{"home.html", "dashboard.html", "issues.html", "epics.html", "themes.html", "reports.html"}
	
	for _, page := range pages {
		// Parse base.html and the specific page template together
		t, err := template.ParseFS(templateFS, "templates/base.html", "templates/"+page)
		if err != nil {
			log.Fatalf("Failed to parse %s: %v", page, err)
		}
		templates[page] = t
	}

	app := &App{
		db:          db,
		templates:   templates,
		config:      config,
		rateLimiter: NewRateLimiter(),
		sseClients:  make(map[chan SSEMessage]bool),
		syncStatus:  &SyncStatus{},
	}

	// Setup routes
	mux := http.NewServeMux()
	mux.HandleFunc("/", app.handleHome)
	mux.HandleFunc("/login", app.handleLogin)
	mux.HandleFunc("/logout", app.handleLogout)
	mux.HandleFunc("/auth/callback", app.handleCallback)
	mux.HandleFunc("/dashboard", app.requireAuth(app.handleDashboard))
	mux.HandleFunc("/issues", app.requireAuth(app.handleIssues))
	mux.HandleFunc("/sync", app.requireAuth(app.handleSync))
	mux.HandleFunc("/epics", app.requireAuth(app.handleEpics))
	mux.HandleFunc("/themes", app.requireAuth(app.handleThemes))
	mux.HandleFunc("/reports", app.requireAuth(app.handleReports))
	
	// API endpoints for issues
	mux.HandleFunc("/api/issues", app.requireAuth(app.handleAPIIssues))
	mux.HandleFunc("/api/issues/search", app.requireAuth(app.handleAPIIssuesSearch))
	mux.HandleFunc("/api/sync/status", app.requireAuth(app.handleAPISyncStatus))
	mux.HandleFunc("/api/dashboard-stats", app.requireAuth(app.handleAPIDashboardStats))
	
	// Week 3-4: Epic and Theme management
	mux.HandleFunc("/api/epics", app.requireAuth(app.handleAPIEpics))
	mux.HandleFunc("/api/epics/", app.requireAuth(app.handleAPIEpic))
	mux.HandleFunc("/api/themes", app.requireAuth(app.handleAPIThemes))
	mux.HandleFunc("/api/themes/", app.requireAuth(app.handleAPITheme))
	mux.HandleFunc("/api/reports", app.requireAuth(app.handleAPIReports))
	
	// Week 2: Real-time features
	mux.HandleFunc("/webhook/github", app.handleWebhook)
	mux.HandleFunc("/events", app.handleSSE) // Remove requireAuth to allow public SSE connection
	
	// Health check endpoint for monitoring
	mux.HandleFunc("/health", app.handleHealth)
	
	// Safari SSE debug page (development only)
	mux.HandleFunc("/safari_sse_test.html", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "safari_sse_test.html")
	})

	// Wrap with security headers middleware
	handler := app.securityHeaders(mux)

	// Start background cleanup tasks
	go app.cleanupExpiredSessions()

	// Start background sync worker
	go app.startBackgroundSync()

	// Start server
	log.Printf("Starting server on http://localhost:%s", config.Port)
	log.Printf("GitHub OAuth configured for repo: %s/%s", config.GitHubRepoOwner, config.GitHubRepoName)
	if config.WebhookSecret != "" {
		log.Println("GitHub webhook endpoint available at: /webhook/github")
	}
	log.Fatal(http.ListenAndServe(":"+config.Port, handler))
}

func (app *App) handleHome(w http.ResponseWriter, r *http.Request) {
	// Only handle exact "/" path, not all unmatched paths
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	
	user := app.getCurrentUser(r)
	
	if user != nil {
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}

	data := map[string]interface{}{
		"User": user,
	}

	if err := app.templates["home.html"].ExecuteTemplate(w, "base.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// handleHealth provides a health check endpoint for monitoring
func (app *App) handleHealth(w http.ResponseWriter, r *http.Request) {
	// Only accept GET requests
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	health := struct {
		Status   string    `json:"status"`
		Database string    `json:"database"`
		Version  string    `json:"version"`
		Time     time.Time `json:"time"`
	}{
		Status:   "ok",
		Database: "ok",
		Version:  "1.0.0", // You can inject this from build flags
		Time:     time.Now().UTC(),
	}

	// Check if database is configured
	if app.db == nil {
		health.Status = "degraded"
		if app.config.Environment == "production" {
			health.Database = "unavailable"
			log.Printf("Health check: database not configured")
		} else {
			health.Database = "error: database not configured"
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(health)
		return
	}

	// Check database connectivity
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	var dbStatus string
	err := app.db.QueryRowContext(ctx, "SELECT 'ok'").Scan(&dbStatus)

	if err != nil {
		// Don't expose database error details in production
		health.Status = "degraded"
		if app.config.Environment == "production" {
			health.Database = "unavailable"
			log.Printf("Health check database error: %v", err) // Log the actual error server-side
		} else {
			health.Database = "error: " + err.Error()
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(health)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(health)
}


func (app *App) handleDashboard(w http.ResponseWriter, r *http.Request) {
	user := app.getCurrentUser(r)
	
	// Generate CSRF token for this session
	var csrfToken string
	if cookie, err := r.Cookie("session"); err == nil {
		csrfToken = app.generateCSRFToken(cookie.Value)
	}
	
	// Get stats from database
	var stats struct {
		TotalIssues  int
		OpenIssues   int
		ClosedIssues int
	}
	
	// Only query database if it's available
	if app.db != nil {
		row := app.db.QueryRow(`
			SELECT 
				COUNT(*) as total,
				COUNT(CASE WHEN state = 'open' THEN 1 END) as open,
				COUNT(CASE WHEN state = 'closed' THEN 1 END) as closed
			FROM issues
		`)
		row.Scan(&stats.TotalIssues, &stats.OpenIssues, &stats.ClosedIssues)
	}

	data := map[string]interface{}{
		"User":      user,
		"Stats":     stats,
		"RepoOwner": app.config.GitHubRepoOwner,
		"RepoName":  app.config.GitHubRepoName,
		"CSRFToken": csrfToken,
	}

	// Check if template exists before executing
	tmpl, exists := app.templates["dashboard.html"]
	if !exists || tmpl == nil {
		log.Printf("Template error: dashboard.html not found")
		if app.config.Environment == "production" {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		} else {
			http.Error(w, "Template not found: dashboard.html", http.StatusInternalServerError)
		}
		return
	}

	if err := tmpl.ExecuteTemplate(w, "base.html", data); err != nil {
		log.Printf("Template execution error: %v", err)
		if app.config.Environment == "production" {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		} else {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}



func (app *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	// Rate limit login attempts by IP
	clientIP := r.RemoteAddr
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		clientIP = xff
	}
	
	if !app.rateLimiter.Allow("login:"+clientIP, 10, 15*time.Minute) {
		http.Error(w, "Too many login attempts. Please try again later.", http.StatusTooManyRequests)
		return
	}
	
	config := app.getOAuthConfig()
	// Generate random state for CSRF protection
	// Generate secure state parameter with 256 bits of entropy for OAuth CSRF protection
	state := generateSecureToken(32)

	// Store state in session/cookie for validation
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_state",
		Value:    state,
		Path:     "/",
		MaxAge:   600, // 10 minutes
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode, // Keep Lax for OAuth flow
		Secure:   app.config.Environment == "production",
	})

	url := config.AuthCodeURL(state, oauth2.AccessTypeOnline)
	if app.config.Environment != "production" {
		log.Printf("OAuth Login: Redirecting to GitHub: %s", url)
	} else {
		log.Printf("OAuth Login: Initiating GitHub authentication")
	}
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func (app *App) handleLogout(w http.ResponseWriter, r *http.Request) {
	// Get session cookie
	cookie, err := r.Cookie("session")
	if err == nil {
		// Delete session from database
		app.db.Exec("DELETE FROM sessions WHERE id = ?", cookie.Value)
	}

	// Clear session cookie
	http.SetCookie(w, &http.Cookie{
		Name:   "session",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (app *App) handleCallback(w http.ResponseWriter, r *http.Request) {
	// Log callback details - reduce verbosity in production
	if app.config.Environment != "production" {
		code := r.URL.Query().Get("code")
		state := r.URL.Query().Get("state")
		// Only log first 6 chars of sensitive data
		codePreview := "***"
		if len(code) >= 6 {
			codePreview = code[:6] + "..."
		}
		log.Printf("OAuth Callback: code=%s, state=%s...", codePreview, state[:8])
	} else {
		log.Printf("OAuth Callback: Processing authentication")
	}
	
	// Verify state for CSRF protection
	stateCookie, err := r.Cookie("oauth_state")
	if err != nil || stateCookie.Value != r.URL.Query().Get("state") {
		if app.config.Environment != "production" {
			log.Printf("OAuth state mismatch: cookie exists=%v, states match=%v", 
				err == nil, stateCookie != nil && stateCookie.Value == r.URL.Query().Get("state"))
		}
		http.Error(w, "Invalid state parameter", http.StatusBadRequest)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" || len(code) > 256 {
		http.Error(w, "Invalid authorization code", http.StatusBadRequest)
		return
	}
	config := app.getOAuthConfig()

	token, err := config.Exchange(context.Background(), code)
	if err != nil {
		log.Printf("OAuth ERROR: Failed to exchange code for token: %v", err)
		http.Error(w, "Failed to exchange code for token", http.StatusInternalServerError)
		return
	}
	if app.config.Environment != "production" {
		log.Printf("OAuth: Successfully exchanged code for token")
	}

	// Get user info from GitHub API
	client := config.Client(context.Background(), token)
	resp, err := client.Get("https://api.github.com/user")
	if err != nil {
		log.Printf("OAuth ERROR: Failed to get user info: %v", err)
		http.Error(w, "Failed to get user info", http.StatusInternalServerError)
		return
	}
	if app.config.Environment != "production" {
		log.Printf("OAuth: Successfully fetched user info from GitHub")
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

	// Default email if still empty
	if githubUser.Email == "" {
		githubUser.Email = fmt.Sprintf("%s@users.noreply.github.com", githubUser.Login)
	}

	// Encrypt the access token before storing
	encryptedToken, err := app.encryptToken(token.AccessToken)
	if err != nil {
		http.Error(w, "Failed to secure token", http.StatusInternalServerError)
		return
	}

	// Create or update user in database
	if app.config.Environment != "production" {
		log.Printf("OAuth: Saving user to database - Login=%s", githubUser.Login)
	}
	_, err = app.db.Exec(`
		INSERT INTO users (email, github_id, github_login, name, avatar_url, access_token) 
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(github_id) DO UPDATE SET
			email = excluded.email,
			github_login = excluded.github_login,
			name = excluded.name,
			avatar_url = excluded.avatar_url,
			access_token = excluded.access_token
	`, githubUser.Email, githubUser.ID, githubUser.Login,
		githubUser.Name, githubUser.AvatarURL, encryptedToken)

	if err != nil {
		log.Printf("OAuth ERROR: Failed to save user to database: %v", err)
		http.Error(w, "Failed to save user", http.StatusInternalServerError)
		return
	}
	if app.config.Environment != "production" {
		log.Printf("OAuth: User saved successfully")
	}

	// Get user ID
	var userID int64
	err = app.db.QueryRow("SELECT id FROM users WHERE github_id = ?", githubUser.ID).Scan(&userID)
	if err != nil {
		http.Error(w, "Failed to get user ID", http.StatusInternalServerError)
		return
	}

	// Create session
	// Generate cryptographically secure session ID with 256 bits of entropy (32 bytes = 64 hex chars)
	sessionID := generateSecureToken(32)
	_, err = app.db.Exec(`
		INSERT INTO sessions (id, user_id, expires_at)
		VALUES (?, ?, datetime('now', '+7 days'))
	`, sessionID, userID)

	if err != nil {
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	// Set session cookie with security best practices
	// IMPORTANT: Using SameSiteLaxMode for OAuth redirects to work properly
	// Strict mode prevents cookies from being sent on redirects from external sites (GitHub)
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    sessionID,
		Path:     "/",
		MaxAge:   7 * 24 * 60 * 60, // 7 days
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode, // Lax mode allows cookies on top-level navigation
		Secure:   app.config.Environment == "production",
	})

	// Clear OAuth state cookie
	http.SetCookie(w, &http.Cookie{
		Name:   "oauth_state",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})

	if app.config.Environment != "production" {
		log.Printf("OAuth: Login successful for user %s, redirecting to /dashboard", githubUser.Login)
	} else {
		log.Printf("OAuth: Authentication completed successfully")
	}
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

func (app *App) handleIssues(w http.ResponseWriter, r *http.Request) {
	user := app.getCurrentUser(r)
	
	// Generate CSRF token for this session
	var csrfToken string
	if cookie, err := r.Cookie("session"); err == nil {
		csrfToken = app.generateCSRFToken(cookie.Value)
	}
	
	data := struct {
		User      *User
		CSRFToken string
		RepoOwner string
		RepoName  string
	}{
		User:      user,
		CSRFToken: csrfToken,
		RepoOwner: app.config.GitHubRepoOwner,
		RepoName:  app.config.GitHubRepoName,
	}
	
	if err := app.templates["issues.html"].ExecuteTemplate(w, "base.html", data); err != nil {
		log.Printf("Error rendering issues template: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

func (app *App) handleSync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	user := app.getCurrentUser(r)
	if user == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Verify CSRF token
	csrfToken := r.Header.Get("X-CSRF-Token")
	if csrfToken == "" {
		csrfToken = r.FormValue("csrf_token")
	}
	
	if !app.validateCSRFToken(r, csrfToken) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	// Trigger incremental sync (it will get the token itself)
	go app.performIncrementalSync()

	w.Write([]byte(`<div class="text-green-600">Sync started! Refresh the page in a few seconds to see updated data.</div>`))
}

func (app *App) syncIssues(accessToken string) {
	// Create OAuth2 client
	ctx := context.Background()
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: accessToken})
	client := oauth2.NewClient(ctx, ts)

	// First, sync repository information
	repoURL := fmt.Sprintf("https://api.github.com/repos/%s/%s",
		app.config.GitHubRepoOwner, app.config.GitHubRepoName)
	
	respRepo, err := client.Get(repoURL)
	if err != nil {
		log.Printf("Failed to fetch repository info: %v", err)
		return
	}
	defer respRepo.Body.Close()
	
	var repo struct {
		ID              int64     `json:"id"`
		Name            string    `json:"name"`
		FullName        string    `json:"full_name"`
		Description     string    `json:"description"`
		Private         bool      `json:"private"`
		DefaultBranch   string    `json:"default_branch"`
		StargazersCount int       `json:"stargazers_count"`
		OpenIssuesCount int       `json:"open_issues_count"`
		CreatedAt       time.Time `json:"created_at"`
		UpdatedAt       time.Time `json:"updated_at"`
		Owner           struct {
			Login string `json:"login"`
		} `json:"owner"`
	}
	
	if err := json.NewDecoder(respRepo.Body).Decode(&repo); err != nil {
		log.Printf("Failed to parse repository info: %v", err)
		return
	}
	
	// Save repository information
	_, err = app.db.Exec(`
		INSERT INTO repositories (
			github_id, owner, name, full_name, description,
			default_branch, private, stargazers_count, open_issues_count,
			created_at, updated_at, synced_at
		)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(github_id) DO UPDATE SET
			name = excluded.name,
			full_name = excluded.full_name,
			description = excluded.description,
			default_branch = excluded.default_branch,
			private = excluded.private,
			stargazers_count = excluded.stargazers_count,
			open_issues_count = excluded.open_issues_count,
			updated_at = excluded.updated_at,
			synced_at = excluded.synced_at
	`, repo.ID, repo.Owner.Login, repo.Name, repo.FullName, repo.Description,
		repo.DefaultBranch, repo.Private, repo.StargazersCount, repo.OpenIssuesCount,
		repo.CreatedAt, repo.UpdatedAt, time.Now())
	
	if err != nil {
		log.Printf("Failed to save repository info: %v", err)
	}

	// Fetch all issues with pagination
	page := 1
	totalSynced := 0
	
	for {
		url := fmt.Sprintf("https://api.github.com/repos/%s/%s/issues?state=all&per_page=100&page=%d",
			app.config.GitHubRepoOwner, app.config.GitHubRepoName, page)

		resp, err := client.Get(url)
		if err != nil {
			log.Printf("Failed to fetch issues page %d: %v", page, err)
			return
		}
		defer resp.Body.Close()

		var issues []struct {
			ID        int64     `json:"id"`
			Number    int       `json:"number"`
			Title     string    `json:"title"`
			Body      string    `json:"body"`
			State     string    `json:"state"`
			CreatedAt time.Time `json:"created_at"`
			UpdatedAt time.Time `json:"updated_at"`
			ClosedAt  *time.Time `json:"closed_at"`
			User      struct {
				Login string `json:"login"`
			} `json:"user"`
			Assignee *struct {
				Login string `json:"login"`
			} `json:"assignee"`
			Labels []struct {
				Name  string `json:"name"`
				Color string `json:"color"`
			} `json:"labels"`
			Milestone *struct {
				Title string `json:"title"`
			} `json:"milestone"`
			PullRequest *struct {
				URL string `json:"url"`
			} `json:"pull_request"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&issues); err != nil {
			log.Printf("Failed to parse issues: %v", err)
			break
		}
		
		if len(issues) == 0 {
			break // No more issues
		}

		// Save issues to database (skip pull requests)
		for _, issue := range issues {
			// Skip pull requests (they appear as issues in the API)
			if issue.PullRequest != nil {
				continue
			}
			
			labels, _ := json.Marshal(issue.Labels)
			
			var assignee string
			if issue.Assignee != nil {
				assignee = issue.Assignee.Login
			}
			
			var milestone string
			if issue.Milestone != nil {
				milestone = issue.Milestone.Title
			}

			_, err := app.db.Exec(`
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
				log.Printf("Failed to save issue #%d: %v", issue.Number, err)
			} else {
				totalSynced++
			}
		}
		
		page++
		if len(issues) < 100 {
			break // Last page
		}
	}

	log.Printf("Synced %d issues total", totalSynced)
}

// API endpoint to get all issues with optional filtering
func (app *App) handleAPIIssues(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	// Parse query parameters
	state := r.URL.Query().Get("state") // open, closed, or all
	limit := 100
	offset := 0
	
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := fmt.Sscanf(l, "%d", &limit); err == nil && parsed == 1 && limit > 0 && limit <= 1000 {
			// limit is valid
		} else {
			limit = 100
		}
	}
	
	if o := r.URL.Query().Get("offset"); o != "" {
		if parsed, err := fmt.Sscanf(o, "%d", &offset); err == nil && parsed == 1 && offset >= 0 {
			// offset is valid
		} else {
			offset = 0
		}
	}
	
	// Build query
	query := `
		SELECT 
			id, github_id, number, title, body, state, labels,
			assignee, author, milestone, created_at, updated_at,
			closed_at, synced_at
		FROM issues
	`
	
	var args []interface{}
	if state != "" && state != "all" {
		query += " WHERE state = ?"
		args = append(args, state)
	}
	
	query += " ORDER BY updated_at DESC LIMIT ? OFFSET ?"
	args = append(args, limit, offset)
	
	rows, err := app.db.Query(query, args...)
	if err != nil {
		http.Error(w, `{"error":"Failed to fetch issues"}`, http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	
	type Issue struct {
		ID        int64      `json:"id"`
		GitHubID  int64      `json:"github_id"`
		Number    int        `json:"number"`
		Title     string     `json:"title"`
		Body      string     `json:"body"`
		State     string     `json:"state"`
		Labels    string     `json:"labels_raw"`
		Assignee  *string    `json:"assignee"`
		Author    string     `json:"author"`
		Milestone *string    `json:"milestone"`
		CreatedAt time.Time  `json:"created_at"`
		UpdatedAt time.Time  `json:"updated_at"`
		ClosedAt  *time.Time `json:"closed_at"`
		SyncedAt  time.Time  `json:"synced_at"`
	}
	
	var issues []Issue
	for rows.Next() {
		var issue Issue
		var assignee, milestone sql.NullString
		var closedAt sql.NullTime
		
		err := rows.Scan(
			&issue.ID, &issue.GitHubID, &issue.Number, &issue.Title,
			&issue.Body, &issue.State, &issue.Labels, &assignee,
			&issue.Author, &milestone, &issue.CreatedAt, &issue.UpdatedAt,
			&closedAt, &issue.SyncedAt,
		)
		if err != nil {
			log.Printf("Failed to scan issue: %v", err)
			continue
		}
		
		if assignee.Valid {
			issue.Assignee = &assignee.String
		}
		if milestone.Valid {
			issue.Milestone = &milestone.String
		}
		if closedAt.Valid {
			issue.ClosedAt = &closedAt.Time
		}
		
		issues = append(issues, issue)
	}
	
	// Count total issues for pagination
	var total int
	countQuery := "SELECT COUNT(*) FROM issues"
	if state != "" && state != "all" {
		countQuery += " WHERE state = ?"
		err = app.db.QueryRow(countQuery, state).Scan(&total)
	} else {
		err = app.db.QueryRow(countQuery).Scan(&total)
	}
	
	if err != nil {
		log.Printf("Failed to count issues: %v", err)
	}
	
	// Log API response for debugging
	log.Printf("API Issues: returning %d issues (total: %d, state filter: %s)", 
		len(issues), total, state)
	
	response := map[string]interface{}{
		"issues": issues,
		"total":  total,
		"limit":  limit,
		"offset": offset,
	}
	
	json.NewEncoder(w).Encode(response)
}

// API endpoint for searching issues
func (app *App) handleAPIIssuesSearch(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	query := r.URL.Query().Get("q")
	if query == "" {
		http.Error(w, `{"error":"Query parameter 'q' is required"}`, http.StatusBadRequest)
		return
	}
	
	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := fmt.Sscanf(l, "%d", &limit); err == nil && parsed == 1 && limit > 0 && limit <= 100 {
			// limit is valid
		} else {
			limit = 50
		}
	}
	
	// Simple full-text search in title and body
	searchQuery := `
		SELECT 
			id, github_id, number, title, body, state, labels,
			assignee, author, milestone, created_at, updated_at,
			closed_at, synced_at
		FROM issues
		WHERE (title LIKE ? OR body LIKE ? OR labels LIKE ?)
		ORDER BY updated_at DESC
		LIMIT ?
	`
	
	searchPattern := "%" + query + "%"
	rows, err := app.db.Query(searchQuery, searchPattern, searchPattern, searchPattern, limit)
	if err != nil {
		http.Error(w, `{"error":"Failed to search issues"}`, http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	
	type Issue struct {
		ID        int64      `json:"id"`
		GitHubID  int64      `json:"github_id"`
		Number    int        `json:"number"`
		Title     string     `json:"title"`
		Body      string     `json:"body"`
		State     string     `json:"state"`
		Labels    string     `json:"labels_raw"`
		Assignee  *string    `json:"assignee"`
		Author    string     `json:"author"`
		Milestone *string    `json:"milestone"`
		CreatedAt time.Time  `json:"created_at"`
		UpdatedAt time.Time  `json:"updated_at"`
		ClosedAt  *time.Time `json:"closed_at"`
		SyncedAt  time.Time  `json:"synced_at"`
	}
	
	var issues []Issue
	for rows.Next() {
		var issue Issue
		var assignee, milestone sql.NullString
		var closedAt sql.NullTime
		
		err := rows.Scan(
			&issue.ID, &issue.GitHubID, &issue.Number, &issue.Title,
			&issue.Body, &issue.State, &issue.Labels, &assignee,
			&issue.Author, &milestone, &issue.CreatedAt, &issue.UpdatedAt,
			&closedAt, &issue.SyncedAt,
		)
		if err != nil {
			log.Printf("Failed to scan issue: %v", err)
			continue
		}
		
		if assignee.Valid {
			issue.Assignee = &assignee.String
		}
		if milestone.Valid {
			issue.Milestone = &milestone.String
		}
		if closedAt.Valid {
			issue.ClosedAt = &closedAt.Time
		}
		
		issues = append(issues, issue)
	}
	
	response := map[string]interface{}{
		"issues": issues,
		"query":  query,
		"count":  len(issues),
	}
	
	json.NewEncoder(w).Encode(response)
}

// API endpoint to check sync status
func (app *App) handleAPISyncStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	// Get last sync time for repository
	var lastSync sql.NullTime
	err := app.db.QueryRow(`
		SELECT synced_at FROM repositories 
		WHERE owner = ? AND name = ?
		ORDER BY synced_at DESC LIMIT 1
	`, app.config.GitHubRepoOwner, app.config.GitHubRepoName).Scan(&lastSync)
	
	var lastSyncTime *time.Time
	if err == nil && lastSync.Valid {
		lastSyncTime = &lastSync.Time
	}
	
	// Count issues
	var totalIssues, openIssues, closedIssues int
	app.db.QueryRow("SELECT COUNT(*) FROM issues").Scan(&totalIssues)
	app.db.QueryRow("SELECT COUNT(*) FROM issues WHERE state = 'open'").Scan(&openIssues)
	app.db.QueryRow("SELECT COUNT(*) FROM issues WHERE state = 'closed'").Scan(&closedIssues)
	
	response := map[string]interface{}{
		"repository": map[string]string{
			"owner": app.config.GitHubRepoOwner,
			"name":  app.config.GitHubRepoName,
		},
		"last_sync": lastSyncTime,
		"stats": map[string]int{
			"total":  totalIssues,
			"open":   openIssues,
			"closed": closedIssues,
		},
	}
	
	json.NewEncoder(w).Encode(response)
}

// handleAPIDashboardStats returns dashboard statistics as JSON (for HTMX refresh)
func (app *App) handleAPIDashboardStats(w http.ResponseWriter, r *http.Request) {
	// Get statistics
	var stats struct {
		TotalIssues  int
		OpenIssues   int
		ClosedIssues int
	}
	
	app.db.QueryRow("SELECT COUNT(*) FROM issues").Scan(&stats.TotalIssues)
	app.db.QueryRow("SELECT COUNT(*) FROM issues WHERE state = 'open'").Scan(&stats.OpenIssues)
	app.db.QueryRow("SELECT COUNT(*) FROM issues WHERE state = 'closed'").Scan(&stats.ClosedIssues)
	
	// Return as HTML fragments for HTMX
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `
		<div class="bg-gray-50 p-4 rounded">
			<div class="text-2xl font-bold">%d</div>
			<div class="text-gray-600">Total Issues</div>
		</div>
		<div class="bg-green-50 p-4 rounded">
			<div class="text-2xl font-bold text-green-600">%d</div>
			<div class="text-gray-600">Open Issues</div>
		</div>
		<div class="bg-purple-50 p-4 rounded">
			<div class="text-2xl font-bold text-purple-600">%d</div>
			<div class="text-gray-600">Closed Issues</div>
		</div>
	`, stats.TotalIssues, stats.OpenIssues, stats.ClosedIssues)
}

// handleWebhook processes GitHub webhook events for real-time updates
func (app *App) handleWebhook(w http.ResponseWriter, r *http.Request) {
	// Log incoming webhook request
	log.Printf("Webhook request received: Method=%s, Event=%s, Delivery=%s",
		r.Method,
		r.Header.Get("X-GitHub-Event"),
		r.Header.Get("X-GitHub-Delivery"))
	
	if r.Method != http.MethodPost {
		log.Printf("Webhook rejected: invalid method %s", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Read the payload
	payload, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("Failed to read webhook payload: %v", err)
		http.Error(w, "Failed to read payload", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	log.Printf("Webhook payload size: %d bytes", len(payload))

	// Validate webhook signature if secret is configured
	if app.config.WebhookSecret != "" {
		signature := r.Header.Get("X-Hub-Signature-256")
		if signature == "" {
			log.Printf("Webhook rejected: missing signature header")
			http.Error(w, "Missing signature", http.StatusUnauthorized)
			return
		}

		// Safely truncate signature for logging
		truncatedSig := signature
		if len(signature) > 30 {
			truncatedSig = signature[:30] + "..."
		}
		log.Printf("Validating webhook signature: %s", truncatedSig)
		if !app.validateWebhookSignature(payload, signature) {
			log.Printf("Webhook rejected: invalid signature")
			// Log additional debugging info
			mac := hmac.New(sha256.New, []byte(app.config.WebhookSecret))
			mac.Write(payload)
			calculated := hex.EncodeToString(mac.Sum(nil))
			log.Printf("Expected: sha256=%s", calculated)
			log.Printf("Received: %s", signature)
			http.Error(w, "Invalid signature", http.StatusUnauthorized)
			return
		}
		log.Printf("Webhook signature validated successfully")
	}

	// Get event type
	eventType := r.Header.Get("X-GitHub-Event")
	
	// Store webhook event for audit
	_, err = app.db.Exec(`
		INSERT INTO webhook_events (event_type, signature, payload, processed)
		VALUES (?, ?, ?, 0)
	`, eventType, r.Header.Get("X-Hub-Signature-256"), string(payload))
	
	if err != nil {
		log.Printf("Failed to store webhook event: %v", err)
	}

	// Handle different event types
	switch eventType {
	case "issues":
		app.handleIssueWebhook(payload)
	case "ping":
		log.Println("Received GitHub webhook ping")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("pong"))
		return
	default:
		log.Printf("Unhandled webhook event type: %s", eventType)
	}

	w.WriteHeader(http.StatusOK)
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// validateWebhookSignature validates GitHub webhook signature
func (app *App) validateWebhookSignature(payload []byte, signature string) bool {
	if !strings.HasPrefix(signature, "sha256=") {
		return false
	}
	
	expected := signature[7:] // Remove "sha256=" prefix
	mac := hmac.New(sha256.New, []byte(app.config.WebhookSecret))
	mac.Write(payload)
	calculated := hex.EncodeToString(mac.Sum(nil))
	
	return hmac.Equal([]byte(expected), []byte(calculated))
}

// handleIssueWebhook processes issue webhook events
func (app *App) handleIssueWebhook(payload []byte) {
	var event struct {
		Action string `json:"action"`
		Issue  struct {
			ID        int64     `json:"id"`
			Number    int       `json:"number"`
			Title     string    `json:"title"`
			Body      string    `json:"body"`
			State     string    `json:"state"`
			CreatedAt time.Time `json:"created_at"`
			UpdatedAt time.Time `json:"updated_at"`
			ClosedAt  *time.Time `json:"closed_at"`
			User      struct {
				Login string `json:"login"`
			} `json:"user"`
			Assignee *struct {
				Login string `json:"login"`
			} `json:"assignee"`
			Labels []struct {
				Name string `json:"name"`
			} `json:"labels"`
		} `json:"issue"`
		Repository struct {
			Owner struct {
				Login string `json:"login"`
			} `json:"owner"`
			Name string `json:"name"`
		} `json:"repository"`
	}

	if err := json.Unmarshal(payload, &event); err != nil {
		log.Printf("Failed to unmarshal issue webhook: %v", err)
		log.Printf("Webhook payload sample: %s", string(payload[:min(500, len(payload))]))
		return
	}

	// Validate repository matches our configured repo
	if event.Repository.Owner.Login != app.config.GitHubRepoOwner ||
		event.Repository.Name != app.config.GitHubRepoName {
		log.Printf("Webhook from wrong repository: %s/%s (expected %s/%s)",
			event.Repository.Owner.Login, event.Repository.Name,
			app.config.GitHubRepoOwner, app.config.GitHubRepoName)
		return
	}

	log.Printf("Processing %s event for issue #%d in %s/%s",
		event.Action, event.Issue.Number,
		event.Repository.Owner.Login, event.Repository.Name)

	// Convert labels to JSON string
	labels := []string{}
	for _, l := range event.Issue.Labels {
		labels = append(labels, l.Name)
	}
	labelsJSON, _ := json.Marshal(labels)

	// Update or insert issue
	assignee := ""
	if event.Issue.Assignee != nil {
		assignee = event.Issue.Assignee.Login
	}

	_, err := app.db.Exec(`
		INSERT OR REPLACE INTO issues (
			github_id, number, title, body, state, labels,
			assignee, author, created_at, updated_at, closed_at, synced_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
	`, event.Issue.ID, event.Issue.Number, event.Issue.Title, event.Issue.Body,
		event.Issue.State, string(labelsJSON), assignee, event.Issue.User.Login,
		event.Issue.CreatedAt, event.Issue.UpdatedAt, event.Issue.ClosedAt)

	if err != nil {
		log.Printf("Failed to update issue from webhook: %v", err)
		return
	}

	// Broadcast update to SSE clients
	app.broadcastSSE(SSEMessage{
		Event: "issue_update",
		Data: map[string]interface{}{
			"action": event.Action,
			"issue": map[string]interface{}{
				"number": event.Issue.Number,
				"title":  event.Issue.Title,
				"state":  event.Issue.State,
			},
		},
	})

	log.Printf("Successfully processed webhook: %s issue #%d (state: %s)", event.Action, event.Issue.Number, event.Issue.State)
}

// handleSSE handles Server-Sent Events for real-time updates
func (app *App) handleSSE(w http.ResponseWriter, r *http.Request) {
	// Check if user is authenticated (but don't block connection)
	user := app.getCurrentUser(r)
	isAuthenticated := user != nil
	
	// Set SSE headers with Safari compatibility
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // Disable Nginx buffering

	// Create a channel for this client
	messageChan := make(chan SSEMessage, 10)

	// Register the client
	app.sseMutex.Lock()
	app.sseClients[messageChan] = true
	app.sseMutex.Unlock()

	// Remove client on disconnect
	defer func() {
		app.sseMutex.Lock()
		delete(app.sseClients, messageChan)
		close(messageChan)
		app.sseMutex.Unlock()
	}()

	// Create a ticker for keepalive
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	// Get the flusher for real-time streaming
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	// Send initial connection message
	connectionMsg := "Connected to real-time updates"
	if !isAuthenticated {
		connectionMsg = "Connected (login for full updates)"
	}
	fmt.Fprintf(w, "event: connected\ndata: {\"message\":\"%s\"}\n\n", connectionMsg)
	flusher.Flush()

	// Only send sync status to authenticated users
	if isAuthenticated {
		app.syncStatus.mu.RLock()
		status := map[string]interface{}{
			"in_progress":   app.syncStatus.InProgress,
			"last_sync_at":  app.syncStatus.LastSyncAt,
			"issues_synced": app.syncStatus.IssuesSynced,
		}
		app.syncStatus.mu.RUnlock()
		
		statusJSON, _ := json.Marshal(status)
		fmt.Fprintf(w, "event: sync_status\ndata: %s\n\n", statusJSON)
		flusher.Flush()
	}

	// Listen for messages and client disconnect
	for {
		select {
		case msg := <-messageChan:
			// Only send sensitive messages to authenticated users
			if isAuthenticated || msg.Event == "connected" || msg.Event == "keepalive" {
				// Send message to client
				data, _ := json.Marshal(msg.Data)
				fmt.Fprintf(w, "event: %s\ndata: %s\n\n", msg.Event, data)
				flusher.Flush()
			}

		case <-ticker.C:
			// Send keepalive
			fmt.Fprintf(w, ": keepalive\n\n")
			flusher.Flush()

		case <-r.Context().Done():
			// Client disconnected
			return
		}
	}
}

// broadcastSSE sends a message to all connected SSE clients
func (app *App) broadcastSSE(msg SSEMessage) {
	app.sseMutex.RLock()
	defer app.sseMutex.RUnlock()

	for client := range app.sseClients {
		select {
		case client <- msg:
			// Message sent
		default:
			// Client buffer is full, skip
		}
	}
}

// startBackgroundSync starts the background sync worker
func (app *App) startBackgroundSync() {
	// Initial sync after 10 seconds
	time.Sleep(10 * time.Second)
	app.performIncrementalSync()

	// Then sync every 5 minutes
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		app.performIncrementalSync()
	}
}

// performIncrementalSync performs an incremental sync with rate limiting
func (app *App) performIncrementalSync() {
	// Check if sync is already in progress
	app.syncStatus.mu.Lock()
	if app.syncStatus.InProgress {
		app.syncStatus.mu.Unlock()
		return
	}
	app.syncStatus.InProgress = true
	app.syncStatus.Error = ""
	app.syncStatus.mu.Unlock()

	// Broadcast sync started
	app.broadcastSSE(SSEMessage{
		Event: "sync_started",
		Data:  map[string]interface{}{"timestamp": time.Now()},
	})

	defer func() {
		// Mark sync as complete
		app.syncStatus.mu.Lock()
		app.syncStatus.InProgress = false
		app.syncStatus.LastSyncAt = time.Now()
		app.syncStatus.mu.Unlock()

		// Broadcast sync completed
		app.broadcastSSE(SSEMessage{
			Event: "sync_completed",
			Data: map[string]interface{}{
				"timestamp":     time.Now(),
				"issues_synced": app.syncStatus.IssuesSynced,
			},
		})
	}()

	// Get the most recent user with an access token
	var accessToken string
	err := app.db.QueryRow(`
		SELECT access_token FROM users 
		WHERE access_token IS NOT NULL AND access_token != ''
		ORDER BY id DESC LIMIT 1
	`).Scan(&accessToken)

	if err != nil {
		log.Printf("No access token available for sync: %v", err)
		app.syncStatus.mu.Lock()
		app.syncStatus.Error = "No access token available"
		app.syncStatus.mu.Unlock()
		return
	}

	// Decrypt the access token
	decryptedToken, err := app.decryptToken(accessToken)
	if err != nil {
		log.Printf("Failed to decrypt access token: %v", err)
		app.syncStatus.mu.Lock()
		app.syncStatus.Error = "Failed to decrypt token"
		app.syncStatus.mu.Unlock()
		return
	}

	// Get last sync time - the updated_at is stored as a string in Go's time format
	var lastSyncStr sql.NullString
	err = app.db.QueryRow(`
		SELECT MAX(updated_at)
		FROM issues
		WHERE updated_at IS NOT NULL AND updated_at != ''
	`).Scan(&lastSyncStr)

	var lastSync time.Time
	if err != nil || !lastSyncStr.Valid || lastSyncStr.String == "" {
		log.Printf("No valid last sync time found (error: %v), starting from beginning", err)
		lastSync = time.Unix(0, 0)
	} else {
		// Parse the time string - it's stored in Go's default format
		lastSync, err = time.Parse("2006-01-02 15:04:05 -0700 MST", lastSyncStr.String)
		if err != nil {
			// Try RFC3339 format as fallback
			lastSync, err = time.Parse(time.RFC3339, lastSyncStr.String)
			if err != nil {
				log.Printf("Error parsing last sync time '%s': %v, starting from beginning", lastSyncStr.String, err)
				lastSync = time.Unix(0, 0)
			}
		}
		if !lastSync.IsZero() {
			log.Printf("Last sync time from DB: %s", lastSync.Format(time.RFC3339))
		}
	}

	// Subtract 5 minutes from last sync to catch any concurrent updates
	// GitHub's 'since' parameter is exclusive, so we need to go back a bit
	// to ensure we don't miss issues updated at exactly the same time
	originalLastSync := lastSync
	lastSync = lastSync.Add(-5 * time.Minute)

	// Prepare GitHub API request with incremental sync
	// Use ascending order to process older updates first
	since := lastSync.Format(time.RFC3339)
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/issues?state=all&sort=updated&direction=asc&since=%s&per_page=100",
		app.config.GitHubRepoOwner, app.config.GitHubRepoName, since)

	log.Printf("Starting incremental sync for repo %s/%s", app.config.GitHubRepoOwner, app.config.GitHubRepoName)
	log.Printf("  Original last update: %s", originalLastSync.Format(time.RFC3339))
	log.Printf("  Syncing since: %s (5 minutes before last update)", since)
	log.Printf("  API URL: %s", apiURL)

	// Create HTTP client with rate limiting awareness
	client := &http.Client{Timeout: 30 * time.Second}
	
	// Fetch issues with pagination
	issuesSynced := 0
	page := 1

	for {
		// Rate limit check (GitHub allows 5000 requests/hour for authenticated requests)
		time.Sleep(100 * time.Millisecond) // Simple rate limiting: 10 requests per second max

		pageURL := fmt.Sprintf("%s&page=%d", apiURL, page)
		req, err := http.NewRequest("GET", pageURL, nil)
		if err != nil {
			log.Printf("Failed to create request: %v", err)
			break
		}

		req.Header.Set("Authorization", "Bearer "+decryptedToken)
		req.Header.Set("Accept", "application/vnd.github.v3+json")

		resp, err := client.Do(req)
		if err != nil {
			log.Printf("Failed to fetch issues: %v", err)
			app.syncStatus.mu.Lock()
			app.syncStatus.Error = fmt.Sprintf("Failed to fetch issues: %v", err)
			app.syncStatus.mu.Unlock()
			break
		}

		// Check rate limit headers
		remaining := resp.Header.Get("X-RateLimit-Remaining")
		if remaining != "" {
			if rem, _ := strconv.Atoi(remaining); rem < 100 {
				log.Printf("Rate limit low: %s remaining", remaining)
				// Wait longer if rate limit is low
				time.Sleep(5 * time.Second)
			}
		}

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			log.Printf("GitHub API error: %d - %s", resp.StatusCode, string(body))
			log.Printf("Request URL was: %s", pageURL)
			app.syncStatus.mu.Lock()
			app.syncStatus.Error = fmt.Sprintf("GitHub API error: %d", resp.StatusCode)
			app.syncStatus.mu.Unlock()
			break
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			log.Printf("Failed to read response body: %v", err)
			break
		}

		var issues []map[string]interface{}
		if err := json.Unmarshal(body, &issues); err != nil {
			log.Printf("Failed to decode issues: %v", err)
			log.Printf("Response body (first 500 chars): %s", string(body[:min(500, len(body))]))
			break
		}

		if len(issues) == 0 {
			log.Printf("No more issues to sync on page %d", page)
			break // No more issues
		}
		
		log.Printf("Processing %d issues from page %d", len(issues), page)
		// Log first issue details for debugging
		if len(issues) > 0 {
			if number, ok := issues[0]["number"]; ok {
				if updated, ok := issues[0]["updated_at"]; ok {
					log.Printf("  First issue: #%.0f, updated: %v", number, updated)
				}
			}
		}

		// Store issues in database
		for _, issue := range issues {
			// Skip pull requests (they appear as issues in the API)
			if _, isPR := issue["pull_request"]; isPR {
				continue
			}
			
			if err := app.storeIssue(issue); err != nil {
				log.Printf("Failed to store issue: %v", err)
				continue
			}
			issuesSynced++

			// Broadcast progress update every 10 issues
			if issuesSynced%10 == 0 {
				app.syncStatus.mu.Lock()
				app.syncStatus.IssuesSynced = issuesSynced
				app.syncStatus.mu.Unlock()

				app.broadcastSSE(SSEMessage{
					Event: "sync_progress",
					Data: map[string]interface{}{
						"issues_synced": issuesSynced,
					},
				})
			}
		}

		// Check if we should continue to next page
		if len(issues) < 100 {
			break // This was the last page
		}
		page++
	}

	// Update sync status in database
	_, err = app.db.Exec(`
		INSERT OR REPLACE INTO sync_status (
			repo_owner, repo_name, last_sync_at, sync_in_progress, issues_synced, updated_at
		) VALUES (?, ?, CURRENT_TIMESTAMP, 0, ?, CURRENT_TIMESTAMP)
	`, app.config.GitHubRepoOwner, app.config.GitHubRepoName, issuesSynced)

	if err != nil {
		log.Printf("Failed to update sync status: %v", err)
	}

	app.syncStatus.mu.Lock()
	app.syncStatus.IssuesSynced = issuesSynced
	app.syncStatus.mu.Unlock()

	log.Printf("Incremental sync completed: %d issues synced", issuesSynced)
}

// storeIssue stores a GitHub issue in the database
func (app *App) storeIssue(issue map[string]interface{}) error {
	// Extract fields
	id := int64(issue["id"].(float64))
	number := int(issue["number"].(float64))
	title := issue["title"].(string)
	body := ""
	if issue["body"] != nil {
		body = issue["body"].(string)
	}
	state := issue["state"].(string)

	// Handle labels
	labels := []string{}
	if labelsList, ok := issue["labels"].([]interface{}); ok {
		for _, l := range labelsList {
			if labelMap, ok := l.(map[string]interface{}); ok {
				if name, ok := labelMap["name"].(string); ok {
					labels = append(labels, name)
				}
			}
		}
	}
	labelsJSON, _ := json.Marshal(labels)

	// Handle assignee
	assignee := ""
	if issue["assignee"] != nil {
		if assigneeMap, ok := issue["assignee"].(map[string]interface{}); ok {
			if login, ok := assigneeMap["login"].(string); ok {
				assignee = login
			}
		}
	}

	// Handle author
	author := ""
	if user, ok := issue["user"].(map[string]interface{}); ok {
		if login, ok := user["login"].(string); ok {
			author = login
		}
	}

	// Parse timestamps
	createdAt, _ := time.Parse(time.RFC3339, issue["created_at"].(string))
	updatedAt, _ := time.Parse(time.RFC3339, issue["updated_at"].(string))
	
	var closedAt *time.Time
	if issue["closed_at"] != nil && issue["closed_at"].(string) != "" {
		t, _ := time.Parse(time.RFC3339, issue["closed_at"].(string))
		closedAt = &t
	}

	// Store in database
	_, err := app.db.Exec(`
		INSERT OR REPLACE INTO issues (
			github_id, number, title, body, state, labels,
			assignee, author, created_at, updated_at, closed_at, synced_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
	`, id, number, title, body, state, string(labelsJSON),
		assignee, author, createdAt, updatedAt, closedAt)

	return err
}

func (app *App) getOAuthConfig() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     app.config.GitHubClientID,
		ClientSecret: app.config.GitHubClientSecret,
		RedirectURL:  app.config.GitHubRedirectURL,
		Scopes: []string{
			"user:email",
			"repo",     // Full control of private repositories
			"read:org", // Read org and team membership
		},
		Endpoint: github.Endpoint,
	}
}

func (app *App) getCurrentUser(r *http.Request) *User {
	cookie, err := r.Cookie("session")
	if err != nil {
		return nil
	}

	var user User
	err = app.db.QueryRow(`
		SELECT u.id, u.email, u.github_id, u.github_login, u.name, u.avatar_url
		FROM users u
		JOIN sessions s ON s.user_id = u.id
		WHERE s.id = ? AND s.expires_at > datetime('now')
	`, cookie.Value).Scan(&user.ID, &user.Email, &user.GitHubID,
		&user.GitHubLogin, &user.Name, &user.AvatarURL)

	if err != nil {
		return nil
	}
	return &user
}

func (app *App) requireAuth(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := app.getCurrentUser(r)
		if user == nil {
			// For SSE endpoints, return an error event
			if r.Header.Get("Accept") == "text/event-stream" || r.URL.Path == "/events" {
				w.Header().Set("Content-Type", "text/event-stream")
				w.Header().Set("Cache-Control", "no-cache")
				w.Header().Set("Connection", "close")
				w.WriteHeader(http.StatusUnauthorized)
				fmt.Fprintf(w, "event: error\ndata: {\"error\":\"Authentication required\"}\n\n")
				return
			}
			// For API endpoints, return JSON error
			if strings.HasPrefix(r.URL.Path, "/api/") {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(map[string]string{
					"error": "Authentication required",
				})
				return
			}
			// For regular pages, redirect to login
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		handler(w, r)
	}
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
		// Return a placeholder for development
		if key == "GITHUB_CLIENT_ID" {
			return "dev-client-id"
		}
		if key == "GITHUB_CLIENT_SECRET" {
			return "dev-client-secret"
		}
		if key == "SESSION_SECRET" {
			return "dev-session-secret-32bytes-long!!"
		}
		if key == "GITHUB_REPO_OWNER" {
			return "owner"
		}
		if key == "GITHUB_REPO_NAME" {
			return "repo"
		}
		log.Printf("Warning: Required environment variable %s not set, using placeholder", key)
	}
	return value
}

// generateSecureToken generates a cryptographically secure random token.
// The byteLength parameter specifies the number of random bytes to generate.
// The returned hex string will be 2x the byte length (e.g., 32 bytes = 64 hex chars).
// For session IDs, use at least 16 bytes (128 bits of entropy).
func generateSecureToken(byteLength int) string {
	if byteLength < 16 {
		panic("generateSecureToken: minimum 16 bytes required for security")
	}
	b := make([]byte, byteLength)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("Failed to generate secure random token: %v", err))
	}
	return hex.EncodeToString(b)
}

// generateRandomString is deprecated - use generateSecureToken instead
func generateRandomString(length int) string {
	// Maintain backward compatibility but use secure implementation
	// This generates 'length' bytes, resulting in 2*length hex characters
	if length < 16 {
		length = 16 // Enforce minimum security
	}
	return generateSecureToken(length)
}

// encryptToken encrypts a token using AES-256-GCM
func (app *App) encryptToken(plaintext string) (string, error) {
	// Derive key from session secret
	key := sha256.Sum256([]byte(app.config.EncryptionKey))
	
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// decryptToken decrypts a token encrypted with encryptToken
func (app *App) decryptToken(ciphertext string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	key := sha256.Sum256([]byte(app.config.EncryptionKey))
	
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertextBytes := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertextBytes, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// generateCSRFToken creates a new CSRF token for the session
func (app *App) generateCSRFToken(sessionID string) string {
	// Generate secure CSRF token with 256 bits of entropy
	token := generateSecureToken(32)
	// Store in database with expiration
	app.db.Exec(`
		INSERT OR REPLACE INTO csrf_tokens (session_id, token, expires_at)
		VALUES (?, ?, datetime('now', '+1 hour'))
	`, sessionID, token)
	return token
}

// validateCSRFToken checks if the provided CSRF token is valid
func (app *App) validateCSRFToken(r *http.Request, token string) bool {
	if token == "" {
		return false
	}
	
	cookie, err := r.Cookie("session")
	if err != nil {
		return false
	}
	
	var valid bool
	err = app.db.QueryRow(`
		SELECT COUNT(*) > 0 FROM csrf_tokens 
		WHERE session_id = ? AND token = ? AND expires_at > datetime('now')
	`, cookie.Value, token).Scan(&valid)
	
	return err == nil && valid
}

// securityHeaders adds comprehensive security headers to all responses
func (app *App) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Prevent clickjacking attacks
		w.Header().Set("X-Frame-Options", "DENY")
		
		// Prevent MIME type sniffing
		w.Header().Set("X-Content-Type-Options", "nosniff")
		
		// Enable XSS protection (for older browsers)
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		
		// Referrer policy for privacy
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		
		// Permissions Policy (formerly Feature Policy)
		w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		
		// Content Security Policy
		csp := "default-src 'self'; " +
			"script-src 'self' 'unsafe-inline' https://unpkg.com https://cdn.tailwindcss.com; " +
			"style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; " +
			"img-src 'self' https://avatars.githubusercontent.com data:; " +
			"connect-src 'self'; " +
			"font-src 'self'; " +
			"object-src 'none'; " +
			"base-uri 'self'; " +
			"form-action 'self'; " +
			"frame-ancestors 'none'; " +
			"block-all-mixed-content"
		
		// Production-specific headers
		if app.config.Environment == "production" {
			csp += "; upgrade-insecure-requests"
			// HTTP Strict Transport Security (HSTS)
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
			// Additional production headers
			w.Header().Set("X-Permitted-Cross-Domain-Policies", "none")
		}
		w.Header().Set("Content-Security-Policy", csp)
		
		// Strict Transport Security (only in production)
		if app.config.Environment == "production" {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
		}
		
		// Add request ID for tracing
		requestID := r.Header.Get("X-Request-ID")
		if requestID == "" {
			// Generate request ID with 128 bits of entropy
			requestID = generateSecureToken(16)
		}
		w.Header().Set("X-Request-ID", requestID)
		
		next.ServeHTTP(w, r)
	})
}

// cleanupExpiredSessions periodically removes expired sessions and tokens
func (app *App) cleanupExpiredSessions() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	
	for range ticker.C {
		// Clean expired sessions
		result, err := app.db.Exec(`
			DELETE FROM sessions WHERE expires_at < datetime('now')
		`)
		if err == nil {
			if rows, _ := result.RowsAffected(); rows > 0 {
				log.Printf("Cleaned up %d expired sessions", rows)
			}
		}
		
		// Clean expired CSRF tokens
		result, err = app.db.Exec(`
			DELETE FROM csrf_tokens WHERE expires_at < datetime('now')
		`)
		if err == nil {
			if rows, _ := result.RowsAffected(); rows > 0 {
				log.Printf("Cleaned up %d expired CSRF tokens", rows)
			}
		}
	}
}

// Epic and Theme Management Handlers

func (app *App) handleEpics(w http.ResponseWriter, r *http.Request) {
	user := app.getCurrentUser(r)
	
	data := map[string]interface{}{
		"User": user,
	}
	
	if err := app.templates["epics.html"].ExecuteTemplate(w, "base.html", data); err != nil {
		log.Printf("Template execution error: %v", err)
		if app.config.Environment == "production" {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		} else {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

func (app *App) handleThemes(w http.ResponseWriter, r *http.Request) {
	user := app.getCurrentUser(r)
	
	data := map[string]interface{}{
		"User": user,
	}
	
	if err := app.templates["themes.html"].ExecuteTemplate(w, "base.html", data); err != nil {
		log.Printf("Template execution error: %v", err)
		if app.config.Environment == "production" {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		} else {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

func (app *App) handleReports(w http.ResponseWriter, r *http.Request) {
	user := app.getCurrentUser(r)
	
	data := map[string]interface{}{
		"User": user,
	}
	
	if err := app.templates["reports.html"].ExecuteTemplate(w, "base.html", data); err != nil {
		log.Printf("Template execution error: %v", err)
		if app.config.Environment == "production" {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		} else {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

// API: Epic Management
func (app *App) handleAPIEpics(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		app.getEpics(w, r)
	case http.MethodPost:
		app.createEpic(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (app *App) handleAPIEpic(w http.ResponseWriter, r *http.Request) {
	// Extract epic ID from path
	path := r.URL.Path
	parts := strings.Split(strings.TrimPrefix(path, "/api/epics/"), "/")
	if len(parts) < 1 || parts[0] == "" {
		http.Error(w, "Epic ID required", http.StatusBadRequest)
		return
	}
	
	epicID, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		http.Error(w, "Invalid epic ID", http.StatusBadRequest)
		return
	}
	
	// Handle issue assignment to epic
	if len(parts) > 1 && parts[1] == "issues" {
		switch r.Method {
		case http.MethodPost:
			app.assignIssueToEpic(w, r, epicID)
		case http.MethodDelete:
			app.removeIssueFromEpic(w, r, epicID)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
		return
	}
	
	switch r.Method {
	case http.MethodGet:
		app.getEpic(w, r, epicID)
	case http.MethodPut:
		app.updateEpic(w, r, epicID)
	case http.MethodDelete:
		app.deleteEpic(w, r, epicID)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (app *App) getEpics(w http.ResponseWriter, r *http.Request) {
	// Get current user
	user := app.getCurrentUser(r)
	if user == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	
	query := `
		SELECT 
			e.id, e.title, e.description, e.status, e.color, e.owner,
			e.created_at, e.updated_at,
			COUNT(DISTINCT ie.issue_id) as issue_count,
			COUNT(DISTINCT CASE WHEN i.state = 'closed' THEN ie.issue_id END) as closed_issue_count
		FROM epics e
		LEFT JOIN issue_epics ie ON e.id = ie.epic_id
		LEFT JOIN issues i ON ie.issue_id = i.id
		WHERE e.user_id = ?
		GROUP BY e.id
		ORDER BY e.updated_at DESC
	`
	
	rows, err := app.db.Query(query, user.ID)
	if err != nil {
		http.Error(w, "Failed to fetch epics", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	
	type Epic struct {
		ID                int64     `json:"id"`
		Title             string    `json:"title"`
		Description       *string   `json:"description"`
		Status            string    `json:"status"`
		Color             string    `json:"color"`
		Owner             *string   `json:"owner"`
		CreatedAt         time.Time `json:"created_at"`
		UpdatedAt         time.Time `json:"updated_at"`
		IssueCount        int       `json:"issue_count"`
		ClosedIssueCount  int       `json:"closed_issue_count"`
	}
	
	var epics []Epic
	for rows.Next() {
		var epic Epic
		err := rows.Scan(
			&epic.ID, &epic.Title, &epic.Description, &epic.Status,
			&epic.Color, &epic.Owner, &epic.CreatedAt, &epic.UpdatedAt,
			&epic.IssueCount, &epic.ClosedIssueCount,
		)
		if err != nil {
			continue
		}
		
		
		epics = append(epics, epic)
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(epics)
}



// Security helper functions for input validation and sanitization

// sanitizeInput removes dangerous characters and escapes HTML
func sanitizeInput(s string) string {
	// Remove null bytes and control characters
	s = strings.ReplaceAll(s, "\x00", "")
	s = strings.TrimSpace(s)
	// HTML escape to prevent XSS
	return html.EscapeString(s)
}

// isValidHexColor validates hex color format
func isValidHexColor(color string) bool {
	matched, _ := regexp.MatchString(`^#[0-9A-Fa-f]{6}$`, color)
	return matched
}

// isValidEpicStatus validates epic status values
func isValidEpicStatus(status string) bool {
	validStatuses := []string{"active", "completed", "archived"}
	for _, valid := range validStatuses {
		if status == valid {
			return true
		}
	}
	return false
}

// isValidThemeStatus validates theme status values
func isValidThemeStatus(status string) bool {
	validStatuses := []string{"planned", "in_progress", "completed", "cancelled"}
	for _, valid := range validStatuses {
		if status == valid {
			return true
		}
	}
	return false
}

func (app *App) createEpic(w http.ResponseWriter, r *http.Request) {
	// Get current user
	user := app.getCurrentUser(r)
	if user == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	
	// Validate CSRF token
	cookie, _ := r.Cookie("session")
	if cookie != nil {
		csrfToken := r.Header.Get("X-CSRF-Token")
		if csrfToken == "" {
			csrfToken = r.FormValue("csrf_token")
		}
		
		if !app.validateCSRFToken(r, csrfToken) {
			http.Error(w, "Invalid CSRF token", http.StatusForbidden)
			return
		}
	}
	
	var input struct {
		Title       string  `json:"title"`
		Description string  `json:"description"`
		Color       string  `json:"color"`
		Owner       string  `json:"owner"`
		Status      string  `json:"status"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}
	
	// Sanitize and validate input
	input.Title = sanitizeInput(input.Title)
	input.Description = sanitizeInput(input.Description)
	input.Owner = sanitizeInput(input.Owner)
	
	// Validate required fields
	if input.Title == "" {
		http.Error(w, "Title is required", http.StatusBadRequest)
		return
	}
	
	if len(input.Title) > 200 {
		http.Error(w, "Title must be less than 200 characters", http.StatusBadRequest)
		return
	}
	
	if len(input.Description) > 5000 {
		http.Error(w, "Description must be less than 5000 characters", http.StatusBadRequest)
		return
	}
	
	// Set defaults and validate
	if input.Color == "" {
		input.Color = "#3B82F6"
	} else if !isValidHexColor(input.Color) {
		http.Error(w, "Invalid color format", http.StatusBadRequest)
		return
	}
	
	if input.Status == "" {
		input.Status = "active"
	} else if !isValidEpicStatus(input.Status) {
		http.Error(w, "Invalid status value", http.StatusBadRequest)
		return
	}
	
	// Insert epic with user_id
	result, err := app.db.Exec(`
		INSERT INTO epics (user_id, title, description, color, owner, status)
		VALUES (?, ?, ?, ?, ?, ?)
	`, user.ID, input.Title, input.Description, input.Color, input.Owner, input.Status)
	
	if err != nil {
		http.Error(w, "Failed to create epic", http.StatusInternalServerError)
		return
	}
	
	epicID, _ := result.LastInsertId()
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id": epicID,
		"message": "Epic created successfully",
	})
}


func (app *App) getEpic(w http.ResponseWriter, r *http.Request, epicID int64) {
	// Get epic details with associated issues
	var epic struct {
		ID          int64     `json:"id"`
		Title       string    `json:"title"`
		Description *string   `json:"description"`
		Status      string    `json:"status"`
		Color       string    `json:"color"`
		Owner       *string   `json:"owner"`
		CreatedAt   time.Time `json:"created_at"`
		UpdatedAt   time.Time `json:"updated_at"`
	}
	
	var description, owner sql.NullString
	err := app.db.QueryRow(`
		SELECT id, title, description, status, color, owner, created_at, updated_at
		FROM epics WHERE id = ?
	`, epicID).Scan(
		&epic.ID, &epic.Title, &description, &epic.Status, 
		&epic.Color, &owner, &epic.CreatedAt, &epic.UpdatedAt,
	)
	
	if err == sql.ErrNoRows {
		http.Error(w, "Epic not found", http.StatusNotFound)
		return
	} else if err != nil {
		http.Error(w, "Failed to fetch epic", http.StatusInternalServerError)
		return
	}
	
	if description.Valid {
		epic.Description = &description.String
	}
	if owner.Valid {
		epic.Owner = &owner.String
	}
	
	// Get associated issues
	rows, err := app.db.Query(`
		SELECT i.id, i.github_id, i.number, i.title, i.state, i.labels, i.assignee, i.author
		FROM issues i
		JOIN issue_epics ie ON i.id = ie.issue_id
		WHERE ie.epic_id = ?
		ORDER BY i.updated_at DESC
	`, epicID)
	
	if err != nil {
		http.Error(w, "Failed to fetch epic issues", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	
	type Issue struct {
		ID       int64   `json:"id"`
		GitHubID int64   `json:"github_id"`
		Number   int     `json:"number"`
		Title    string  `json:"title"`
		State    string  `json:"state"`
		Labels   string  `json:"labels"`
		Assignee *string `json:"assignee"`
		Author   string  `json:"author"`
	}
	
	var issues []Issue
	for rows.Next() {
		var issue Issue
		var assignee sql.NullString
		
		err := rows.Scan(
			&issue.ID, &issue.GitHubID, &issue.Number, &issue.Title,
			&issue.State, &issue.Labels, &assignee, &issue.Author,
		)
		if err != nil {
			continue
		}
		
		if assignee.Valid {
			issue.Assignee = &assignee.String
		}
		
		issues = append(issues, issue)
	}
	
	response := map[string]interface{}{
		"epic":   epic,
		"issues": issues,
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (app *App) updateEpic(w http.ResponseWriter, r *http.Request, epicID int64) {
	// Get current user
	user := app.getCurrentUser(r)
	if user == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	
	// Validate CSRF token
	csrfToken := r.Header.Get("X-CSRF-Token")
	if csrfToken == "" {
		csrfToken = r.FormValue("csrf_token")
	}
	
	if !app.validateCSRFToken(r, csrfToken) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}
	
	var input struct {
		Title       string  `json:"title"`
		Description string  `json:"description"`
		Color       string  `json:"color"`
		Owner       string  `json:"owner"`
		Status      string  `json:"status"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}
	
	// Sanitize and validate input
	input.Title = sanitizeInput(input.Title)
	input.Description = sanitizeInput(input.Description)
	input.Owner = sanitizeInput(input.Owner)
	
	if input.Title == "" {
		http.Error(w, "Title is required", http.StatusBadRequest)
		return
	}
	
	if len(input.Title) > 200 {
		http.Error(w, "Title must be less than 200 characters", http.StatusBadRequest)
		return
	}
	
	if len(input.Description) > 5000 {
		http.Error(w, "Description must be less than 5000 characters", http.StatusBadRequest)
		return
	}
	
	if input.Color != "" && !isValidHexColor(input.Color) {
		http.Error(w, "Invalid color format", http.StatusBadRequest)
		return
	}
	
	if input.Status != "" && !isValidEpicStatus(input.Status) {
		http.Error(w, "Invalid status value", http.StatusBadRequest)
		return
	}
	
	// Update epic - only if owned by user
	_, err := app.db.Exec(`
		UPDATE epics 
		SET title = ?, description = ?, color = ?, owner = ?, status = ?, updated_at = CURRENT_TIMESTAMP
		WHERE id = ? AND user_id = ?
	`, input.Title, input.Description, input.Color, input.Owner, input.Status, epicID, user.ID)
	
	if err != nil {
		http.Error(w, "Failed to update epic or access denied", http.StatusInternalServerError)
		return
	}
	
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "updated"})
}


func (app *App) deleteEpic(w http.ResponseWriter, r *http.Request, epicID int64) {
	// Get current user
	user := app.getCurrentUser(r)
	if user == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	
	// Validate CSRF token
	csrfToken := r.Header.Get("X-CSRF-Token")
	if csrfToken == "" {
		csrfToken = r.FormValue("csrf_token")
	}
	
	if !app.validateCSRFToken(r, csrfToken) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}
	
	// Delete only if owned by user
	result, err := app.db.Exec(`
		DELETE FROM epics WHERE id = ? AND user_id = ?
	`, epicID, user.ID)
	
	if err != nil {
		http.Error(w, "Failed to delete epic", http.StatusInternalServerError)
		return
	}
	
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		http.Error(w, "Epic not found or access denied", http.StatusNotFound)
		return
	}
	
	w.WriteHeader(http.StatusNoContent)
}


func (app *App) assignIssueToEpic(w http.ResponseWriter, r *http.Request, epicID int64) {
	var input struct {
		IssueID int64 `json:"issue_id"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}
	
	_, err := app.db.Exec(`
		INSERT OR IGNORE INTO issue_epics (issue_id, epic_id) VALUES (?, ?)
	`, input.IssueID, epicID)
	
	if err != nil {
		http.Error(w, "Failed to assign issue to epic", http.StatusInternalServerError)
		return
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Issue assigned to epic",
	})
}

func (app *App) removeIssueFromEpic(w http.ResponseWriter, r *http.Request, epicID int64) {
	issueIDStr := r.URL.Query().Get("issue_id")
	if issueIDStr == "" {
		http.Error(w, "Issue ID required", http.StatusBadRequest)
		return
	}
	
	issueID, err := strconv.ParseInt(issueIDStr, 10, 64)
	if err != nil {
		http.Error(w, "Invalid issue ID", http.StatusBadRequest)
		return
	}
	
	_, err = app.db.Exec(`
		DELETE FROM issue_epics WHERE issue_id = ? AND epic_id = ?
	`, issueID, epicID)
	
	if err != nil {
		http.Error(w, "Failed to remove issue from epic", http.StatusInternalServerError)
		return
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Issue removed from epic",
	})
}

// API: Theme Management
func (app *App) handleAPIThemes(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		app.getThemes(w, r)
	case http.MethodPost:
		app.createTheme(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (app *App) handleAPITheme(w http.ResponseWriter, r *http.Request) {
	// Extract theme ID from path
	path := r.URL.Path
	parts := strings.Split(strings.TrimPrefix(path, "/api/themes/"), "/")
	if len(parts) < 1 || parts[0] == "" {
		http.Error(w, "Theme ID required", http.StatusBadRequest)
		return
	}
	
	themeID, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		http.Error(w, "Invalid theme ID", http.StatusBadRequest)
		return
	}
	
	// Handle epic assignment to theme
	if len(parts) > 1 && parts[1] == "epics" {
		switch r.Method {
		case http.MethodPost:
			app.assignEpicToTheme(w, r, themeID)
		case http.MethodDelete:
			app.removeEpicFromTheme(w, r, themeID)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
		return
	}
	
	switch r.Method {
	case http.MethodGet:
		app.getTheme(w, r, themeID)
	case http.MethodPut:
		app.updateTheme(w, r, themeID)
	case http.MethodDelete:
		app.deleteTheme(w, r, themeID)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (app *App) getThemes(w http.ResponseWriter, r *http.Request) {
	query := `
		SELECT 
			t.id, t.name, t.description, t.quarter, t.status,
			t.created_at, t.updated_at,
			COUNT(DISTINCT et.epic_id) as epic_count
		FROM themes t
		LEFT JOIN epic_themes et ON t.id = et.theme_id
		GROUP BY t.id
		ORDER BY t.quarter DESC, t.updated_at DESC
	`
	
	rows, err := app.db.Query(query)
	if err != nil {
		http.Error(w, "Failed to fetch themes", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	
	type Theme struct {
		ID          int64     `json:"id"`
		Name        string    `json:"name"`
		Description *string   `json:"description"`
		Quarter     *string   `json:"quarter"`
		Status      string    `json:"status"`
		CreatedAt   time.Time `json:"created_at"`
		UpdatedAt   time.Time `json:"updated_at"`
		EpicCount   int       `json:"epic_count"`
	}
	
	var themes []Theme
	for rows.Next() {
		var theme Theme
		var description, quarter sql.NullString
		
		err := rows.Scan(
			&theme.ID, &theme.Name, &description, &quarter, &theme.Status,
			&theme.CreatedAt, &theme.UpdatedAt, &theme.EpicCount,
		)
		if err != nil {
			http.Error(w, "Failed to scan theme", http.StatusInternalServerError)
			return
		}
		
		if description.Valid {
			theme.Description = &description.String
		}
		if quarter.Valid {
			theme.Quarter = &quarter.String
		}
		
		themes = append(themes, theme)
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(themes)
}

func (app *App) createTheme(w http.ResponseWriter, r *http.Request) {
	// Get current user
	user := app.getCurrentUser(r)
	if user == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	
	// Validate CSRF token
	csrfToken := r.Header.Get("X-CSRF-Token")
	if csrfToken == "" {
		csrfToken = r.FormValue("csrf_token")
	}
	
	if !app.validateCSRFToken(r, csrfToken) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}
	
	var input struct {
		Name        string  `json:"name"`
		Description string  `json:"description"`
		Quarter     string  `json:"quarter"`
		Status      string  `json:"status"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}
	
	// Sanitize and validate input
	input.Name = sanitizeInput(input.Name)
	input.Description = sanitizeInput(input.Description)
	input.Quarter = sanitizeInput(input.Quarter)
	
	if input.Name == "" {
		http.Error(w, "Name is required", http.StatusBadRequest)
		return
	}
	
	if len(input.Name) > 200 {
		http.Error(w, "Name must be less than 200 characters", http.StatusBadRequest)
		return
	}
	
	if len(input.Description) > 5000 {
		http.Error(w, "Description must be less than 5000 characters", http.StatusBadRequest)
		return
	}
	
	if input.Status == "" {
		input.Status = "planned"
	} else if !isValidThemeStatus(input.Status) {
		http.Error(w, "Invalid status value", http.StatusBadRequest)
		return
	}
	
	// Insert theme with user_id
	result, err := app.db.Exec(`
		INSERT INTO themes (user_id, name, description, quarter, status)
		VALUES (?, ?, ?, ?, ?)
	`, user.ID, input.Name, input.Description, input.Quarter, input.Status)
	
	if err != nil {
		http.Error(w, "Failed to create theme", http.StatusInternalServerError)
		return
	}
	
	themeID, _ := result.LastInsertId()
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id": themeID,
		"message": "Theme created successfully",
	})
}


func (app *App) getTheme(w http.ResponseWriter, r *http.Request, themeID int64) {
	// Get theme details with associated epics
	var theme struct {
		ID          int64     `json:"id"`
		Name        string    `json:"name"`
		Description *string   `json:"description"`
		Quarter     *string   `json:"quarter"`
		Status      string    `json:"status"`
		CreatedAt   time.Time `json:"created_at"`
		UpdatedAt   time.Time `json:"updated_at"`
	}
	
	var description, quarter sql.NullString
	err := app.db.QueryRow(`
		SELECT id, name, description, quarter, status, created_at, updated_at
		FROM themes WHERE id = ?
	`, themeID).Scan(
		&theme.ID, &theme.Name, &description, &quarter,
		&theme.Status, &theme.CreatedAt, &theme.UpdatedAt,
	)
	
	if err == sql.ErrNoRows {
		http.Error(w, "Theme not found", http.StatusNotFound)
		return
	} else if err != nil {
		http.Error(w, "Failed to fetch theme", http.StatusInternalServerError)
		return
	}
	
	if description.Valid {
		theme.Description = &description.String
	}
	if quarter.Valid {
		theme.Quarter = &quarter.String
	}
	
	// Get associated epics
	rows, err := app.db.Query(`
		SELECT e.id, e.title, e.description, e.status, e.color, e.owner
		FROM epics e
		JOIN epic_themes et ON e.id = et.epic_id
		WHERE et.theme_id = ?
		ORDER BY e.updated_at DESC
	`, themeID)
	
	if err != nil {
		http.Error(w, "Failed to fetch theme epics", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	
	type Epic struct {
		ID          int64   `json:"id"`
		Title       string  `json:"title"`
		Description *string `json:"description"`
		Status      string  `json:"status"`
		Color       string  `json:"color"`
		Owner       *string `json:"owner"`
	}
	
	var epics []Epic
	for rows.Next() {
		var epic Epic
		var epicDesc, epicOwner sql.NullString
		
		err := rows.Scan(
			&epic.ID, &epic.Title, &epicDesc, &epic.Status,
			&epic.Color, &epicOwner,
		)
		if err != nil {
			continue
		}
		
		if epicDesc.Valid {
			epic.Description = &epicDesc.String
		}
		if epicOwner.Valid {
			epic.Owner = &epicOwner.String
		}
		
		epics = append(epics, epic)
	}
	
	response := map[string]interface{}{
		"theme": theme,
		"epics": epics,
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (app *App) updateTheme(w http.ResponseWriter, r *http.Request, themeID int64) {
	var input struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Quarter     string `json:"quarter"`
		Status      string `json:"status"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}
	
	_, err := app.db.Exec(`
		UPDATE themes 
		SET name = ?, description = ?, quarter = ?, status = ?, updated_at = CURRENT_TIMESTAMP
		WHERE id = ?
	`, input.Name, input.Description, input.Quarter, input.Status, themeID)
	
	if err != nil {
		http.Error(w, "Failed to update theme", http.StatusInternalServerError)
		return
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Theme updated successfully",
	})
}

func (app *App) deleteTheme(w http.ResponseWriter, r *http.Request, themeID int64) {
	// Get current user
	user := app.getCurrentUser(r)
	if user == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	
	// Validate CSRF token
	csrfToken := r.Header.Get("X-CSRF-Token")
	if csrfToken == "" {
		csrfToken = r.FormValue("csrf_token")
	}
	
	if !app.validateCSRFToken(r, csrfToken) {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}
	
	// Delete only if owned by user
	result, err := app.db.Exec(`
		DELETE FROM themes WHERE id = ? AND user_id = ?
	`, themeID, user.ID)
	
	if err != nil {
		http.Error(w, "Failed to delete theme", http.StatusInternalServerError)
		return
	}
	
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		http.Error(w, "Theme not found or access denied", http.StatusNotFound)
		return
	}
	
	w.WriteHeader(http.StatusNoContent)
}


func (app *App) assignEpicToTheme(w http.ResponseWriter, r *http.Request, themeID int64) {
	var input struct {
		EpicID int64 `json:"epic_id"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}
	
	_, err := app.db.Exec(`
		INSERT OR IGNORE INTO epic_themes (epic_id, theme_id) VALUES (?, ?)
	`, input.EpicID, themeID)
	
	if err != nil {
		http.Error(w, "Failed to assign epic to theme", http.StatusInternalServerError)
		return
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Epic assigned to theme",
	})
}

func (app *App) removeEpicFromTheme(w http.ResponseWriter, r *http.Request, themeID int64) {
	epicIDStr := r.URL.Query().Get("epic_id")
	if epicIDStr == "" {
		http.Error(w, "Epic ID required", http.StatusBadRequest)
		return
	}
	
	epicID, err := strconv.ParseInt(epicIDStr, 10, 64)
	if err != nil {
		http.Error(w, "Invalid epic ID", http.StatusBadRequest)
		return
	}
	
	_, err = app.db.Exec(`
		DELETE FROM epic_themes WHERE epic_id = ? AND theme_id = ?
	`, epicID, themeID)
	
	if err != nil {
		http.Error(w, "Failed to remove epic from theme", http.StatusInternalServerError)
		return
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Epic removed from theme",
	})
}

// API: Reports
func (app *App) handleAPIReports(w http.ResponseWriter, r *http.Request) {
	reportType := r.URL.Query().Get("type")
	
	switch reportType {
	case "summary":
		app.getReportSummary(w, r)
	case "burndown":
		app.getBurndownData(w, r)
	case "velocity":
		app.getVelocityData(w, r)
	default:
		app.getReportSummary(w, r)
	}
}

func (app *App) getReportSummary(w http.ResponseWriter, r *http.Request) {
	// Get overall statistics
	type Summary struct {
		TotalIssues      int     `json:"total_issues"`
		OpenIssues       int     `json:"open_issues"`
		ClosedIssues     int     `json:"closed_issues"`
		TotalEpics       int     `json:"total_epics"`
		ActiveEpics      int     `json:"active_epics"`
		CompletedEpics   int     `json:"completed_epics"`
		TotalThemes      int     `json:"total_themes"`
		CurrentQuarter   string  `json:"current_quarter"`
		OverallProgress  float64 `json:"overall_progress"`
	}
	
	var summary Summary
	
	// Get issue counts
	app.db.QueryRow("SELECT COUNT(*) FROM issues").Scan(&summary.TotalIssues)
	app.db.QueryRow("SELECT COUNT(*) FROM issues WHERE state = 'open'").Scan(&summary.OpenIssues)
	app.db.QueryRow("SELECT COUNT(*) FROM issues WHERE state = 'closed'").Scan(&summary.ClosedIssues)
	
	// Get epic counts
	app.db.QueryRow("SELECT COUNT(*) FROM epics").Scan(&summary.TotalEpics)
	app.db.QueryRow("SELECT COUNT(*) FROM epics WHERE status = 'active'").Scan(&summary.ActiveEpics)
	app.db.QueryRow("SELECT COUNT(*) FROM epics WHERE status = 'completed'").Scan(&summary.CompletedEpics)
	
	// Get theme count
	app.db.QueryRow("SELECT COUNT(*) FROM themes").Scan(&summary.TotalThemes)
	
	// Calculate current quarter
	now := time.Now()
	quarter := (now.Month()-1)/3 + 1
	summary.CurrentQuarter = fmt.Sprintf("%d-Q%d", now.Year(), quarter)
	
	// Calculate overall progress
	if summary.TotalIssues > 0 {
		summary.OverallProgress = float64(summary.ClosedIssues) / float64(summary.TotalIssues) * 100
	}
	
	// Get top epics by progress
	epicRows, err := app.db.Query(`
		SELECT 
			e.id, e.title, e.status,
			COUNT(DISTINCT ie.issue_id) as total_issues,
			COUNT(DISTINCT CASE WHEN i.state = 'closed' THEN ie.issue_id END) as closed_issues
		FROM epics e
		LEFT JOIN issue_epics ie ON e.id = ie.epic_id
		LEFT JOIN issues i ON ie.issue_id = i.id
		WHERE e.status = 'active'
		GROUP BY e.id
		HAVING total_issues > 0
		ORDER BY (closed_issues * 100.0 / total_issues) DESC
		LIMIT 5
	`)
	
	type EpicProgress struct {
		ID           int64   `json:"id"`
		Title        string  `json:"title"`
		TotalIssues  int     `json:"total_issues"`
		ClosedIssues int     `json:"closed_issues"`
		Progress     float64 `json:"progress"`
	}
	
	var topEpics []EpicProgress
	if err == nil {
		defer epicRows.Close()
		for epicRows.Next() {
			var epic EpicProgress
			var status string
			epicRows.Scan(&epic.ID, &epic.Title, &status, &epic.TotalIssues, &epic.ClosedIssues)
			if epic.TotalIssues > 0 {
				epic.Progress = float64(epic.ClosedIssues) / float64(epic.TotalIssues) * 100
			}
			topEpics = append(topEpics, epic)
		}
	}
	
	response := map[string]interface{}{
		"summary":    summary,
		"top_epics":  topEpics,
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (app *App) getBurndownData(w http.ResponseWriter, r *http.Request) {
	// Get issues closed over time for the last 30 days
	thirtyDaysAgo := time.Now().AddDate(0, 0, -30)
	
	rows, err := app.db.Query(`
		SELECT 
			DATE(closed_at) as close_date,
			COUNT(*) as issues_closed
		FROM issues
		WHERE closed_at IS NOT NULL 
		AND closed_at >= ?
		GROUP BY DATE(closed_at)
		ORDER BY close_date
	`, thirtyDaysAgo)
	
	if err != nil {
		http.Error(w, "Failed to fetch burndown data", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	
	type DailyCount struct {
		Date   string `json:"date"`
		Closed int    `json:"closed"`
	}
	
	var data []DailyCount
	for rows.Next() {
		var count DailyCount
		rows.Scan(&count.Date, &count.Closed)
		data = append(data, count)
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func (app *App) getVelocityData(w http.ResponseWriter, r *http.Request) {
	// Get weekly velocity for the last 12 weeks
	twelveWeeksAgo := time.Now().AddDate(0, 0, -84)
	
	rows, err := app.db.Query(`
		SELECT 
			strftime('%Y-%W', closed_at) as week,
			COUNT(*) as issues_closed
		FROM issues
		WHERE closed_at IS NOT NULL 
		AND closed_at >= ?
		GROUP BY strftime('%Y-%W', closed_at)
		ORDER BY week
	`, twelveWeeksAgo)
	
	if err != nil {
		http.Error(w, "Failed to fetch velocity data", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	
	type WeeklyVelocity struct {
		Week   string `json:"week"`
		Closed int    `json:"closed"`
	}
	
	var data []WeeklyVelocity
	for rows.Next() {
		var velocity WeeklyVelocity
		rows.Scan(&velocity.Week, &velocity.Closed)
		data = append(data, velocity)
	}
	
	// Calculate average velocity
	var totalClosed int
	for _, v := range data {
		totalClosed += v.Closed
	}
	
	avgVelocity := 0.0
	if len(data) > 0 {
		avgVelocity = float64(totalClosed) / float64(len(data))
	}
	
	response := map[string]interface{}{
		"weekly_data": data,
		"average_velocity": avgVelocity,
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
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
		github_id INTEGER UNIQUE,
		owner TEXT NOT NULL,
		name TEXT NOT NULL,
		full_name TEXT UNIQUE,
		description TEXT,
		default_branch TEXT,
		private BOOLEAN DEFAULT 0,
		stargazers_count INTEGER DEFAULT 0,
		open_issues_count INTEGER DEFAULT 0,
		created_at DATETIME,
		updated_at DATETIME,
		synced_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(owner, name)
	);

	CREATE INDEX IF NOT EXISTS idx_issues_state ON issues(state);
	CREATE INDEX IF NOT EXISTS idx_issues_number ON issues(number);
	CREATE INDEX IF NOT EXISTS idx_issues_updated ON issues(updated_at);
	CREATE INDEX IF NOT EXISTS idx_issues_created ON issues(created_at);

	CREATE TABLE IF NOT EXISTS sync_status (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		repo_owner TEXT NOT NULL,
		repo_name TEXT NOT NULL,
		last_sync_at DATETIME,
		sync_in_progress BOOLEAN DEFAULT 0,
		issues_synced INTEGER DEFAULT 0,
		error TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(repo_owner, repo_name)
	);

	CREATE TABLE IF NOT EXISTS webhook_events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		event_type TEXT NOT NULL,
		action TEXT,
		signature TEXT,
		payload TEXT NOT NULL,
		processed BOOLEAN DEFAULT 0,
		error TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE INDEX IF NOT EXISTS idx_webhook_events_created ON webhook_events(created_at);
	CREATE INDEX IF NOT EXISTS idx_webhook_events_processed ON webhook_events(processed);
	CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

	CREATE TABLE IF NOT EXISTS csrf_tokens (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		session_id TEXT NOT NULL,
		token TEXT NOT NULL,
		expires_at DATETIME NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(session_id, token)
	);

	CREATE INDEX IF NOT EXISTS idx_csrf_expires ON csrf_tokens(expires_at);

	-- Epic and Theme tables for product features
	CREATE TABLE IF NOT EXISTS epics (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL DEFAULT 1,
		title TEXT NOT NULL,
		description TEXT,
		status TEXT DEFAULT 'active' CHECK (status IN ('active', 'completed', 'archived')),
		color TEXT DEFAULT '#3B82F6',
		owner TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS issue_epics (
		issue_id INTEGER NOT NULL,
		epic_id INTEGER NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		PRIMARY KEY (issue_id, epic_id),
		FOREIGN KEY (issue_id) REFERENCES issues(id) ON DELETE CASCADE,
		FOREIGN KEY (epic_id) REFERENCES epics(id) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS themes (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL DEFAULT 1,
		name TEXT NOT NULL,
		description TEXT,
		quarter TEXT,
		status TEXT DEFAULT 'planned' CHECK (status IN ('planned', 'in_progress', 'completed', 'cancelled')),
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS epic_themes (
		epic_id INTEGER NOT NULL,
		theme_id INTEGER NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		PRIMARY KEY (epic_id, theme_id),
		FOREIGN KEY (epic_id) REFERENCES epics(id) ON DELETE CASCADE,
		FOREIGN KEY (theme_id) REFERENCES themes(id) ON DELETE CASCADE
	);

	-- Indexes for performance
	CREATE INDEX IF NOT EXISTS idx_epics_status ON epics(status);
	CREATE INDEX IF NOT EXISTS idx_epics_owner ON epics(owner);
	CREATE INDEX IF NOT EXISTS idx_themes_quarter ON themes(quarter);
	CREATE INDEX IF NOT EXISTS idx_themes_status ON themes(status);
	`

	if _, err := db.Exec(schema); err != nil {
		log.Fatal(err)
	}

	log.Println("Database migrations completed")
}