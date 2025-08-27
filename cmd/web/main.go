package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
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
	tmpl        *template.Template
	config      Config
	rateLimiter *RateLimiter
}

// RateLimiter implements a simple in-memory rate limiter
type RateLimiter struct {
	attempts map[string][]time.Time
	mu       sync.RWMutex
}

func NewRateLimiter() *RateLimiter {
	return &RateLimiter{
		attempts: make(map[string][]time.Time),
	}
}

func (rl *RateLimiter) Allow(key string, limit int, window time.Duration) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	
	now := time.Now()
	cutoff := now.Add(-window)
	
	// Clean old attempts
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
	GitHubRepoName     string
	Environment        string
}

type User struct {
	ID          int64
	Email       string
	GitHubID    int
	GitHubLogin string
	Name        string
	AvatarURL   string
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
		GitHubRepoOwner:    mustGetEnv("GITHUB_REPO_OWNER"),
		GitHubRepoName:     mustGetEnv("GITHUB_REPO_NAME"),
		Environment:        getEnv("ENVIRONMENT", "development"),
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

	// Parse templates
	tmpl := template.Must(template.New("").ParseFS(templateFS, "templates/*.html"))

	app := &App{
		db:          db,
		tmpl:        tmpl,
		config:      config,
		rateLimiter: NewRateLimiter(),
	}

	// Setup routes
	mux := http.NewServeMux()
	mux.HandleFunc("/", app.handleHome)
	mux.HandleFunc("/login", app.handleLogin)
	mux.HandleFunc("/logout", app.handleLogout)
	mux.HandleFunc("/auth/callback", app.handleCallback)
	mux.HandleFunc("/dashboard", app.requireAuth(app.handleDashboard))
	mux.HandleFunc("/sync", app.requireAuth(app.handleSync))

	// Wrap with security headers middleware
	handler := app.securityHeaders(mux)

	// Start background cleanup tasks
	go app.cleanupExpiredSessions()

	// Start server
	log.Printf("Starting server on http://localhost:%s", config.Port)
	log.Fatal(http.ListenAndServe(":"+config.Port, handler))
}

func (app *App) handleHome(w http.ResponseWriter, r *http.Request) {
	user := app.getCurrentUser(r)
	
	if user != nil {
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}

	data := map[string]interface{}{
		"User": user,
	}

	if err := app.tmpl.ExecuteTemplate(w, "home.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
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
	
	row := app.db.QueryRow(`
		SELECT 
			COUNT(*) as total,
			COUNT(CASE WHEN state = 'open' THEN 1 END) as open,
			COUNT(CASE WHEN state = 'closed' THEN 1 END) as closed
		FROM issues
	`)
	row.Scan(&stats.TotalIssues, &stats.OpenIssues, &stats.ClosedIssues)

	data := map[string]interface{}{
		"User":      user,
		"Stats":     stats,
		"RepoOwner": app.config.GitHubRepoOwner,
		"RepoName":  app.config.GitHubRepoName,
		"CSRFToken": csrfToken,
	}

	if err := app.tmpl.ExecuteTemplate(w, "dashboard.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
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
	state := generateRandomString(32)

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
	log.Printf("OAuth Login: Redirecting to GitHub: %s", url)
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
	log.Printf("OAuth Callback: URL=%s", r.URL.String())
	log.Printf("OAuth Callback: Query params: code=%s, state=%s", r.URL.Query().Get("code"), r.URL.Query().Get("state"))
	
	// Verify state for CSRF protection
	stateCookie, err := r.Cookie("oauth_state")
	if err != nil || stateCookie.Value != r.URL.Query().Get("state") {
		log.Printf("OAuth state mismatch: cookie=%v, param=%v", stateCookie, r.URL.Query().Get("state"))
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
	log.Printf("OAuth: Successfully exchanged code for token")

	// Get user info from GitHub API
	client := config.Client(context.Background(), token)
	resp, err := client.Get("https://api.github.com/user")
	if err != nil {
		log.Printf("OAuth ERROR: Failed to get user info: %v", err)
		http.Error(w, "Failed to get user info", http.StatusInternalServerError)
		return
	}
	log.Printf("OAuth: Successfully fetched user info from GitHub")
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
	log.Printf("OAuth: Saving user to database - ID=%d, Login=%s, Email=%s", githubUser.ID, githubUser.Login, githubUser.Email)
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
	log.Printf("OAuth: User saved successfully")

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

	log.Printf("OAuth: Login successful for user %s, redirecting to /dashboard", githubUser.Login)
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
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

	// Get user's encrypted access token
	var encryptedToken string
	err := app.db.QueryRow("SELECT access_token FROM users WHERE id = ?", user.ID).Scan(&encryptedToken)
	if err != nil {
		w.Write([]byte(`<div class="text-red-600">Failed to get access token</div>`))
		return
	}

	// Decrypt the access token
	accessToken, err := app.decryptToken(encryptedToken)
	if err != nil {
		w.Write([]byte(`<div class="text-red-600">Failed to decrypt access token</div>`))
		return
	}

	// Sync issues from GitHub
	go app.syncIssues(accessToken)

	w.Write([]byte(`<div class="text-green-600">Sync started! Refresh the page in a few seconds to see updated data.</div>`))
}

func (app *App) syncIssues(accessToken string) {
	// Create OAuth2 client
	ctx := context.Background()
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: accessToken})
	client := oauth2.NewClient(ctx, ts)

	// Fetch issues from GitHub
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/issues?state=all&per_page=100",
		app.config.GitHubRepoOwner, app.config.GitHubRepoName)

	resp, err := client.Get(url)
	if err != nil {
		log.Printf("Failed to fetch issues: %v", err)
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
	}

	if err := json.NewDecoder(resp.Body).Decode(&issues); err != nil {
		log.Printf("Failed to parse issues: %v", err)
		return
	}

	// Save issues to database
	for _, issue := range issues {
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
		}
	}

	log.Printf("Synced %d issues", len(issues))
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

func generateRandomString(length int) string {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("Failed to generate random string: %v", err))
	}
	return hex.EncodeToString(b)
}

// encryptToken encrypts a token using AES-256-GCM
func (app *App) encryptToken(plaintext string) (string, error) {
	// Derive key from session secret
	key := sha256.Sum256([]byte(app.config.SessionSecret))
	
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

	key := sha256.Sum256([]byte(app.config.SessionSecret))
	
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
	token := generateRandomString(32)
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

// securityHeaders adds security headers to all responses
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
			"frame-ancestors 'none'"
		
		// Only upgrade to HTTPS in production
		if app.config.Environment == "production" {
			csp += "; upgrade-insecure-requests"
		}
		w.Header().Set("Content-Security-Policy", csp)
		
		// Strict Transport Security (only in production)
		if app.config.Environment == "production" {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
		}
		
		// Add request ID for tracing
		requestID := r.Header.Get("X-Request-ID")
		if requestID == "" {
			requestID = generateRandomString(16)
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

	CREATE TABLE IF NOT EXISTS csrf_tokens (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		session_id TEXT NOT NULL,
		token TEXT NOT NULL,
		expires_at DATETIME NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(session_id, token)
	);

	CREATE INDEX IF NOT EXISTS idx_csrf_expires ON csrf_tokens(expires_at);
	`

	if _, err := db.Exec(schema); err != nil {
		log.Fatal(err)
	}

	log.Println("Database migrations completed")
}