package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/joho/godotenv"
	_ "modernc.org/sqlite"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

//go:embed templates/*.html
var templateFS embed.FS

type App struct {
	db     *sql.DB
	tmpl   *template.Template
	config Config
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
		db:     db,
		tmpl:   tmpl,
		config: config,
	}

	// Setup routes
	mux := http.NewServeMux()
	mux.HandleFunc("/", app.handleHome)
	mux.HandleFunc("/login", app.handleLogin)
	mux.HandleFunc("/logout", app.handleLogout)
	mux.HandleFunc("/auth/callback", app.handleCallback)
	mux.HandleFunc("/dashboard", app.requireAuth(app.handleDashboard))
	mux.HandleFunc("/sync", app.requireAuth(app.handleSync))

	// Start server
	log.Printf("Starting server on http://localhost:%s", config.Port)
	log.Fatal(http.ListenAndServe(":"+config.Port, mux))
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
	}

	if err := app.tmpl.ExecuteTemplate(w, "dashboard.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
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

	// Default email if still empty
	if githubUser.Email == "" {
		githubUser.Email = fmt.Sprintf("%s@users.noreply.github.com", githubUser.Login)
	}

	// Create or update user in database
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

	// Get user's access token
	var accessToken string
	err := app.db.QueryRow("SELECT access_token FROM users WHERE id = ?", user.ID).Scan(&accessToken)
	if err != nil {
		w.Write([]byte(`<div class="text-red-600">Failed to get access token</div>`))
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
	rand.Read(b)
	return hex.EncodeToString(b)
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

	log.Println("Database migrations completed")
}