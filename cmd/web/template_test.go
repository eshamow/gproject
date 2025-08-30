package main

import (
	"bytes"
	"html/template"
	"strings"
	"testing"
)

// TestTemplateIsolation verifies that dashboard and issues templates
// don't interfere with each other due to shared block names
func TestTemplateIsolation(t *testing.T) {
	// Initialize templates the same way the app does
	templates := make(map[string]*template.Template)
	pages := []string{"home.html", "dashboard.html", "issues.html"}

	for _, page := range pages {
		tmpl, err := template.ParseFS(templateFS, "templates/base.html", "templates/"+page)
		if err != nil {
			t.Fatalf("Failed to parse %s: %v", page, err)
		}
		templates[page] = tmpl
	}

	// Test data
	data := map[string]interface{}{
		"User": map[string]interface{}{
			"GitHubLogin": "testuser",
			"AvatarURL":   "https://example.com/avatar",
			"Name":        "Test User",
		},
		"Stats": map[string]interface{}{
			"TotalIssues":  10,
			"OpenIssues":   5,
			"ClosedIssues": 5,
		},
		"RepoOwner": "owner",
		"RepoName":  "repo",
		"CSRFToken": "test-token",
	}

	tests := []struct {
		name          string
		template      string
		expectedTitle string
	}{
		{"Home page", "home.html", "GProject - Home"},
		{"Dashboard page", "dashboard.html", "GProject - Dashboard"},
		{"Issues page", "issues.html", "GProject - Issues"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			err := templates[tt.template].ExecuteTemplate(&buf, "base.html", data)
			if err != nil {
				t.Fatalf("Failed to execute %s: %v", tt.template, err)
			}

			output := buf.String()
			expectedTag := "<title>" + tt.expectedTitle + "</title>"
			if !strings.Contains(output, expectedTag) {
				// Find what title is actually rendered
				start := strings.Index(output, "<title>")
				end := strings.Index(output, "</title>")
				actualTitle := ""
				if start >= 0 && end > start {
					actualTitle = output[start : end+8]
				}
				t.Errorf("Template %s: expected title tag %q, got %q",
					tt.template, expectedTag, actualTitle)
			}
		})
	}
}
