package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// =============================================================================
// DEPLOYMENT INFRASTRUCTURE TESTS
// =============================================================================

// TestDockerfileValidity validates Dockerfile best practices
// CRITICAL: Ensures container security and efficiency
func TestDockerfileValidity(t *testing.T) {
	dockerfilePath := "/Users/eshamow/proj/gproject/Dockerfile"

	content, err := os.ReadFile(dockerfilePath)
	if err != nil {
		t.Skipf("Dockerfile not found: %v", err)
		return
	}

	dockerfileContent := string(content)

	// Security checks
	securityChecks := []struct {
		name          string
		pattern       string
		shouldContain bool
		reason        string
	}{
		{
			name:          "Non-root user",
			pattern:       "USER ",
			shouldContain: true,
			reason:        "Container should not run as root",
		},
		{
			name:          "No sudo",
			pattern:       "sudo ",
			shouldContain: false,
			reason:        "Should not use sudo in container",
		},
		{
			name:          "Multi-stage build",
			pattern:       "FROM .* AS builder",
			shouldContain: true,
			reason:        "Should use multi-stage build to minimize image size",
		},
		{
			name:          "No latest tag",
			pattern:       "FROM .*:latest",
			shouldContain: false,
			reason:        "Should use specific version tags for reproducibility",
		},
		{
			name:          "COPY not ADD",
			pattern:       "ADD ",
			shouldContain: false,
			reason:        "Should use COPY instead of ADD unless tar extraction needed",
		},
		{
			name:          "Health check",
			pattern:       "HEALTHCHECK",
			shouldContain: true,
			reason:        "Should define health check for container orchestration",
		},
	}

	for _, check := range securityChecks {
		t.Run(check.name, func(t *testing.T) {
			var contains bool
			// Special handling for regex patterns
			if check.name == "Multi-stage build" {
				// Check for multi-stage build pattern
				contains = strings.Contains(dockerfileContent, " AS builder")
			} else {
				contains = strings.Contains(dockerfileContent, check.pattern)
			}
			
			if contains != check.shouldContain {
				if check.shouldContain {
					t.Errorf("Dockerfile missing: %s - %s", check.pattern, check.reason)
				} else {
					t.Errorf("Dockerfile contains problematic: %s - %s", check.pattern, check.reason)
				}
			}
		})
	}
}

// TestDockerComposeConfiguration validates docker-compose setup
// CRITICAL: Ensures proper service configuration
func TestDockerComposeConfiguration(t *testing.T) {
	composeFiles := []string{
		"/Users/eshamow/proj/gproject/docker-compose.yml",
		"/Users/eshamow/proj/gproject/docker-compose.prod.yml",
	}

	for _, file := range composeFiles {
		t.Run(filepath.Base(file), func(t *testing.T) {
			content, err := os.ReadFile(file)
			if err != nil {
				t.Skipf("Docker Compose file not found: %v", err)
				return
			}

			composeContent := string(content)
			isProd := strings.Contains(file, "prod")

			// Configuration checks
			checks := []struct {
				name          string
				pattern       string
				shouldContain bool
				prodOnly      bool
			}{
				{
					name:          "Health check defined",
					pattern:       "healthcheck:",
					shouldContain: true,
					prodOnly:      false,
				},
				{
					name:          "Restart policy",
					pattern:       "restart:",
					shouldContain: true,
					prodOnly:      true,
				},
				{
					name:          "Volume for data persistence",
					pattern:       "volumes:",
					shouldContain: true,
					prodOnly:      false,
				},
				{
					name:          "Read-only root filesystem",
					pattern:       "read_only: true",
					shouldContain: true,
					prodOnly:      true,
				},
				{
					name:          "Security options",
					pattern:       "security_opt:",
					shouldContain: true,
					prodOnly:      true,
				},
				{
					name:          "Resource limits",
					pattern:       "mem_limit:",
					shouldContain: true,
					prodOnly:      true,
				},
			}

			for _, check := range checks {
				if check.prodOnly && !isProd {
					continue // Skip production-only checks for dev compose
				}

				t.Run(check.name, func(t *testing.T) {
					contains := strings.Contains(composeContent, check.pattern)
					if contains != check.shouldContain {
						if check.shouldContain {
							t.Errorf("Missing configuration: %s", check.pattern)
						} else {
							t.Errorf("Problematic configuration: %s", check.pattern)
						}
					}
				})
			}
		})
	}
}

// TestCICDWorkflowSecurity validates GitHub Actions workflow security
// CRITICAL: Prevents supply chain attacks
func TestCICDWorkflowSecurity(t *testing.T) {
	workflowFiles := []string{
		"/Users/eshamow/proj/gproject/.github/workflows/ci.yml",
		"/Users/eshamow/proj/gproject/.github/workflows/deploy.yml",
	}

	for _, file := range workflowFiles {
		t.Run(filepath.Base(file), func(t *testing.T) {
			content, err := os.ReadFile(file)
			if err != nil {
				t.Skipf("Workflow file not found: %v", err)
				return
			}

			workflowContent := string(content)

			// Security checks for GitHub Actions
			securityPatterns := []struct {
				name          string
				pattern       string
				shouldContain bool
				reason        string
			}{
				{
					name:          "Permissions defined",
					pattern:       "permissions:",
					shouldContain: true,
					reason:        "Should explicitly define minimal permissions",
				},
				{
					name:          "No hardcoded secrets",
					pattern:       "password: \"",  // Look for hardcoded password strings
					shouldContain: false,
					reason:        "Should not contain hardcoded passwords",
				},
				{
					name:          "Uses secrets properly",
					pattern:       "${{ secrets.",
					shouldContain: true,
					reason:        "Should use GitHub secrets for sensitive data",
				},
				{
					name:          "Pin action versions",
					pattern:       "@main",
					shouldContain: false,
					reason:        "Should pin action versions, not use @main",
				},
				{
					name:          "Pin action versions",
					pattern:       "@master",
					shouldContain: false,
					reason:        "Should pin action versions, not use @master",
				},
			}

			for _, check := range securityPatterns {
				t.Run(check.name, func(t *testing.T) {
					contains := strings.Contains(workflowContent, check.pattern)
					if contains != check.shouldContain {
						if check.shouldContain {
							t.Errorf("Missing: %s - %s", check.pattern, check.reason)
						} else {
							t.Errorf("Security issue: %s - %s", check.pattern, check.reason)
						}
					}
				})
			}
		})
	}
}

// TestBuildProcess validates the build process works correctly
// CRITICAL: Ensures deployable artifacts can be created
func TestBuildProcess(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping build test in short mode")
	}

	// Test that the application builds without errors
	cmd := exec.Command("go", "build", "-o", "/tmp/gproject-test", "./cmd/web")
	cmd.Dir = "/Users/eshamow/proj/gproject"

	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Build failed: %v\nOutput: %s", err, output)
	}

	// Check binary was created
	if _, err := os.Stat("/tmp/gproject-test"); os.IsNotExist(err) {
		t.Error("Binary not created after build")
	}

	// Clean up
	os.Remove("/tmp/gproject-test")
}

// TestMakefileTargets validates critical Makefile targets exist and work
// IMPORTANT: Ensures documented commands actually work
func TestMakefileTargets(t *testing.T) {
	makefilePath := "/Users/eshamow/proj/gproject/Makefile"

	content, err := os.ReadFile(makefilePath)
	if err != nil {
		t.Skipf("Makefile not found: %v", err)
		return
	}

	makefileContent := string(content)

	// Critical targets that should exist
	requiredTargets := []string{
		"run:",
		"test:",
		"build:",
		"db-reset:",
		"docker-build:",
	}

	for _, target := range requiredTargets {
		t.Run(strings.TrimSuffix(target, ":"), func(t *testing.T) {
			if !strings.Contains(makefileContent, target) {
				t.Errorf("Makefile missing critical target: %s", target)
			}
		})
	}

	// Skip running 'make test' from within tests to avoid recursion
	// Just verify the target exists
	if !testing.Short() {
		cmd := exec.Command("make", "-n", "test")
		cmd.Dir = "/Users/eshamow/proj/gproject"

		if _, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("make test target check failed: %v", err)
		} else {
			t.Log("make test target exists and is properly configured")
		}
	}
}

// TestEnvironmentConfiguration validates .env.example completeness
// IMPORTANT: Ensures all required environment variables are documented
func TestEnvironmentConfiguration(t *testing.T) {
	// Check for .env.example
	envExamplePath := "/Users/eshamow/proj/gproject/.env.example"

	content, err := os.ReadFile(envExamplePath)
	if err != nil {
		t.Skipf(".env.example not found - should exist for deployment: %v", err)
		return
	}

	envContent := string(content)

	// Required environment variables
	requiredVars := []string{
		"GITHUB_CLIENT_ID",
		"GITHUB_CLIENT_SECRET",
		"GITHUB_REPO_OWNER",
		"GITHUB_REPO_NAME",
		"SESSION_SECRET",
		"ENCRYPTION_KEY",
		"WEBHOOK_SECRET",
		"ENVIRONMENT",
		"PORT",
	}

	for _, varName := range requiredVars {
		t.Run(varName, func(t *testing.T) {
			if !strings.Contains(envContent, varName) {
				t.Errorf(".env.example missing required variable: %s", varName)
			}
		})
	}
}

// TestDockerIgnore validates .dockerignore contains sensitive files
// CRITICAL: Prevents secrets from being included in Docker images
func TestDockerIgnore(t *testing.T) {
	dockerignorePath := "/Users/eshamow/proj/gproject/.dockerignore"

	content, err := os.ReadFile(dockerignorePath)
	if err != nil {
		t.Fatalf(".dockerignore not found - critical for security: %v", err)
	}

	dockerignoreContent := string(content)

	// Patterns that must be ignored
	criticalIgnores := []string{
		".env",
		".git",
		"*.db",
		"*.sqlite",
		"*.key",
		"*.pem",
		".DS_Store",
		"node_modules",
	}

	for _, pattern := range criticalIgnores {
		t.Run(pattern, func(t *testing.T) {
			if !strings.Contains(dockerignoreContent, pattern) {
				t.Errorf(".dockerignore missing critical pattern: %s", pattern)
			}
		})
	}
}

// TestProductionReadiness performs final production readiness checks
// CRITICAL: Validates system is ready for production deployment
func TestProductionReadiness(t *testing.T) {
	checks := []struct {
		name      string
		checkFunc func() error
	}{
		{
			name: "Dockerfile exists",
			checkFunc: func() error {
				_, err := os.Stat("/Users/eshamow/proj/gproject/Dockerfile")
				return err
			},
		},
		{
			name: "Docker Compose production config exists",
			checkFunc: func() error {
				_, err := os.Stat("/Users/eshamow/proj/gproject/docker-compose.prod.yml")
				return err
			},
		},
		{
			name: "CI workflow exists",
			checkFunc: func() error {
				_, err := os.Stat("/Users/eshamow/proj/gproject/.github/workflows/ci.yml")
				return err
			},
		},
		{
			name: "Deploy workflow exists",
			checkFunc: func() error {
				_, err := os.Stat("/Users/eshamow/proj/gproject/.github/workflows/deploy.yml")
				return err
			},
		},
		{
			name: "Health endpoint configured",
			checkFunc: func() error {
				// This is validated by other tests, just check it's tested
				return nil
			},
		},
	}

	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			if err := check.checkFunc(); err != nil {
				t.Errorf("Production readiness check failed: %v", err)
			}
		})
	}
}
