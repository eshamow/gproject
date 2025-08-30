# SRE Platform Engineer Tasks - Week 6 Deployment

## Your Mission
Transform our working GitHub Issues frontend into a production-ready, containerized application that can be deployed this week. Focus on pragmatic choices that ship now, not perfect infrastructure.

## Context
- Application: Go web server with SQLite database
- Current state: Fully functional, security hardened, 45+ tests passing
- Goal: Deploy to production by end of week
- Philosophy: Simple, reliable, maintainable

## Priority 1: Containerization

### Create Dockerfile
Requirements:
- Multi-stage build (builder + runtime)
- Go 1.21 compatibility
- Handle SQLite properly (modernc.org/sqlite is pure Go, no CGO needed)
- Include templates and static files
- Minimal Alpine-based runtime image
- Non-root user for runtime
- Expose port 8080

Key considerations:
- Database file must be in a volume-mounted directory
- Templates directory must be copied correctly
- Binary must be statically linked

### Create Docker Compose Files

1. **docker-compose.yml** (development):
   - Build from local Dockerfile
   - Mount ./data for database persistence
   - Mount ./web for template hot-reload
   - Environment variables from .env file
   - Port 8080 exposed

2. **docker-compose.prod.yml** (production):
   - Use built image from registry
   - Volume for database only (not code)
   - Production environment variables
   - Restart policy: unless-stopped
   - Health check configuration

## Priority 2: CI/CD Pipeline

### Update GitHub Actions (.github/workflows/ci.yml)
Current state: Basic test runner
Required additions:
1. Docker build and push to GitHub Container Registry
2. Security scanning (trivy or similar)
3. Test run inside container
4. Tag with git SHA and 'latest' for main branch

### Create Deployment Workflow (.github/workflows/deploy.yml)
1. Manual trigger (workflow_dispatch)
2. Environment protection for production
3. Pull and run latest image
4. Health check verification
5. Rollback instructions in case of failure

## Priority 3: Configuration & Operations

### Health Check Endpoint
Add to application (if not exists):
- GET /health endpoint
- Returns 200 OK with basic status
- Checks database connectivity
- Returns JSON with version info

### Production Configuration
Create .env.production template with:
- All required environment variables
- Secure defaults
- Clear documentation for each variable
- No actual secrets (use placeholders)

### Logging Strategy
- Structured logging to stdout
- Log levels: ERROR, WARN, INFO, DEBUG
- Request logging with duration
- Error stack traces in development only

## Priority 4: Documentation

### Create DEPLOYMENT.md
Include:
1. **Local Development**
   - How to run with Docker Compose
   - Environment setup
   - Testing in container

2. **Production Deployment**
   - Step-by-step deployment process
   - Required environment variables
   - Database backup/restore
   - SSL/TLS setup (if needed)

3. **Operations**
   - How to view logs
   - How to access database
   - How to rollback
   - Common troubleshooting

4. **Security Notes**
   - Secret management
   - Network configuration
   - Update procedures

## Constraints & Guidelines

### Must Have
- Container runs without root privileges
- Database persists across container restarts
- All existing tests pass in container
- Can deploy in < 5 minutes
- Can rollback in < 2 minutes

### Should Avoid
- Complex orchestration (no K8s yet)
- Multiple containers (monolith is fine)
- External dependencies (Redis, PostgreSQL)
- Build-time secrets
- Large image sizes (aim for < 100MB)

### Testing Requirements
After implementation, these must work:
```bash
# Local development
docker-compose up
# Visit http://localhost:8080 and test OAuth flow

# Production build
docker-compose -f docker-compose.prod.yml up

# CI/CD
git push # Should trigger tests and build
```

## Deliverables Checklist
- [ ] Dockerfile (multi-stage, secure, minimal)
- [ ] docker-compose.yml (development)
- [ ] docker-compose.prod.yml (production)
- [ ] Updated .github/workflows/ci.yml
- [ ] New .github/workflows/deploy.yml
- [ ] .env.production template
- [ ] DEPLOYMENT.md documentation
- [ ] Health check endpoint (if needed)
- [ ] All tests passing in container

## Success Metrics
1. Docker image < 100MB
2. Container starts in < 5 seconds
3. All security tests pass in container
4. Zero hard-coded secrets
5. Clear deployment documentation

## Time Expectation
This should take 2-3 hours of focused work. If you hit blockers, document them and we'll address pragmatically. Remember: good enough to ship beats perfect but not deployed.

Start with the Dockerfile and docker-compose.yml - once those work locally, everything else follows naturally.