# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a GitHub Issues frontend that adds product management features (epics, themes, reporting) on top of GitHub's issue tracking. It's a single-developer project optimized for rapid shipping with minimal operational complexity.

## Core Architecture Principles

1. **Start Simple**: Begin with a single `main.go` file. Only create packages when duplication becomes painful.
2. **SQLite First**: Use embedded SQLite, not PostgreSQL. Single-writer pattern (sync process) is a feature, not a limitation.
3. **No Build Pipeline**: HTMX + Alpine.js via CDN. No npm, webpack, or frontend build tools initially.
4. **Ship Weekly**: Each week must deliver working, visible features. Infrastructure can wait.
5. **Foundation Hygiene**: Security, data integrity, and user trust are NOT premature optimization. Do these right from day 1.

## Key Commands

```bash
# Development
make run          # Start the application
make dev          # Start with hot-reload (if air installed)

# Database
make db-reset     # Reset database and run migrations

# Testing
make test         # Run all tests

# When implemented later:
make build        # Build production binary
make docker-build # Build Docker image
```

## Technology Stack

- **Backend**: Go with standard library (avoid heavy frameworks like Gin/Echo initially)
- **Database**: SQLite with `modernc.org/sqlite` (pure Go, no CGO)
- **Frontend**: HTMX for interactivity, Alpine.js for client state, Tailwind CSS via CDN
- **Auth**: GitHub OAuth first, Passkeys later
- **Deployment**: Single binary, Docker only when needed

## Implementation Phases

**Current focus from docs/IMPLEMENTATION_PLAN.md:**

1. **Week 1**: Basic web server with GitHub OAuth
2. **Week 2**: GitHub Issues sync (this is the core value)
3. **Week 3-4**: Epics, themes, and enrichment features
4. **Week 5-6**: Reports, polish, and deployment

## Critical Implementation Details

### GitHub API Integration

- Use both REST and GraphQL APIs (GraphQL for batch fetching)
- Rate limit: 5000 requests/hour authenticated
- Implement webhook handlers for real-time updates
- Store GitHub access tokens encrypted in database

### Database Schema

Core tables only initially:
- `users`: GitHub auth data
- `sessions`: Active user sessions  
- `issues`: Synced from GitHub
- `epics`: User-created groupings
- `themes`: Higher-level groupings

Add tables incrementally as features require them.

### Authentication Flow

1. User clicks "Login with GitHub"
2. Redirect to GitHub OAuth with state parameter (CSRF protection)
3. GitHub redirects back with code
4. Exchange code for access token
5. Create session, store encrypted token

### Sync Strategy

- Initial sync: Fetch all issues via GraphQL
- Incremental sync: Use `updated_at` filter
- Real-time: GitHub webhooks for instant updates
- Conflict resolution: GitHub is always source of truth

## Foundation Hygiene vs Premature Optimization

### Do From Day 1 (Foundation Hygiene)
These are NOT premature optimization - they're doing things right the first time:

1. **Security Basics**:
   - CSRF protection (300 lines protects 100% of users)
   - Secure session management with httpOnly, secure cookies
   - Input validation and output escaping
   - Parameterized SQL queries (NEVER concatenate)
   - Environment variables for secrets
   - Rate limiting for external API calls

2. **Data Integrity**:
   - Foreign key constraints in database
   - Transactions for multi-step operations
   - Proper error handling with context
   - Audit logging for important operations

3. **User Trust**:
   - Clear error messages
   - Graceful degradation
   - Loading states for async operations
   - Consistent UI feedback

### Defer Until Needed (Premature Optimization)

1. **No microservices** - Monolith until 10K+ users
2. **No Kubernetes** - systemd or Docker Compose is fine
3. **No GraphQL server** - REST endpoints with HTMX
4. **No React/Vue** - HTMX delivers same UX with 10% complexity
5. **No ORMs** - Direct SQL with parameterized queries
6. **No dependency injection frameworks** - Go's simplicity is the feature
7. **No extensive testing initially** - Ship first, test what breaks
8. **No caching layer** - Until you measure the need
9. **No message queues** - Goroutines and channels first

## File Structure (Build Incrementally)

Start with:
```
/cmd/web/main.go         # Everything here first
/web/templates/*.html    # HTML templates
/data/gproject.db       # SQLite database
/.env                   # Configuration
/Makefile              # Simple commands
```

Grow to (only when needed):
```
/internal/
  /auth/               # GitHub OAuth handling
  /sync/               # GitHub sync logic
  /models/             # Data structures
  /handlers/           # HTTP handlers
```

## Security Essentials

- Always use parameterized SQL queries
- Store secrets in environment variables
- Use CSRF tokens for state-changing operations
- Validate webhook signatures from GitHub
- Escape output in templates (Go does this by default)
- Use secure session cookies (httpOnly, secure, sameSite)

## Performance Guidelines

- SQLite with WAL mode handles thousands of concurrent reads
- Use database indexes on foreign keys and commonly queried fields
- Implement HTTP caching headers for static content
- Batch GitHub API requests using GraphQL
- Run sync operations in background goroutines

## Decision Framework: Should I Add This Now?

When facing a "should I add this?" decision, ask:

1. **Is it security?** → YES, add it now
   - Example: CSRF tokens, secure cookies, input validation
   - Why: Security debt compounds exponentially

2. **Does it protect data integrity?** → YES, add it now
   - Example: Database constraints, transactions, proper error handling
   - Why: Corrupted data is harder to fix than missing features

3. **Will removing it later break user trust?** → YES, add it now
   - Example: Session management, audit logs, graceful error handling
   - Why: User trust is expensive to rebuild

4. **Is it an abstraction for future flexibility?** → NO, defer it
   - Example: Repository pattern, dependency injection, plugin system
   - Why: YAGNI - patterns will emerge from real usage

5. **Is it an optimization?** → NO, defer it
   - Example: Caching, database pooling, query optimization
   - Why: Optimize after measuring, not before

6. **Is it a nice-to-have feature?** → NO, defer it
   - Example: Dark mode, keyboard shortcuts, advanced filters
   - Why: Ship core value first

## Common Pitfalls

### Under-engineering (Shipping Carelessly)
1. **No CSRF protection**: "It's just an MVP" → Data loss, user compromise
2. **Storing passwords in plain text**: "We'll fix it later" → Never acceptable
3. **SQL injection vulnerabilities**: "We trust our users" → You shouldn't
4. **No error handling**: "It works on my machine" → It won't in production
5. **No session management**: "We'll add it when we scale" → Users hate re-logging in

### Over-engineering (Shipping Never)
1. **40+ files before first feature ships**: Perfect architecture, no users
2. **PostgreSQL for read-heavy workload**: SQLite handles millions of reads
3. **Frontend build pipeline**: HTMX + CDN ships today
4. **100% test coverage before launch**: Ship first, test what breaks
5. **Premature abstraction**: Duplicate code until patterns emerge
6. **Debating whether to remove working security code**: The real productivity trap

## When to Add Complexity

Only add when you measure the need:
- **PostgreSQL**: When you need multiple concurrent writers (not reads)
- **Redis**: When in-memory caching proves insufficient
- **Docker**: When deployment gets painful (not before)
- **Tests**: After users report bugs (test those paths)
- **Monitoring**: When you have users to monitor
- **Abstractions**: When you've written the same code 3+ times
- **Microservices**: When team boundaries require it
- **API versioning**: When you have external consumers
- **Feature flags**: When you need gradual rollouts

## The Pragmatic Balance

**Ship fast** means:
- Skip unnecessary abstractions
- Use boring technology
- Deploy monoliths
- Write SQL directly
- Use server-side rendering

**Ship fast** does NOT mean:
- Skip security basics
- Ignore data integrity  
- Break user trust
- Create technical debt you'll pay for in weeks (not months)
- Debate removing working security code

**Remember**: There's a huge difference between:
- "We'll add security later" (NEVER OK)
- "We'll add caching later" (TOTALLY OK)

The first is irresponsible. The second is pragmatic.

## References

- Full implementation details: `/docs/IMPLEMENTATION_PLAN.md`
- Architecture decisions: `/docs/STACK.md`