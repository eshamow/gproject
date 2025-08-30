# Week 6: Deployment & Operations Plan

## Overview
Transform our working application into a production-ready, deployable system with minimal operational complexity.

## Core Objectives
1. **Containerization**: Docker image that runs anywhere
2. **Local Development**: Docker Compose for consistent dev environment
3. **CI/CD**: GitHub Actions for automated testing and deployment
4. **Configuration**: Environment-based config management
5. **Monitoring**: Basic health checks and logging
6. **Documentation**: Clear deployment instructions

## Task Delegation

### SRE Platform Engineer Tasks

#### 1. Containerization (Priority: HIGH)
- [ ] Create multi-stage Dockerfile
  - Builder stage with Go 1.21
  - Minimal Alpine runtime image
  - Proper handling of SQLite database
  - Static file serving for templates
- [ ] Ensure container runs without CGO issues
- [ ] Test container locally with production config

#### 2. Docker Compose Setup (Priority: HIGH)
- [ ] Create docker-compose.yml for local development
- [ ] Create docker-compose.prod.yml for production
- [ ] Volume mapping for persistent SQLite database
- [ ] Environment variable configuration
- [ ] Health check configuration
- [ ] Restart policies

#### 3. CI/CD Pipeline (Priority: HIGH)
- [ ] Update GitHub Actions workflow
  - Run tests on push/PR
  - Build Docker image on main branch
  - Push to GitHub Container Registry
  - Security scanning (basic)
- [ ] Add deployment workflow
  - Manual trigger for production deploy
  - Environment protection rules

#### 4. Configuration Management (Priority: MEDIUM)
- [ ] Create production .env.production template
- [ ] Document all required environment variables
- [ ] Add configuration validation on startup
- [ ] Secrets management strategy (GitHub Secrets)

#### 5. Monitoring & Health (Priority: MEDIUM)
- [ ] Add /health endpoint to application
- [ ] Structured logging with proper levels
- [ ] Basic metrics (request count, response time)
- [ ] Error tracking setup (logs for now)

#### 6. Deployment Documentation (Priority: HIGH)
- [ ] Create DEPLOYMENT.md with:
  - Local development setup
  - Production deployment steps
  - Environment configuration
  - Troubleshooting guide
  - Rollback procedures

### Principal Engineer Review Tasks

#### Pre-Deployment Checklist
- [ ] Review Dockerfile for security best practices
- [ ] Validate CI/CD pipeline configuration
- [ ] Test complete deployment flow locally
- [ ] Verify all security controls work in container
- [ ] Ensure database persistence across container restarts
- [ ] Validate production configuration

#### Final Assessment
- [ ] All critical paths tested in container
- [ ] Deployment documentation complete and accurate
- [ ] Rollback strategy defined and tested
- [ ] Security controls verified in production config
- [ ] Performance acceptable (< 2s page loads)

## Pragmatic Choices

### Do Now (Ship This Week)
1. Single container deployment (no orchestration)
2. SQLite with volume mount (no PostgreSQL migration)
3. GitHub Container Registry (free, integrated)
4. Manual deployment trigger (no auto-deploy)
5. Basic health checks (not full observability)
6. Log files for monitoring (not APM tools)

### Defer Until Needed
1. Kubernetes/orchestration (until scaling required)
2. PostgreSQL migration (until write bottleneck)
3. Advanced monitoring (Prometheus, Grafana)
4. Auto-scaling (until load requires)
5. Multi-region deployment
6. CDN for static assets

## Success Criteria
- [ ] Application runs in Docker locally
- [ ] CI passes on all commits
- [ ] Can deploy to production in < 5 minutes
- [ ] Can rollback in < 2 minutes
- [ ] All security tests pass in container
- [ ] Documentation allows new developer to deploy

## Timeline
- **Today**: Create Dockerfile and Docker Compose
- **Tomorrow**: CI/CD pipeline and testing
- **Day 3**: Production configuration and health checks
- **Day 4**: Documentation and final testing
- **Day 5**: Deploy to production

## Deployment Architecture

```
GitHub Repo → GitHub Actions → Docker Build → GitHub Container Registry
                    ↓
            Run Tests & Security Checks
                    ↓
            Manual Approval
                    ↓
            Deploy to Server (Docker Run)
                    ↓
            Health Check & Smoke Tests
```

## Risk Mitigation
1. **Data Loss**: Volume mounts with backup strategy
2. **Bad Deploy**: Quick rollback via previous image tag
3. **Secrets Leak**: GitHub Secrets, never in code
4. **Downtime**: Health checks before traffic switch
5. **Performance**: Test with production data volume

## Next Steps
1. SRE engineer implements containerization
2. SRE sets up CI/CD pipeline
3. Review and test complete flow
4. Deploy to staging environment
5. Final review and production deploy