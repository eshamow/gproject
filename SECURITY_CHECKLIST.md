# Security Checklist

## ✅ Addressed in Current Code

### Critical Issues Fixed
- [x] **Token Encryption**: GitHub access tokens now encrypted with AES-256-GCM before storage
- [x] **CSRF Protection**: Added CSRF tokens for all state-changing operations
- [x] **Security Headers**: Implemented comprehensive security headers middleware
- [x] **Rate Limiting**: Added rate limiting for authentication endpoints
- [x] **Session Security**: Improved cookie security with Strict SameSite and secure flags
- [x] **Input Validation**: Added validation for OAuth callback parameters
- [x] **Automatic Cleanup**: Background task removes expired sessions and tokens

### Security Headers Implemented
- [x] X-Frame-Options: DENY (prevents clickjacking)
- [x] X-Content-Type-Options: nosniff (prevents MIME sniffing)
- [x] X-XSS-Protection: 1; mode=block (legacy XSS protection)
- [x] Content-Security-Policy (restricts resource loading)
- [x] Strict-Transport-Security (HSTS in production)
- [x] Referrer-Policy: strict-origin-when-cross-origin

## ⚠️ Important Security Tasks for Week 2-3

### High Priority
- [ ] **Webhook Signature Verification**: When implementing GitHub webhooks, MUST verify signatures
- [ ] **API Rate Limiting**: Extend rate limiting to all endpoints, not just auth
- [ ] **Audit Logging**: Log security events (login attempts, permission changes, data access)
- [ ] **Database Backups**: Implement encrypted backup strategy
- [ ] **Secret Rotation**: Build mechanism to rotate SESSION_SECRET without logging users out

### Medium Priority  
- [ ] **2FA Support**: Add optional 2FA for high-privilege users
- [ ] **Permission System**: Implement role-based access control (RBAC) before multi-user features
- [ ] **Content Security Policy Nonce**: Replace 'unsafe-inline' with nonces for scripts
- [ ] **Request Size Limits**: Add middleware to limit request body size
- [ ] **SQL Query Timeouts**: Add context timeouts for all database queries

## 🔒 Security Best Practices to Maintain

### Development
1. **Never log sensitive data**: No tokens, passwords, or PII in logs
2. **Use parameterized queries**: Always use ? placeholders, never string concatenation
3. **Validate all inputs**: Check length, format, and business logic constraints
4. **Escape all outputs**: Go templates auto-escape, but verify when using JavaScript
5. **Review dependencies**: Run `go mod audit` regularly (when available)

### Deployment (Week 5-6)
1. **Use environment variables**: Never hardcode secrets
2. **Run as non-root user**: Create dedicated service account
3. **Restrict file permissions**: 
   - Database: 600 (owner read/write only)
   - Binary: 755 (everyone can execute, only owner can write)
   - Config: 400 (owner read-only)
4. **Enable WAL mode**: Add `?_journal_mode=WAL` to SQLite connection
5. **Use reverse proxy**: Caddy or nginx with proper headers

### Monitoring (Post-Launch)
1. **Failed login attempts**: Alert on repeated failures from same IP
2. **Token usage patterns**: Detect unusual API access patterns
3. **Database size growth**: Monitor for potential DoS via sync abuse
4. **Response times**: Detect potential timing attacks
5. **Error rates**: High error rates may indicate attack attempts

## 🚨 Security Incident Response Plan

### If Breach Suspected:
1. **Rotate SESSION_SECRET immediately**: Forces all users to re-authenticate
2. **Revoke all GitHub tokens**: Use GitHub API to revoke app tokens
3. **Check audit logs**: Review access patterns for anomalies
4. **Notify users**: If personal data potentially accessed
5. **Patch and deploy**: Fix vulnerability and deploy immediately

### Prevention Measures:
- Regular security updates: `go get -u ./...` monthly
- Dependency scanning: Check for CVEs in dependencies
- Code review: Security review before major features
- Penetration testing: Consider after reaching 100+ users
- Security headers testing: Use securityheaders.com

## 📊 Security Debt Tracking

### Current Acceptable Risks (Pre-Launch):
1. **No WAF**: Acceptable for MVP, add Cloudflare later
2. **Single encryption key**: Acceptable until multi-tenant needs
3. **No HSM**: Software encryption sufficient for MVP
4. **Basic rate limiting**: In-memory sufficient until distributed deployment
5. **No security.txt**: Add before public launch

### Must Fix Before Public Launch:
1. **Webhook verification**: Critical for data integrity
2. **Audit logging**: Required for compliance
3. **Backup encryption**: Protect user data at rest
4. **Security documentation**: Public security policy
5. **Vulnerability disclosure**: Process for security reports

## 🔑 Quick Security Commands

```bash
# Generate secure session secret
openssl rand -hex 32

# Check for vulnerable dependencies
go list -m -json all | nancy sleuth

# Test security headers
curl -I http://localhost:8080 | grep -E "X-Frame|X-Content|CSP"

# Check database permissions
ls -la data/gproject.db

# Monitor active sessions
sqlite3 data/gproject.db "SELECT COUNT(*) FROM sessions WHERE expires_at > datetime('now');"

# Force logout all users (emergency)
sqlite3 data/gproject.db "DELETE FROM sessions;"
```

## 📝 Security Review Checklist for PRs

Before merging any PR, verify:
- [ ] No hardcoded secrets or credentials
- [ ] All SQL queries use parameterization
- [ ] New endpoints have rate limiting
- [ ] State-changing operations check CSRF tokens
- [ ] User inputs are validated and sanitized
- [ ] Error messages don't leak sensitive information
- [ ] New dependencies are from trusted sources
- [ ] Security headers still properly set
- [ ] Tests cover security edge cases
- [ ] Documentation updated for security features

---

Remember: **Security is a journey, not a destination.** This checklist will evolve as the application grows.