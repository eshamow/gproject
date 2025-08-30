# Deployment Guide

This guide covers deploying the GitHub Issues frontend application using Docker.

## Prerequisites

- Docker 20.10+ and Docker Compose 2.0+
- GitHub OAuth Application configured
- Domain with SSL certificate (for production)
- 512MB RAM minimum, 1GB recommended
- 5GB disk space for application and database

## Quick Start

### Local Development with Docker

1. **Clone the repository:**
```bash
git clone https://github.com/eshamow/gproject.git
cd gproject
```

2. **Set up environment variables:**
```bash
cp .env.example .env
# Edit .env with your GitHub OAuth credentials
```

3. **Start the application:**
```bash
docker-compose up --build
```

4. **Access the application:**
- Open http://localhost:8080
- Login with GitHub OAuth
- Database persists in `./data/gproject.db`

### Production Deployment

## Step 1: Server Setup

1. **Create application directory:**
```bash
sudo mkdir -p /opt/gproject
sudo mkdir -p /var/lib/gproject/data
sudo mkdir -p /var/lib/gproject/backups
sudo chown -R $USER:$USER /opt/gproject /var/lib/gproject
```

2. **Clone repository:**
```bash
cd /opt/gproject
git clone https://github.com/eshamow/gproject.git .
```

## Step 2: Configure Environment

1. **Create production environment file:**
```bash
cp .env.production .env.production.local
```

2. **Edit `.env.production.local` with your values:**
```bash
# Required variables:
PORT=8080
ENVIRONMENT=production
DATABASE_URL=file:/app/data/gproject.db

# GitHub OAuth (create at https://github.com/settings/applications/new)
GITHUB_CLIENT_ID=your_production_client_id
GITHUB_CLIENT_SECRET=your_production_client_secret
GITHUB_REDIRECT_URL=https://yourdomain.com/auth/callback

# Security (generate with: openssl rand -base64 32)
SESSION_SECRET=your_secure_random_string_here

# Repository to sync
GITHUB_REPO_OWNER=your_github_username
GITHUB_REPO_NAME=your_repo_name

# Webhook secret (generate with: openssl rand -hex 32)
GITHUB_WEBHOOK_SECRET=your_webhook_secret_here
```

## Step 3: Deploy with Docker Compose

1. **Pull and start the container:**
```bash
# For first deployment
docker-compose -f docker-compose.prod.yml up -d

# For updates
docker-compose -f docker-compose.prod.yml pull
docker-compose -f docker-compose.prod.yml up -d
```

2. **Verify deployment:**
```bash
# Check container status
docker-compose -f docker-compose.prod.yml ps

# Check logs
docker-compose -f docker-compose.prod.yml logs -f

# Test health endpoint
curl http://localhost:8080/health
```

## Step 4: Configure Reverse Proxy (nginx)

1. **Install nginx:**
```bash
sudo apt update
sudo apt install nginx certbot python3-certbot-nginx
```

2. **Create nginx configuration:**
```nginx
# /etc/nginx/sites-available/gproject
server {
    listen 80;
    server_name yourdomain.com;
    
    location / {
        proxy_pass http://localhost:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # WebSocket support for SSE
        proxy_set_header Connection '';
        proxy_http_version 1.1;
        chunked_transfer_encoding off;
        proxy_buffering off;
        proxy_cache off;
    }
    
    location /health {
        proxy_pass http://localhost:8080/health;
        access_log off;
    }
}
```

3. **Enable site and SSL:**
```bash
sudo ln -s /etc/nginx/sites-available/gproject /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
sudo certbot --nginx -d yourdomain.com
```

## Step 5: Configure GitHub Webhooks

1. Go to `https://github.com/YOUR_ORG/YOUR_REPO/settings/hooks`
2. Click "Add webhook"
3. Configure:
   - Payload URL: `https://yourdomain.com/webhook/github`
   - Content type: `application/json`
   - Secret: Use the value from `GITHUB_WEBHOOK_SECRET`
   - Events: Select "Issues" and "Issue comments"
4. Save the webhook

## Operations

### Viewing Logs

```bash
# All logs
docker-compose -f docker-compose.prod.yml logs

# Follow logs
docker-compose -f docker-compose.prod.yml logs -f

# Last 100 lines
docker-compose -f docker-compose.prod.yml logs --tail=100
```

### Database Management

**Backup database:**
```bash
docker-compose -f docker-compose.prod.yml exec web \
  cp /app/data/gproject.db /app/data/backup-$(date +%Y%m%d-%H%M%S).db
```

**Restore database:**
```bash
docker-compose -f docker-compose.prod.yml down
cp /path/to/backup.db /var/lib/gproject/data/gproject.db
docker-compose -f docker-compose.prod.yml up -d
```

**Access SQLite shell:**
```bash
docker-compose -f docker-compose.prod.yml exec web \
  sqlite3 /app/data/gproject.db
```

### Updating the Application

1. **Pull latest changes:**
```bash
cd /opt/gproject
git pull origin main
```

2. **Update container:**
```bash
docker-compose -f docker-compose.prod.yml pull
docker-compose -f docker-compose.prod.yml up -d
```

3. **Verify update:**
```bash
docker-compose -f docker-compose.prod.yml logs --tail=50
curl http://localhost:8080/health
```

### Rolling Back

If an update causes issues:

1. **Check available images:**
```bash
docker images | grep gproject
```

2. **Rollback to previous version:**
```bash
# Stop current container
docker-compose -f docker-compose.prod.yml down

# Edit docker-compose.prod.yml to use specific tag
# image: ghcr.io/eshamow/gproject:previous-tag

# Start previous version
docker-compose -f docker-compose.prod.yml up -d
```

3. **Restore database if needed:**
```bash
cp /var/lib/gproject/backups/gproject-TIMESTAMP.db /var/lib/gproject/data/gproject.db
```

## Monitoring

### Health Checks

The application exposes `/health` endpoint that returns:
```json
{
  "status": "ok",
  "database": "ok",
  "version": "1.0.0",
  "time": "2024-01-01T12:00:00Z"
}
```

### Monitoring Setup

1. **Basic monitoring with cron:**
```bash
# Add to crontab
*/5 * * * * curl -f http://localhost:8080/health || echo "GProject is down" | mail -s "Alert: GProject Down" admin@example.com
```

2. **Using Uptime Kuma (recommended):**
```bash
docker run -d \
  --name uptime-kuma \
  -p 3001:3001 \
  -v uptime-kuma:/app/data \
  louislam/uptime-kuma:1
```

## Troubleshooting

### Container won't start

1. **Check logs:**
```bash
docker-compose -f docker-compose.prod.yml logs --tail=100
```

2. **Verify environment variables:**
```bash
docker-compose -f docker-compose.prod.yml config
```

3. **Check disk space:**
```bash
df -h
du -sh /var/lib/gproject/data/
```

### Database locked errors

1. **Stop the container:**
```bash
docker-compose -f docker-compose.prod.yml down
```

2. **Remove lock files:**
```bash
rm -f /var/lib/gproject/data/*.db-shm
rm -f /var/lib/gproject/data/*.db-wal
```

3. **Restart:**
```bash
docker-compose -f docker-compose.prod.yml up -d
```

### OAuth callback errors

1. Verify `GITHUB_REDIRECT_URL` matches GitHub OAuth app settings
2. Check SSL certificate is valid
3. Ensure cookies are enabled and `SESSION_SECRET` is set

### Performance issues

1. **Check container resources:**
```bash
docker stats
```

2. **Increase memory limit in docker-compose.prod.yml:**
```yaml
deploy:
  resources:
    limits:
      memory: 1G
```

3. **Enable SQLite WAL mode (should be automatic):**
```sql
PRAGMA journal_mode=WAL;
```

## Security Notes

### Required Security Measures

1. **Environment Variables:**
   - Never commit `.env.production.local` to git
   - Use strong, unique values for all secrets
   - Rotate secrets regularly

2. **Network Security:**
   - Always use HTTPS in production
   - Configure firewall to only allow ports 80, 443, and SSH
   - Use fail2ban for brute force protection

3. **Database Security:**
   - Regular automated backups
   - Encrypt backups at rest
   - Test restore procedures monthly

4. **Container Security:**
   - Run as non-root user (already configured)
   - Keep Docker and base images updated
   - Scan images for vulnerabilities with Trivy

### Security Checklist

- [ ] SSL certificate installed and auto-renewing
- [ ] All secrets are strong and unique
- [ ] Firewall configured with minimal open ports
- [ ] Regular backups configured and tested
- [ ] Monitoring alerts configured
- [ ] GitHub webhook secret configured
- [ ] Session cookies set to secure, httpOnly, sameSite
- [ ] Rate limiting enabled (built into application)

## CI/CD Integration

### Automated Deployments

The repository includes GitHub Actions workflows for CI/CD:

1. **CI Pipeline** (`.github/workflows/ci.yml`):
   - Runs tests on every push
   - Builds and pushes Docker images to GitHub Container Registry
   - Performs security scanning with Trivy

2. **Deploy Workflow** (`.github/workflows/deploy.yml`):
   - Manual deployment trigger
   - Supports staging and production environments
   - Automatic rollback on failure

### Setting up CD

1. **Add GitHub Secrets:**
   - `DEPLOY_HOST`: Your server IP/hostname
   - `DEPLOY_USER`: SSH username
   - `DEPLOY_SSH_KEY`: Private SSH key for deployment
   - `DEPLOY_URL`: Public URL for verification

2. **Trigger deployment:**
   - Go to Actions tab in GitHub
   - Select "Deploy to Production"
   - Click "Run workflow"
   - Choose environment and tag

## Support

For issues or questions:
1. Check application logs first
2. Review this documentation
3. Check GitHub Issues for known problems
4. Create a new issue with logs and environment details

## Quick Commands Reference

```bash
# Start application
docker-compose -f docker-compose.prod.yml up -d

# Stop application
docker-compose -f docker-compose.prod.yml down

# View logs
docker-compose -f docker-compose.prod.yml logs -f

# Restart application
docker-compose -f docker-compose.prod.yml restart

# Update application
docker-compose -f docker-compose.prod.yml pull && docker-compose -f docker-compose.prod.yml up -d

# Backup database
docker-compose -f docker-compose.prod.yml exec web cp /app/data/gproject.db /app/data/backup.db

# Check health
curl http://localhost:8080/health

# Shell access
docker-compose -f docker-compose.prod.yml exec web sh
```