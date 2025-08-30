#!/bin/bash
# Production deployment script with comprehensive error handling

set -euo pipefail  # Exit on error, undefined variables, and pipe failures
IFS=$'\n\t'       # Set secure Internal Field Separator

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

# Error handler
error_handler() {
    local line_no=$1
    local exit_code=$2
    log_error "Error occurred in script at line: ${line_no}, exit code: ${exit_code}"
    cleanup_on_error
    exit "${exit_code}"
}

# Cleanup function for error scenarios
cleanup_on_error() {
    log_info "Performing cleanup..."
    # Add any cleanup tasks here (e.g., removing temp files, restoring backups)
}

# Set error trap
trap 'error_handler ${LINENO} $?' ERR

# Validate environment
validate_environment() {
    log_info "Validating deployment environment..."
    
    # Check required environment variables
    local required_vars=("GITHUB_REPOSITORY" "GITHUB_TOKEN" "DEPLOY_HOST")
    for var in "${required_vars[@]}"; do
        if [[ -z "${!var:-}" ]]; then
            log_error "Required environment variable $var is not set"
            exit 1
        fi
    done
    
    # Check required commands
    local required_commands=("docker" "docker-compose" "git")
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            log_error "Required command '$cmd' is not installed"
            exit 1
        fi
    done
    
    log_info "Environment validation completed successfully"
}

# Backup database before deployment
backup_database() {
    log_info "Creating database backup..."
    
    local backup_dir="/var/backups/gproject"
    local backup_file="${backup_dir}/gproject_$(date +%Y%m%d_%H%M%S).db"
    
    # Create backup directory if it doesn't exist
    if [[ ! -d "$backup_dir" ]]; then
        mkdir -p "$backup_dir" || {
            log_error "Failed to create backup directory"
            return 1
        }
    fi
    
    # Create backup
    if [[ -f "/var/lib/gproject/data/gproject.db" ]]; then
        cp "/var/lib/gproject/data/gproject.db" "$backup_file" || {
            log_error "Failed to create database backup"
            return 1
        }
        log_info "Database backed up to: $backup_file"
        
        # Keep only last 5 backups
        find "$backup_dir" -name "gproject_*.db" -type f | sort -r | tail -n +6 | xargs -r rm
    else
        log_warn "No existing database found to backup"
    fi
}

# Health check function
health_check() {
    local max_attempts=30
    local attempt=0
    local health_url="${1:-http://localhost:8080/health}"
    
    log_info "Performing health check on $health_url"
    
    while [[ $attempt -lt $max_attempts ]]; do
        if curl -sf "$health_url" > /dev/null 2>&1; then
            log_info "Health check passed"
            return 0
        fi
        
        attempt=$((attempt + 1))
        log_info "Health check attempt $attempt/$max_attempts failed, retrying..."
        sleep 2
    done
    
    log_error "Health check failed after $max_attempts attempts"
    return 1
}

# Pull latest Docker image
pull_image() {
    log_info "Pulling latest Docker image..."
    
    docker pull "ghcr.io/${GITHUB_REPOSITORY}:latest" || {
        log_error "Failed to pull Docker image"
        return 1
    }
    
    log_info "Docker image pulled successfully"
}

# Deploy application
deploy_application() {
    log_info "Starting deployment..."
    
    # Stop existing containers
    log_info "Stopping existing containers..."
    docker-compose -f docker-compose.prod.yml down --timeout 30 || true
    
    # Start new containers
    log_info "Starting new containers..."
    docker-compose -f docker-compose.prod.yml up -d || {
        log_error "Failed to start containers"
        return 1
    }
    
    # Wait for application to be ready
    sleep 5
    
    # Perform health check
    if ! health_check; then
        log_error "Application failed health check after deployment"
        rollback
        return 1
    fi
    
    log_info "Deployment completed successfully"
}

# Rollback function
rollback() {
    log_error "Initiating rollback..."
    
    # Stop current containers
    docker-compose -f docker-compose.prod.yml down --timeout 30
    
    # Start previous version (assuming we tagged it)
    docker-compose -f docker-compose.prod.yml up -d --scale web=1 || {
        log_error "Rollback failed"
        return 1
    }
    
    # Restore database if needed
    # This would require additional logic to track the previous backup
    
    log_info "Rollback completed"
}

# Clean up old Docker resources
cleanup_docker() {
    log_info "Cleaning up Docker resources..."
    
    # Remove unused images (keep last 3)
    docker images | grep "ghcr.io/${GITHUB_REPOSITORY}" | tail -n +4 | awk '{print $3}' | xargs -r docker rmi -f || true
    
    # Clean up dangling resources
    docker system prune -f --volumes || true
    
    log_info "Docker cleanup completed"
}

# Main deployment flow
main() {
    log_info "Starting deployment process..."
    
    # Validate environment
    validate_environment
    
    # Create database backup
    backup_database
    
    # Pull latest image
    if ! pull_image; then
        log_error "Deployment aborted due to image pull failure"
        exit 1
    fi
    
    # Deploy application
    if ! deploy_application; then
        log_error "Deployment failed"
        exit 1
    fi
    
    # Clean up old resources
    cleanup_docker
    
    log_info "Deployment process completed successfully"
}

# Run main function
main "$@"