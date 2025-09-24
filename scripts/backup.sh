#!/bin/bash

# Centuries Mutual Keycloak Backup Script
# This script creates backups of the Keycloak database and configuration

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BACKUP_DIR="$PROJECT_DIR/backups"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_NAME="keycloak_backup_$TIMESTAMP"

# Functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

create_backup_directory() {
    log_info "Creating backup directory..."
    mkdir -p "$BACKUP_DIR/$BACKUP_NAME"
}

backup_database() {
    log_info "Backing up PostgreSQL database..."
    
    # Create database dump
    docker-compose exec -T postgres pg_dump -U keycloak keycloak > "$BACKUP_DIR/$BACKUP_NAME/database.sql"
    
    log_success "Database backup completed"
}

backup_realms() {
    log_info "Backing up realm configurations..."
    
    # Export realms using Keycloak admin CLI
    docker-compose exec -T keycloak /opt/keycloak/bin/kc.sh export --dir /tmp/export --realm CenturiesMutual-Users
    docker-compose exec -T keycloak /opt/keycloak/bin/kc.sh export --dir /tmp/export --realm CenturiesMutual-Staff
    
    # Copy exported files
    docker cp "$(docker-compose ps -q keycloak):/tmp/export" "$BACKUP_DIR/$BACKUP_NAME/"
    
    log_success "Realm configurations backed up"
}

backup_configuration() {
    log_info "Backing up configuration files..."
    
    # Copy important configuration files
    cp -r "$PROJECT_DIR/realms" "$BACKUP_DIR/$BACKUP_NAME/"
    cp -r "$PROJECT_DIR/themes" "$BACKUP_DIR/$BACKUP_NAME/"
    cp "$PROJECT_DIR/docker-compose.yml" "$BACKUP_DIR/$BACKUP_NAME/"
    cp "$PROJECT_DIR/.env" "$BACKUP_DIR/$BACKUP_NAME/" 2>/dev/null || log_warning ".env file not found, skipping"
    
    log_success "Configuration files backed up"
}

create_backup_archive() {
    log_info "Creating backup archive..."
    
    cd "$BACKUP_DIR"
    tar -czf "${BACKUP_NAME}.tar.gz" "$BACKUP_NAME"
    rm -rf "$BACKUP_NAME"
    
    log_success "Backup archive created: ${BACKUP_NAME}.tar.gz"
}

cleanup_old_backups() {
    log_info "Cleaning up old backups..."
    
    # Keep only last 7 days of backups
    find "$BACKUP_DIR" -name "keycloak_backup_*.tar.gz" -mtime +7 -delete
    
    log_success "Old backups cleaned up"
}

show_backup_info() {
    log_info "Backup Information:"
    echo "  Backup Name: $BACKUP_NAME"
    echo "  Backup Location: $BACKUP_DIR/${BACKUP_NAME}.tar.gz"
    echo "  Backup Size: $(du -h "$BACKUP_DIR/${BACKUP_NAME}.tar.gz" | cut -f1)"
    echo "  Created: $(date)"
}

# Main execution
main() {
    log_info "Starting Keycloak backup process..."
    
    create_backup_directory
    backup_database
    backup_realms
    backup_configuration
    create_backup_archive
    cleanup_old_backups
    show_backup_info
    
    log_success "Backup completed successfully!"
}

# Run main function
main "$@"
