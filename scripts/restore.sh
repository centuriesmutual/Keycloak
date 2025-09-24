#!/bin/bash

# Centuries Mutual Keycloak Restore Script
# This script restores Keycloak from a backup

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

show_usage() {
    echo "Usage: $0 <backup_file>"
    echo ""
    echo "Available backups:"
    ls -la "$BACKUP_DIR"/*.tar.gz 2>/dev/null || echo "No backups found"
    echo ""
    echo "Example: $0 keycloak_backup_20241201_120000.tar.gz"
}

check_backup_file() {
    local backup_file="$1"
    
    if [ -z "$backup_file" ]; then
        log_error "Backup file not specified"
        show_usage
        exit 1
    fi
    
    if [ ! -f "$BACKUP_DIR/$backup_file" ]; then
        log_error "Backup file not found: $BACKUP_DIR/$backup_file"
        show_usage
        exit 1
    fi
    
    log_success "Backup file found: $backup_file"
}

extract_backup() {
    local backup_file="$1"
    local extract_dir="$BACKUP_DIR/restore_temp"
    
    log_info "Extracting backup file..."
    
    # Clean up any existing temp directory
    rm -rf "$extract_dir"
    
    # Extract backup
    cd "$BACKUP_DIR"
    tar -xzf "$backup_file" -C "$extract_dir"
    
    # Get the extracted directory name
    local extracted_dir=$(ls "$extract_dir")
    RESTORE_DIR="$extract_dir/$extracted_dir"
    
    log_success "Backup extracted to: $RESTORE_DIR"
}

stop_services() {
    log_info "Stopping Keycloak services..."
    
    cd "$PROJECT_DIR"
    docker-compose down
    
    log_success "Services stopped"
}

restore_database() {
    log_info "Restoring PostgreSQL database..."
    
    # Start only PostgreSQL
    cd "$PROJECT_DIR"
    docker-compose up -d postgres
    
    # Wait for PostgreSQL to be ready
    log_info "Waiting for PostgreSQL to be ready..."
    timeout 60 bash -c 'until docker-compose exec -T postgres pg_isready -U keycloak; do sleep 2; done'
    
    # Drop and recreate database
    docker-compose exec -T postgres psql -U keycloak -c "DROP DATABASE IF EXISTS keycloak;"
    docker-compose exec -T postgres psql -U keycloak -c "CREATE DATABASE keycloak;"
    
    # Restore database
    docker-compose exec -T postgres psql -U keycloak keycloak < "$RESTORE_DIR/database.sql"
    
    log_success "Database restored"
}

restore_configuration() {
    log_info "Restoring configuration files..."
    
    # Copy configuration files back
    if [ -d "$RESTORE_DIR/realms" ]; then
        cp -r "$RESTORE_DIR/realms"/* "$PROJECT_DIR/realms/"
    fi
    
    if [ -d "$RESTORE_DIR/themes" ]; then
        cp -r "$RESTORE_DIR/themes"/* "$PROJECT_DIR/themes/"
    fi
    
    log_success "Configuration files restored"
}

start_services() {
    log_info "Starting all services..."
    
    cd "$PROJECT_DIR"
    docker-compose up -d
    
    # Wait for services to be ready
    log_info "Waiting for services to be ready..."
    timeout 120 bash -c 'until curl -f -k https://localhost:8443/health/ready; do sleep 5; done'
    
    log_success "All services started"
}

cleanup() {
    log_info "Cleaning up temporary files..."
    
    rm -rf "$BACKUP_DIR/restore_temp"
    
    log_success "Cleanup completed"
}

show_restore_info() {
    log_info "Restore completed successfully!"
    echo ""
    log_info "Access URLs:"
    echo "  Keycloak Admin Console: https://keycloak.centuriesmutual.com/admin"
    echo "  Customer Portal: https://keycloak.centuriesmutual.com/realms/CenturiesMutual-Users"
    echo "  Staff Portal: https://keycloak.centuriesmutual.com/realms/CenturiesMutual-Staff"
    echo ""
    log_info "Service Status:"
    docker-compose ps
}

# Main execution
main() {
    local backup_file="$1"
    
    log_info "Starting Keycloak restore process..."
    
    check_backup_file "$backup_file"
    extract_backup "$backup_file"
    stop_services
    restore_database
    restore_configuration
    start_services
    cleanup
    show_restore_info
    
    log_success "Restore completed successfully!"
}

# Run main function
main "$@"
