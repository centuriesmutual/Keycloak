#!/bin/bash

# Centuries Mutual Keycloak Deployment Script
# This script deploys the complete Keycloak enterprise system

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
ENV_FILE="$PROJECT_DIR/.env"

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

check_requirements() {
    log_info "Checking system requirements..."
    
    # Check if Docker is installed
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed. Please install Docker first."
        exit 1
    fi
    
    # Check if Docker Compose is installed
    if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
        log_error "Docker Compose is not installed. Please install Docker Compose first."
        exit 1
    fi
    
    # Check if .env file exists
    if [ ! -f "$ENV_FILE" ]; then
        log_warning ".env file not found. Creating from template..."
        cp "$PROJECT_DIR/env.example" "$ENV_FILE"
        log_warning "Please edit .env file with your configuration before running again."
        exit 1
    fi
    
    log_success "All requirements met"
}

create_directories() {
    log_info "Creating necessary directories..."
    
    mkdir -p "$PROJECT_DIR/ssl"
    mkdir -p "$PROJECT_DIR/logs/nginx"
    mkdir -p "$PROJECT_DIR/logs/keycloak"
    mkdir -p "$PROJECT_DIR/backups"
    mkdir -p "$PROJECT_DIR/themes"
    mkdir -p "$PROJECT_DIR/realms"
    
    log_success "Directories created"
}

generate_ssl_certificates() {
    log_info "Generating SSL certificates..."
    
    if [ ! -f "$PROJECT_DIR/ssl/server.crt.pem" ] || [ ! -f "$PROJECT_DIR/ssl/server.key.pem" ]; then
        log_warning "SSL certificates not found. Generating self-signed certificates..."
        
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout "$PROJECT_DIR/ssl/server.key.pem" \
            -out "$PROJECT_DIR/ssl/server.crt.pem" \
            -subj "/C=US/ST=State/L=City/O=Centuries Mutual/CN=keycloak.centuriesmutual.com"
        
        log_success "Self-signed SSL certificates generated"
        log_warning "For production, replace with proper SSL certificates"
    else
        log_success "SSL certificates already exist"
    fi
}

copy_realm_configs() {
    log_info "Copying realm configurations..."
    
    cp "$PROJECT_DIR/keycloak-customer-realm.json" "$PROJECT_DIR/realms/"
    cp "$PROJECT_DIR/keycloak-staff-realm.json" "$PROJECT_DIR/realms/"
    
    log_success "Realm configurations copied"
}

deploy_services() {
    log_info "Deploying services..."
    
    cd "$PROJECT_DIR"
    
    # Pull latest images
    log_info "Pulling Docker images..."
    docker-compose pull
    
    # Start services
    log_info "Starting services..."
    docker-compose up -d
    
    log_success "Services deployed"
}

wait_for_services() {
    log_info "Waiting for services to be ready..."
    
    # Wait for PostgreSQL
    log_info "Waiting for PostgreSQL..."
    timeout 60 bash -c 'until docker-compose exec -T postgres pg_isready -U keycloak; do sleep 2; done'
    
    # Wait for Keycloak
    log_info "Waiting for Keycloak..."
    timeout 120 bash -c 'until curl -f -k https://localhost:8443/health/ready; do sleep 5; done'
    
    log_success "All services are ready"
}

import_realms() {
    log_info "Importing realm configurations..."
    
    # Import customer realm
    log_info "Importing customer realm..."
    docker-compose exec -T keycloak /opt/keycloak/bin/kc.sh import --file /opt/keycloak/data/import/keycloak-customer-realm.json --override true
    
    # Import staff realm
    log_info "Importing staff realm..."
    docker-compose exec -T keycloak /opt/keycloak/bin/kc.sh import --file /opt/keycloak/data/import/keycloak-staff-realm.json --override true
    
    log_success "Realms imported successfully"
}

show_status() {
    log_info "Service Status:"
    docker-compose ps
    
    echo ""
    log_info "Access URLs:"
    echo "  Keycloak Admin Console: https://keycloak.centuriesmutual.com/admin"
    echo "  Customer Portal: https://keycloak.centuriesmutual.com/realms/CenturiesMutual-Users"
    echo "  Staff Portal: https://keycloak.centuriesmutual.com/realms/CenturiesMutual-Staff"
    echo "  Grafana Dashboard: http://localhost:3000"
    echo "  Prometheus: http://localhost:9090"
    
    echo ""
    log_info "Default Admin Credentials:"
    echo "  Username: admin"
    echo "  Password: (check your .env file)"
}

# Main execution
main() {
    log_info "Starting Centuries Mutual Keycloak deployment..."
    
    check_requirements
    create_directories
    generate_ssl_certificates
    copy_realm_configs
    deploy_services
    wait_for_services
    import_realms
    show_status
    
    log_success "Deployment completed successfully!"
    log_info "You can now access your Keycloak instance at https://keycloak.centuriesmutual.com"
}

# Run main function
main "$@"
