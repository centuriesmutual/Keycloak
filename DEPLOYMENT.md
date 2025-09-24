# Deployment Guide - Centuries Mutual Keycloak Enterprise System

This guide provides detailed instructions for deploying the Centuries Mutual Keycloak enterprise system in various environments.

## 🎯 Deployment Options

### 1. Local Development
### 2. Staging Environment
### 3. Production Environment
### 4. Cloud Deployment (AWS/Azure/GCP)

## 🏠 Local Development Deployment

### Prerequisites
- Docker Desktop 4.0+
- Docker Compose 2.0+
- 8GB RAM minimum
- 20GB free disk space

### Quick Start
```bash
# Clone repository
git clone <repository-url>
cd Keycloak

# Setup environment
cp env.example .env
# Edit .env with your local settings

# Deploy
chmod +x scripts/deploy.sh
./scripts/deploy.sh
```

### Local Configuration
```bash
# .env for local development
KEYCLOAK_HOSTNAME=localhost
KEYCLOAK_ADMIN_PASSWORD=admin123
POSTGRES_PASSWORD=postgres123
ENVIRONMENT=development
LOG_LEVEL=DEBUG
```

### Access URLs (Local)
- Keycloak Admin: https://localhost:8443/admin
- Customer Portal: https://localhost:8443/realms/CenturiesMutual-Users
- Staff Portal: https://localhost:8443/realms/CenturiesMutual-Staff
- Grafana: http://localhost:3000
- Prometheus: http://localhost:9090

## 🧪 Staging Environment Deployment

### Prerequisites
- Linux server (Ubuntu 20.04+ recommended)
- Docker and Docker Compose installed
- Domain name configured
- SSL certificates available

### Server Setup
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER

# Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Install additional tools
sudo apt install -y nginx certbot python3-certbot-nginx
```

### Environment Configuration
```bash
# .env for staging
KEYCLOAK_HOSTNAME=keycloak-staging.centuriesmutual.com
KEYCLOAK_ADMIN_PASSWORD=<secure-password>
POSTGRES_PASSWORD=<secure-db-password>
ENVIRONMENT=staging
LOG_LEVEL=INFO
```

### SSL Certificate Setup
```bash
# Get SSL certificate from Let's Encrypt
sudo certbot --nginx -d keycloak-staging.centuriesmutual.com

# Copy certificates to project
sudo cp /etc/letsencrypt/live/keycloak-staging.centuriesmutual.com/fullchain.pem ssl/server.crt.pem
sudo cp /etc/letsencrypt/live/keycloak-staging.centuriesmutual.com/privkey.pem ssl/server.key.pem
sudo chown $USER:$USER ssl/server.*
```

### Deploy to Staging
```bash
# Deploy services
./scripts/deploy.sh

# Setup monitoring
docker-compose up -d prometheus grafana

# Verify deployment
curl -k https://keycloak-staging.centuriesmutual.com/health/ready
```

## 🏭 Production Environment Deployment

### Infrastructure Requirements

#### Minimum Specifications
- **CPU**: 4 cores
- **RAM**: 16GB
- **Storage**: 100GB SSD
- **Network**: 1Gbps connection

#### Recommended Specifications
- **CPU**: 8 cores
- **RAM**: 32GB
- **Storage**: 500GB SSD with backup
- **Network**: 10Gbps connection
- **Load Balancer**: HAProxy or AWS ALB

### Production Server Setup

#### 1. System Hardening
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install security tools
sudo apt install -y ufw fail2ban unattended-upgrades

# Configure firewall
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable

# Configure fail2ban
sudo systemctl enable fail2ban
sudo systemctl start fail2ban
```

#### 2. Docker Installation
```bash
# Install Docker with production settings
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Configure Docker daemon
sudo tee /etc/docker/daemon.json > /dev/null <<EOF
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  },
  "storage-driver": "overlay2"
}
EOF

sudo systemctl restart docker
```

#### 3. SSL Certificate Management
```bash
# Install certbot
sudo apt install -y certbot

# Get production certificates
sudo certbot certonly --standalone -d keycloak.centuriesmutual.com

# Setup auto-renewal
echo "0 12 * * * /usr/bin/certbot renew --quiet" | sudo crontab -
```

### Production Configuration

#### Environment Variables
```bash
# .env for production
KEYCLOAK_HOSTNAME=keycloak.centuriesmutual.com
KEYCLOAK_ADMIN_PASSWORD=<very-secure-password>
POSTGRES_PASSWORD=<very-secure-db-password>
REDIS_PASSWORD=<secure-redis-password>
GRAFANA_ADMIN_PASSWORD=<secure-grafana-password>

# SMTP Configuration
SMTP_HOST=smtp.centuriesmutual.com
SMTP_PORT=587
SMTP_USER=noreply@centuriesmutual.com
SMTP_PASSWORD=<smtp-password>

# Social Login (Production)
GOOGLE_CLIENT_ID=<production-google-client-id>
GOOGLE_CLIENT_SECRET=<production-google-secret>
FACEBOOK_APP_ID=<production-facebook-app-id>
FACEBOOK_APP_SECRET=<production-facebook-secret>
APPLE_SERVICE_ID=com.centuriesmutual.auth
APPLE_TEAM_ID=<apple-team-id>
APPLE_KEY_ID=<apple-key-id>
APPLE_PRIVATE_KEY=<apple-private-key>

# Production Settings
ENVIRONMENT=production
LOG_LEVEL=WARN
BACKUP_RETENTION_DAYS=30
```

#### Docker Compose Production Override
```yaml
# docker-compose.prod.yml
version: '3.8'

services:
  keycloak:
    environment:
      KC_HEAP_DUMP_PATH: /opt/keycloak/logs
      KC_LOG_LEVEL: WARN
      KC_METRICS_ENABLED: true
    deploy:
      resources:
        limits:
          memory: 4G
        reservations:
          memory: 2G

  postgres:
    environment:
      POSTGRES_SHARED_PRELOAD_LIBRARIES: pg_stat_statements
    command: >
      postgres
      -c shared_preload_libraries=pg_stat_statements
      -c max_connections=200
      -c shared_buffers=256MB
      -c effective_cache_size=1GB
    deploy:
      resources:
        limits:
          memory: 2G
        reservations:
          memory: 1G

  nginx:
    deploy:
      resources:
        limits:
          memory: 512M
        reservations:
          memory: 256M
```

### Production Deployment Steps

#### 1. Initial Deployment
```bash
# Create production environment
cp env.example .env
# Edit .env with production values

# Deploy with production overrides
docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d

# Wait for services
sleep 60

# Import realms
docker-compose exec keycloak /opt/keycloak/bin/kc.sh import --file /opt/keycloak/data/import/keycloak-customer-realm.json --override true
docker-compose exec keycloak /opt/keycloak/bin/kc.sh import --file /opt/keycloak/data/import/keycloak-staff-realm.json --override true
```

#### 2. Setup Monitoring
```bash
# Configure Grafana
docker-compose exec grafana grafana-cli admin reset-admin-password <grafana-password>

# Import dashboards
# (Upload dashboard JSON files to Grafana)
```

#### 3. Setup Backup Automation
```bash
# Add to crontab
crontab -e

# Add backup schedule (daily at 2 AM)
0 2 * * * /path/to/Keycloak/scripts/backup.sh >> /var/log/keycloak-backup.log 2>&1
```

#### 4. Health Checks
```bash
# Create health check script
cat > /usr/local/bin/keycloak-health.sh << 'EOF'
#!/bin/bash
curl -f -k https://keycloak.centuriesmutual.com/health/ready || exit 1
EOF

chmod +x /usr/local/bin/keycloak-health.sh

# Add to crontab for monitoring
*/5 * * * * /usr/local/bin/keycloak-health.sh
```

## ☁️ Cloud Deployment

### AWS Deployment

#### 1. Infrastructure Setup
```bash
# Using AWS CLI
aws ec2 create-key-pair --key-name keycloak-prod

# Create security group
aws ec2 create-security-group --group-name keycloak-sg --description "Keycloak Security Group"
aws ec2 authorize-security-group-ingress --group-name keycloak-sg --protocol tcp --port 22 --cidr 0.0.0.0/0
aws ec2 authorize-security-group-ingress --group-name keycloak-sg --protocol tcp --port 80 --cidr 0.0.0.0/0
aws ec2 authorize-security-group-ingress --group-name keycloak-sg --protocol tcp --port 443 --cidr 0.0.0.0/0
```

#### 2. Launch EC2 Instance
```bash
# Launch instance
aws ec2 run-instances \
  --image-id ami-0c02fb55956c7d316 \
  --count 1 \
  --instance-type t3.large \
  --key-name keycloak-prod \
  --security-groups keycloak-sg \
  --block-device-mappings '[{"DeviceName":"/dev/sda1","Ebs":{"VolumeSize":100,"VolumeType":"gp3"}}]'
```

#### 3. RDS Database Setup
```bash
# Create RDS instance
aws rds create-db-instance \
  --db-instance-identifier keycloak-db \
  --db-instance-class db.t3.medium \
  --engine postgres \
  --master-username keycloak \
  --master-user-password <secure-password> \
  --allocated-storage 100 \
  --storage-type gp2 \
  --vpc-security-group-ids sg-xxxxxxxxx
```

#### 4. Application Load Balancer
```bash
# Create ALB
aws elbv2 create-load-balancer \
  --name keycloak-alb \
  --subnets subnet-xxxxxxxxx subnet-yyyyyyyyy \
  --security-groups sg-xxxxxxxxx
```

### Azure Deployment

#### 1. Resource Group
```bash
# Create resource group
az group create --name keycloak-rg --location eastus
```

#### 2. Virtual Machine
```bash
# Create VM
az vm create \
  --resource-group keycloak-rg \
  --name keycloak-vm \
  --image UbuntuLTS \
  --size Standard_D2s_v3 \
  --admin-username azureuser \
  --generate-ssh-keys
```

#### 3. Database
```bash
# Create PostgreSQL database
az postgres server create \
  --resource-group keycloak-rg \
  --name keycloak-db \
  --location eastus \
  --admin-user keycloak \
  --admin-password <secure-password> \
  --sku-name GP_Gen5_2
```

### GCP Deployment

#### 1. Project Setup
```bash
# Set project
gcloud config set project keycloak-project

# Enable APIs
gcloud services enable compute.googleapis.com
gcloud services enable sqladmin.googleapis.com
```

#### 2. Compute Engine
```bash
# Create VM instance
gcloud compute instances create keycloak-vm \
  --zone=us-central1-a \
  --machine-type=e2-standard-2 \
  --image-family=ubuntu-2004-lts \
  --image-project=ubuntu-os-cloud \
  --boot-disk-size=100GB \
  --boot-disk-type=pd-ssd
```

#### 3. Cloud SQL
```bash
# Create Cloud SQL instance
gcloud sql instances create keycloak-db \
  --database-version=POSTGRES_13 \
  --tier=db-f1-micro \
  --region=us-central1
```

## 🔄 High Availability Setup

### Multi-Instance Deployment

#### 1. Load Balancer Configuration
```yaml
# haproxy.cfg
global
    daemon
    maxconn 4096

defaults
    mode http
    timeout connect 5000ms
    timeout client 50000ms
    timeout server 50000ms

frontend keycloak_frontend
    bind *:80
    bind *:443 ssl crt /etc/ssl/certs/keycloak.pem
    redirect scheme https if !{ ssl_fc }
    default_backend keycloak_backend

backend keycloak_backend
    balance roundrobin
    option httpchk GET /health/ready
    server keycloak1 10.0.1.10:8443 check ssl verify none
    server keycloak2 10.0.1.11:8443 check ssl verify none
    server keycloak3 10.0.1.12:8443 check ssl verify none
```

#### 2. Database Clustering
```yaml
# PostgreSQL cluster setup
services:
  postgres-master:
    image: postgres:15
    environment:
      POSTGRES_REPLICATION_MODE: master
      POSTGRES_REPLICATION_USER: replicator
      POSTGRES_REPLICATION_PASSWORD: <replication-password>
    volumes:
      - postgres_master_data:/var/lib/postgresql/data

  postgres-slave:
    image: postgres:15
    environment:
      POSTGRES_REPLICATION_MODE: slave
      POSTGRES_MASTER_HOST: postgres-master
      POSTGRES_REPLICATION_USER: replicator
      POSTGRES_REPLICATION_PASSWORD: <replication-password>
    depends_on:
      - postgres-master
```

## 📊 Performance Optimization

### Database Tuning
```sql
-- PostgreSQL optimization
ALTER SYSTEM SET shared_buffers = '256MB';
ALTER SYSTEM SET effective_cache_size = '1GB';
ALTER SYSTEM SET maintenance_work_mem = '64MB';
ALTER SYSTEM SET checkpoint_completion_target = 0.9;
ALTER SYSTEM SET wal_buffers = '16MB';
ALTER SYSTEM SET default_statistics_target = 100;
SELECT pg_reload_conf();
```

### Keycloak Tuning
```bash
# JVM optimization
export JAVA_OPTS="-Xms2g -Xmx4g -XX:+UseG1GC -XX:MaxGCPauseMillis=200"
```

### Nginx Optimization
```nginx
# nginx.conf optimizations
worker_processes auto;
worker_connections 1024;
keepalive_timeout 65;
gzip on;
gzip_comp_level 6;
```

## 🔍 Monitoring Setup

### Prometheus Configuration
```yaml
# Additional scrape configs
scrape_configs:
  - job_name: 'keycloak-cluster'
    static_configs:
      - targets: 
        - 'keycloak1:8443'
        - 'keycloak2:8443'
        - 'keycloak3:8443'
```

### Grafana Dashboards
- Import Keycloak dashboard from Grafana.com
- Create custom dashboards for business metrics
- Setup alerting rules

## 🚨 Disaster Recovery

### Backup Strategy
1. **Database Backups**: Daily automated backups
2. **Configuration Backups**: Version controlled
3. **SSL Certificates**: Secure storage
4. **Monitoring Data**: Retention policies

### Recovery Procedures
1. **RTO**: 4 hours maximum
2. **RPO**: 1 hour maximum
3. **Testing**: Monthly recovery drills

## 📋 Deployment Checklist

### Pre-Deployment
- [ ] Environment variables configured
- [ ] SSL certificates obtained
- [ ] Database credentials secured
- [ ] Monitoring configured
- [ ] Backup procedures tested

### Deployment
- [ ] Services deployed successfully
- [ ] Health checks passing
- [ ] Realms imported
- [ ] Users can authenticate
- [ ] Monitoring active

### Post-Deployment
- [ ] Performance baseline established
- [ ] Backup schedule active
- [ ] Alerting configured
- [ ] Documentation updated
- [ ] Team trained

---

This deployment guide ensures a robust, scalable, and secure Keycloak deployment for Centuries Mutual's enterprise needs.
