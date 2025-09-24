# Centuries Mutual Keycloak Enterprise System

A comprehensive, production-ready Keycloak deployment for Centuries Mutual with complete monitoring, backup, and integration examples.

## 🏗️ Architecture Overview

This enterprise system provides:

- **Dual Realm Setup**: Separate realms for customers and staff
- **High Availability**: PostgreSQL database with connection pooling
- **Security**: SSL/TLS termination, rate limiting, security headers
- **Monitoring**: Prometheus metrics collection and Grafana dashboards
- **Backup & Recovery**: Automated backup and restore procedures
- **API Integration**: Sample implementations in Node.js, Python, and React

## 📋 Prerequisites

- Docker and Docker Compose
- OpenSSL (for SSL certificate generation)
- 4GB+ RAM available
- 20GB+ disk space

## 🚀 Quick Start

### 1. Clone and Setup

```bash
git clone <repository-url>
cd Keycloak
cp env.example .env
```

### 2. Configure Environment

Edit `.env` file with your configuration:

```bash
# Required configurations
KEYCLOAK_HOSTNAME=keycloak.centuriesmutual.com
KEYCLOAK_ADMIN_PASSWORD=your_secure_password
POSTGRES_PASSWORD=your_secure_db_password
```

### 3. Deploy

```bash
chmod +x scripts/deploy.sh
./scripts/deploy.sh
```

### 4. Access Your System

- **Keycloak Admin Console**: https://keycloak.centuriesmutual.com/admin
- **Customer Portal**: https://keycloak.centuriesmutual.com/realms/CenturiesMutual-Users
- **Staff Portal**: https://keycloak.centuriesmutual.com/realms/CenturiesMutual-Staff
- **Grafana Dashboard**: http://localhost:3000
- **Prometheus**: http://localhost:9090

## 🏢 Realm Configuration

### Customer Realm (CenturiesMutual-Users)

**Features:**
- Public registration enabled
- Social login (Google, Facebook, Apple)
- Role-based access (basic_user, premium_user, beta_tester)
- 6 iOS applications configured
- TOTP 2FA support

**Default Users:**
- `john.doe` / `Welcome@2024!` (basic_user)
- `jane.premium` / `Premium@2024!` (premium_user)
- `bob.tester` / `Testing@2024!` (beta_tester)

### Staff Realm (CenturiesMutual-Staff)

**Features:**
- Admin-managed users only
- Enhanced security policies
- Role-based access (support_agent, marketing_broker, admin)
- 3 staff applications configured
- Mandatory 2FA

**Default Users:**
- `support.alice` / `Support@2024!` (support_agent)
- `marketing.bob` / `Marketing@2024!` (marketing_broker)
- `admin.charlie` / `Admin@2024!` (admin)
- `admin.sarah` / `SuperAdmin@2024!` (admin with all roles)

## 📱 Mobile Applications

### Customer Apps
- **Home iOS**: Main customer portal
- **Saint Daniels iOS**: Specialized service app
- **My Brothers Keeper iOS**: Community features
- **Drue Maison iOS**: Premium services
- **Light Rain iOS**: Weather/notification service
- **Conservatory iOS**: Content management

### Staff Apps
- **Support iOS**: Customer support tools
- **Legend iOS**: Marketing campaign management
- **Admin iOS**: Administrative functions

## 🔧 Management Scripts

### Deployment
```bash
./scripts/deploy.sh
```
- Checks system requirements
- Creates necessary directories
- Generates SSL certificates
- Deploys all services
- Imports realm configurations

### Backup
```bash
./scripts/backup.sh
```
- Creates database dump
- Exports realm configurations
- Archives configuration files
- Cleans up old backups (7-day retention)

### Restore
```bash
./scripts/restore.sh <backup_file>
```
- Stops services safely
- Restores database
- Restores configurations
- Restarts services

## 📊 Monitoring & Observability

### Prometheus Metrics
- Keycloak performance metrics
- Database connection monitoring
- System resource usage
- Custom business metrics

### Grafana Dashboards
- Keycloak overview
- User authentication trends
- System performance
- Error rate monitoring

### Alerting Rules
- High error rates
- Performance degradation
- Resource exhaustion
- Security events

## 🔐 Security Features

### Network Security
- SSL/TLS encryption
- Security headers (HSTS, CSP, X-Frame-Options)
- Rate limiting on login attempts
- IP-based access controls

### Authentication Security
- Strong password policies
- TOTP 2FA support
- Brute force protection
- Session management

### Application Security
- OAuth 2.0 / OpenID Connect
- PKCE for mobile apps
- JWT token validation
- Role-based access control

## 🔌 API Integration Examples

### Node.js API
```bash
cd examples/nodejs-api
npm install
npm start
```

**Features:**
- JWT token verification
- Role-based endpoints
- JWKS integration
- Error handling

### Python API
```bash
cd examples/python-api
pip install -r requirements.txt
python app.py
```

**Features:**
- Flask-based API
- JWT verification with cryptography
- Role-based decorators
- Comprehensive error handling

### React Application
```bash
cd examples/react-app
npm install
npm start
```

**Features:**
- Keycloak JS adapter
- Material-UI components
- Role-based navigation
- Token refresh handling

## 🗄️ Database Schema

### PostgreSQL Configuration
- **Database**: keycloak
- **User**: keycloak
- **Connection Pooling**: Enabled
- **Backup**: Automated daily
- **Monitoring**: Connection metrics

## 📁 Directory Structure

```
Keycloak/
├── docker-compose.yml          # Main deployment configuration
├── env.example                 # Environment template
├── nginx/                      # Reverse proxy configuration
│   └── nginx.conf
├── monitoring/                 # Monitoring setup
│   ├── prometheus.yml
│   ├── keycloak_rules.yml
│   └── grafana/
├── scripts/                    # Management scripts
│   ├── deploy.sh
│   ├── backup.sh
│   └── restore.sh
├── examples/                   # Integration examples
│   ├── nodejs-api/
│   ├── python-api/
│   └── react-app/
├── ssl/                        # SSL certificates
├── logs/                       # Application logs
├── backups/                    # Backup storage
└── realms/                     # Realm configurations
```

## 🔄 Backup & Recovery

### Automated Backups
- Daily database dumps
- Realm configuration exports
- Configuration file archives
- 7-day retention policy

### Manual Backup
```bash
./scripts/backup.sh
```

### Restore from Backup
```bash
./scripts/restore.sh keycloak_backup_20241201_120000.tar.gz
```

## 🚨 Troubleshooting

### Common Issues

**1. SSL Certificate Errors**
```bash
# Regenerate certificates
rm ssl/server.*
./scripts/deploy.sh
```

**2. Database Connection Issues**
```bash
# Check PostgreSQL status
docker-compose logs postgres
```

**3. Keycloak Not Starting**
```bash
# Check logs
docker-compose logs keycloak
```

**4. Memory Issues**
```bash
# Increase Docker memory limit
# Check system resources
docker stats
```

### Health Checks

```bash
# Check all services
docker-compose ps

# Check Keycloak health
curl -k https://localhost:8443/health/ready

# Check database
docker-compose exec postgres pg_isready -U keycloak
```

## 📈 Performance Tuning

### Database Optimization
- Connection pooling configured
- Query optimization enabled
- Regular maintenance scheduled

### Keycloak Optimization
- JVM heap size tuning
- Cache configuration
- Session management optimization

### Nginx Optimization
- Gzip compression enabled
- Connection keep-alive
- Rate limiting configured

## 🔒 Security Best Practices

1. **Change Default Passwords**: Update all default credentials
2. **SSL Certificates**: Use proper certificates in production
3. **Network Security**: Configure firewall rules
4. **Regular Updates**: Keep all components updated
5. **Monitoring**: Set up alerting for security events
6. **Backup Security**: Encrypt backup files
7. **Access Control**: Limit admin access

## 📞 Support

For support and questions:
- **Documentation**: Check this README and inline comments
- **Logs**: Review application logs in `logs/` directory
- **Monitoring**: Use Grafana dashboards for system health
- **Backup**: Regular backups ensure quick recovery

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

---

**Centuries Mutual Keycloak Enterprise System** - Production-ready identity and access management solution.
