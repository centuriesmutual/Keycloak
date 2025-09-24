const express = require('express');
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');
const cors = require('cors');
const helmet = require('helmet');

const app = express();
const PORT = process.env.PORT || 3001;

// Keycloak configuration
const KEYCLOAK_URL = process.env.KEYCLOAK_URL || 'https://keycloak.centuriesmutual.com';
const REALM = process.env.KEYCLOAK_REALM || 'CenturiesMutual-Users';
const CLIENT_ID = process.env.KEYCLOAK_CLIENT_ID || 'home-ios';

// JWKS client for token verification
const client = jwksClient({
  jwksUri: `${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/certs`,
  cache: true,
  cacheMaxAge: 600000, // 10 minutes
  rateLimit: true,
  jwksRequestsPerMinute: 5,
  jwksUri: `${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/certs`
});

// Middleware
app.use(helmet());
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'],
  credentials: true
}));
app.use(express.json());

// Get signing key for JWT verification
function getKey(header, callback) {
  client.getSigningKey(header.kid, (err, key) => {
    if (err) {
      return callback(err);
    }
    const signingKey = key.publicKey || key.rsaPublicKey;
    callback(null, signingKey);
  });
}

// JWT verification middleware
function verifyToken(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  
  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  jwt.verify(token, getKey, {
    audience: CLIENT_ID,
    issuer: `${KEYCLOAK_URL}/realms/${REALM}`,
    algorithms: ['RS256']
  }, (err, decoded) => {
    if (err) {
      console.error('Token verification failed:', err);
      return res.status(401).json({ error: 'Invalid token' });
    }
    
    req.user = decoded;
    next();
  });
}

// Role-based access control middleware
function requireRole(role) {
  return (req, res, next) => {
    const userRoles = req.user.realm_access?.roles || [];
    
    if (!userRoles.includes(role)) {
      return res.status(403).json({ 
        error: 'Insufficient permissions',
        required: role,
        userRoles: userRoles
      });
    }
    
    next();
  };
}

// Routes

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'healthy', timestamp: new Date().toISOString() });
});

// Public endpoint
app.get('/api/public', (req, res) => {
  res.json({ 
    message: 'This is a public endpoint',
    timestamp: new Date().toISOString()
  });
});

// Protected endpoint - requires authentication
app.get('/api/protected', verifyToken, (req, res) => {
  res.json({
    message: 'This is a protected endpoint',
    user: {
      sub: req.user.sub,
      preferred_username: req.user.preferred_username,
      email: req.user.email,
      roles: req.user.realm_access?.roles || []
    },
    timestamp: new Date().toISOString()
  });
});

// Premium endpoint - requires premium_user role
app.get('/api/premium', verifyToken, requireRole('premium_user'), (req, res) => {
  res.json({
    message: 'This is a premium endpoint',
    user: req.user.preferred_username,
    features: [
      'Advanced analytics',
      'Priority support',
      'Custom themes',
      'API access'
    ],
    timestamp: new Date().toISOString()
  });
});

// Beta features endpoint - requires beta_tester role
app.get('/api/beta', verifyToken, requireRole('beta_tester'), (req, res) => {
  res.json({
    message: 'This is a beta features endpoint',
    user: req.user.preferred_username,
    betaFeatures: [
      'Experimental UI',
      'New authentication flows',
      'Advanced reporting',
      'AI-powered insights'
    ],
    timestamp: new Date().toISOString()
  });
});

// User profile endpoint
app.get('/api/profile', verifyToken, (req, res) => {
  res.json({
    profile: {
      id: req.user.sub,
      username: req.user.preferred_username,
      email: req.user.email,
      firstName: req.user.given_name,
      lastName: req.user.family_name,
      roles: req.user.realm_access?.roles || [],
      groups: req.user.groups || [],
      emailVerified: req.user.email_verified
    },
    timestamp: new Date().toISOString()
  });
});

// Admin endpoint - requires admin role (for staff realm)
app.get('/api/admin/users', verifyToken, requireRole('admin'), (req, res) => {
  res.json({
    message: 'Admin endpoint - user management',
    users: [
      { id: 1, username: 'john.doe', email: 'john.doe@centuriesmutual.com', role: 'basic_user' },
      { id: 2, username: 'jane.premium', email: 'jane.premium@centuriesmutual.com', role: 'premium_user' },
      { id: 3, username: 'bob.tester', email: 'bob.tester@centuriesmutual.com', role: 'beta_tester' }
    ],
    timestamp: new Date().toISOString()
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(500).json({ 
    error: 'Internal server error',
    message: process.env.NODE_ENV === 'development' ? err.message : 'Something went wrong'
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

// Start server
app.listen(PORT, () => {
  console.log(`Centuries Mutual API server running on port ${PORT}`);
  console.log(`Keycloak URL: ${KEYCLOAK_URL}`);
  console.log(`Realm: ${REALM}`);
  console.log(`Client ID: ${CLIENT_ID}`);
});

module.exports = app;
