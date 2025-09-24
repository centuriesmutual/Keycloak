# API Integration Guide - Centuries Mutual Keycloak

This guide provides comprehensive examples and best practices for integrating with the Centuries Mutual Keycloak system.

## 🔑 Authentication Flow Overview

The Centuries Mutual Keycloak system supports multiple authentication flows:

1. **Authorization Code Flow** (Web applications)
2. **PKCE Flow** (Mobile applications)
3. **Client Credentials Flow** (Service-to-service)
4. **Device Authorization Flow** (IoT devices)

## 📱 Mobile Application Integration

### iOS Swift Integration

```swift
import Foundation
import AuthenticationServices

class KeycloakAuthManager: NSObject, ObservableObject {
    @Published var isAuthenticated = false
    @Published var user: KeycloakUser?
    
    private let keycloakURL = "https://keycloak.centuriesmutual.com"
    private let realm = "CenturiesMutual-Users"
    private let clientId = "home-ios"
    
    func login() {
        let authURL = URL(string: "\(keycloakURL)/realms/\(realm)/protocol/openid-connect/auth")!
        
        var components = URLComponents(url: authURL, resolvingAgainstBaseURL: false)!
        components.queryItems = [
            URLQueryItem(name: "client_id", value: clientId),
            URLQueryItem(name: "response_type", value: "code"),
            URLQueryItem(name: "redirect_uri", value: "centuriesmutual://home/callback"),
            URLQueryItem(name: "scope", value: "openid profile email"),
            URLQueryItem(name: "code_challenge_method", value: "S256"),
            URLQueryItem(name: "code_challenge", value: generateCodeChallenge())
        ]
        
        let session = ASWebAuthenticationSession(
            url: components.url!,
            callbackURLScheme: "centuriesmutual"
        ) { [weak self] callbackURL, error in
            if let callbackURL = callbackURL {
                self?.handleCallback(url: callbackURL)
            }
        }
        
        session.presentationContextProvider = self
        session.start()
    }
    
    private func handleCallback(url: URL) {
        // Extract authorization code and exchange for tokens
        // Implementation details...
    }
}

struct KeycloakUser {
    let id: String
    let username: String
    let email: String
    let roles: [String]
}
```

### Android Kotlin Integration

```kotlin
import net.openid.appauth.*

class KeycloakAuthManager(private val context: Context) {
    private val keycloakURL = "https://keycloak.centuriesmutual.com"
    private val realm = "CenturiesMutual-Users"
    private val clientId = "home-ios"
    
    fun login() {
        val authRequest = AuthorizationRequest.Builder(
            AuthorizationServiceConfiguration(
                Uri.parse("$keycloakURL/realms/$realm/protocol/openid-connect/auth"),
                Uri.parse("$keycloakURL/realms/$realm/protocol/openid-connect/token")
            ),
            clientId,
            ResponseTypeValues.CODE,
            Uri.parse("centuriesmutual://home/callback")
        )
            .setScopes("openid", "profile", "email")
            .setCodeVerifier(CodeVerifierUtil.generateRandomCodeVerifier())
            .build()
        
        val authService = AuthorizationService(context)
        val intent = authService.getAuthorizationRequestIntent(authRequest)
        context.startActivity(intent)
    }
    
    fun handleAuthResponse(intent: Intent) {
        val authResponse = AuthorizationResponse.fromIntent(intent)
        val authException = AuthorizationException.fromIntent(intent)
        
        if (authResponse != null) {
            exchangeCodeForTokens(authResponse)
        }
    }
}
```

## 🌐 Web Application Integration

### React Integration

```javascript
import Keycloak from 'keycloak-js';

const keycloakConfig = {
  url: 'https://keycloak.centuriesmutual.com',
  realm: 'CenturiesMutual-Users',
  clientId: 'web-portal'
};

const keycloak = new Keycloak(keycloakConfig);

// Initialize Keycloak
keycloak.init({
  onLoad: 'check-sso',
  silentCheckSsoRedirectUri: window.location.origin + '/silent-check-sso.html',
  pkceMethod: 'S256'
}).then(authenticated => {
  if (authenticated) {
    console.log('User authenticated');
    // Make authenticated API calls
    makeAuthenticatedRequest();
  }
});

// Make authenticated API request
async function makeAuthenticatedRequest() {
  try {
    const response = await fetch('/api/protected', {
      headers: {
        'Authorization': `Bearer ${keycloak.token}`
      }
    });
    
    if (response.ok) {
      const data = await response.json();
      console.log('API Response:', data);
    }
  } catch (error) {
    console.error('API Error:', error);
  }
}

// Check user roles
function hasRole(role) {
  return keycloak.hasRealmRole(role);
}

// Check if user is premium
if (hasRole('premium_user')) {
  // Show premium features
  showPremiumFeatures();
}
```

### Angular Integration

```typescript
import { Injectable } from '@angular/core';
import Keycloak from 'keycloak-js';

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  private keycloak: Keycloak.KeycloakInstance;
  
  constructor() {
    this.keycloak = new Keycloak({
      url: 'https://keycloak.centuriesmutual.com',
      realm: 'CenturiesMutual-Users',
      clientId: 'angular-app'
    });
  }
  
  async init(): Promise<boolean> {
    try {
      const authenticated = await this.keycloak.init({
        onLoad: 'check-sso',
        silentCheckSsoRedirectUri: window.location.origin + '/silent-check-sso.html',
        pkceMethod: 'S256'
      });
      
      return authenticated;
    } catch (error) {
      console.error('Keycloak initialization failed:', error);
      return false;
    }
  }
  
  login(): void {
    this.keycloak.login();
  }
  
  logout(): void {
    this.keycloak.logout();
  }
  
  getToken(): string {
    return this.keycloak.token;
  }
  
  hasRole(role: string): boolean {
    return this.keycloak.hasRealmRole(role);
  }
  
  isPremiumUser(): boolean {
    return this.hasRole('premium_user');
  }
}

// HTTP Interceptor for adding tokens
@Injectable()
export class AuthInterceptor implements HttpInterceptor {
  constructor(private authService: AuthService) {}
  
  intercept(req: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
    const token = this.authService.getToken();
    
    if (token) {
      req = req.clone({
        setHeaders: {
          Authorization: `Bearer ${token}`
        }
      });
    }
    
    return next.handle(req);
  }
}
```

## 🔧 Backend API Integration

### Node.js Express API

```javascript
const express = require('express');
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');

const app = express();

// Keycloak configuration
const KEYCLOAK_URL = 'https://keycloak.centuriesmutual.com';
const REALM = 'CenturiesMutual-Users';
const CLIENT_ID = 'api-server';

// JWKS client for token verification
const client = jwksClient({
  jwksUri: `${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/certs`,
  cache: true,
  cacheMaxAge: 600000
});

// Get signing key
function getKey(header, callback) {
  client.getSigningKey(header.kid, (err, key) => {
    if (err) return callback(err);
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
      return res.status(401).json({ error: 'Invalid token' });
    }
    req.user = decoded;
    next();
  });
}

// Role-based middleware
function requireRole(role) {
  return (req, res, next) => {
    const userRoles = req.user.realm_access?.roles || [];
    if (!userRoles.includes(role)) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    next();
  };
}

// Protected routes
app.get('/api/premium', verifyToken, requireRole('premium_user'), (req, res) => {
  res.json({ message: 'Premium content', user: req.user.preferred_username });
});

app.get('/api/beta', verifyToken, requireRole('beta_tester'), (req, res) => {
  res.json({ message: 'Beta features', user: req.user.preferred_username });
});
```

### Python Flask API

```python
from flask import Flask, request, jsonify
from functools import wraps
import jwt
import requests
from cryptography.hazmat.primitives import serialization
import base64

app = Flask(__name__)

# Keycloak configuration
KEYCLOAK_URL = 'https://keycloak.centuriesmutual.com'
REALM = 'CenturiesMutual-Users'
CLIENT_ID = 'python-api'

# Cache for JWKS
jwks_cache = {}

def get_jwks():
    global jwks_cache
    if not jwks_cache:
        jwks_url = f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/certs"
        response = requests.get(jwks_url)
        jwks_cache = response.json()
    return jwks_cache

def get_signing_key(token):
    header = jwt.get_unverified_header(token)
    kid = header.get('kid')
    
    jwks = get_jwks()
    for key in jwks.get('keys', []):
        if key.get('kid') == kid:
            # Convert JWK to PEM (simplified)
            n = base64.urlsafe_b64decode(key['n'] + '==')
            e = base64.urlsafe_b64decode(key['e'] + '==')
            # ... key conversion logic
            return public_key_pem

def verify_token(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        
        if not token:
            return jsonify({'error': 'No token provided'}), 401
        
        try:
            signing_key = get_signing_key(token)
            payload = jwt.decode(
                token,
                signing_key,
                algorithms=['RS256'],
                audience=CLIENT_ID,
                issuer=f"{KEYCLOAK_URL}/realms/{REALM}"
            )
            request.user = payload
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        
        return f(*args, **kwargs)
    return decorated_function

def require_role(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user_roles = request.user.get('realm_access', {}).get('roles', [])
            if role not in user_roles:
                return jsonify({'error': 'Insufficient permissions'}), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/api/premium')
@verify_token
@require_role('premium_user')
def premium_endpoint():
    return jsonify({
        'message': 'Premium content',
        'user': request.user.get('preferred_username')
    })
```

## 🔐 Service-to-Service Authentication

### Client Credentials Flow

```javascript
// Service authentication
async function getServiceToken() {
  const tokenEndpoint = 'https://keycloak.centuriesmutual.com/realms/CenturiesMutual-Staff/protocol/openid-connect/token';
  
  const response = await fetch(tokenEndpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    body: new URLSearchParams({
      grant_type: 'client_credentials',
      client_id: 'api-service',
      client_secret: 'your-client-secret'
    })
  });
  
  const data = await response.json();
  return data.access_token;
}

// Use service token
async function callProtectedService() {
  const token = await getServiceToken();
  
  const response = await fetch('/api/admin/users', {
    headers: {
      'Authorization': `Bearer ${token}`
    }
  });
  
  return response.json();
}
```

## 📊 User Management API

### Create User

```javascript
async function createUser(userData) {
  const adminToken = await getAdminToken();
  
  const response = await fetch('https://keycloak.centuriesmutual.com/admin/realms/CenturiesMutual-Users/users', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${adminToken}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      username: userData.username,
      email: userData.email,
      firstName: userData.firstName,
      lastName: userData.lastName,
      enabled: true,
      credentials: [{
        type: 'password',
        value: userData.password,
        temporary: false
      }],
      realmRoles: userData.roles
    })
  });
  
  return response.ok;
}
```

### Assign Roles

```javascript
async function assignRole(userId, roleName) {
  const adminToken = await getAdminToken();
  
  // Get role details
  const roleResponse = await fetch(`https://keycloak.centuriesmutual.com/admin/realms/CenturiesMutual-Users/roles/${roleName}`);
  const role = await roleResponse.json();
  
  // Assign role to user
  const response = await fetch(`https://keycloak.centuriesmutual.com/admin/realms/CenturiesMutual-Users/users/${userId}/role-mappings/realm`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${adminToken}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify([role])
  });
  
  return response.ok;
}
```

## 🔄 Token Refresh

### Automatic Token Refresh

```javascript
class TokenManager {
  constructor(keycloak) {
    this.keycloak = keycloak;
    this.refreshInterval = null;
  }
  
  startAutoRefresh() {
    this.refreshInterval = setInterval(async () => {
      try {
        const refreshed = await this.keycloak.updateToken(30);
        if (refreshed) {
          console.log('Token refreshed');
          // Update stored token
          localStorage.setItem('access_token', this.keycloak.token);
        }
      } catch (error) {
        console.error('Token refresh failed:', error);
        this.keycloak.logout();
      }
    }, 30000); // Check every 30 seconds
  }
  
  stopAutoRefresh() {
    if (this.refreshInterval) {
      clearInterval(this.refreshInterval);
    }
  }
}
```

## 🛡️ Security Best Practices

### 1. Token Storage
```javascript
// Secure token storage
class SecureTokenStorage {
  static setToken(token) {
    // Use httpOnly cookies in production
    document.cookie = `access_token=${token}; secure; samesite=strict`;
  }
  
  static getToken() {
    return document.cookie
      .split('; ')
      .find(row => row.startsWith('access_token='))
      ?.split('=')[1];
  }
  
  static removeToken() {
    document.cookie = 'access_token=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';
  }
}
```

### 2. CSRF Protection
```javascript
// CSRF token handling
function getCSRFToken() {
  return document.querySelector('meta[name="csrf-token"]')?.getAttribute('content');
}

function makeAuthenticatedRequest(url, options = {}) {
  return fetch(url, {
    ...options,
    headers: {
      ...options.headers,
      'X-CSRF-Token': getCSRFToken(),
      'Authorization': `Bearer ${getToken()}`
    }
  });
}
```

### 3. Error Handling
```javascript
// Comprehensive error handling
async function handleApiError(response) {
  if (response.status === 401) {
    // Token expired or invalid
    await keycloak.logout();
    return;
  }
  
  if (response.status === 403) {
    // Insufficient permissions
    showError('You do not have permission to access this resource');
    return;
  }
  
  if (response.status >= 500) {
    // Server error
    showError('Server error. Please try again later.');
    return;
  }
  
  const error = await response.json();
  showError(error.message || 'An error occurred');
}
```

## 📱 Mobile App Deep Linking

### iOS URL Scheme Handling

```swift
// AppDelegate.swift
func application(_ app: UIApplication, open url: URL, options: [UIApplication.OpenURLOptionsKey : Any] = [:]) -> Bool {
    if url.scheme == "centuriesmutual" && url.host == "home" {
        handleKeycloakCallback(url: url)
        return true
    }
    return false
}

private func handleKeycloakCallback(url: URL) {
    // Extract authorization code from URL
    let components = URLComponents(url: url, resolvingAgainstBaseURL: false)
    if let code = components?.queryItems?.first(where: { $0.name == "code" })?.value {
        exchangeCodeForTokens(code: code)
    }
}
```

### Android Intent Filter

```xml
<!-- AndroidManifest.xml -->
<activity
    android:name=".MainActivity"
    android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data android:scheme="centuriesmutual"
              android:host="home" />
    </intent-filter>
</activity>
```

## 🧪 Testing Integration

### Unit Tests

```javascript
// Jest test example
describe('Keycloak Integration', () => {
  test('should authenticate user with valid credentials', async () => {
    const mockToken = 'mock-jwt-token';
    const mockUser = { preferred_username: 'testuser' };
    
    // Mock Keycloak
    const mockKeycloak = {
      init: jest.fn().mockResolvedValue(true),
      token: mockToken,
      tokenParsed: mockUser,
      hasRealmRole: jest.fn().mockReturnValue(true)
    };
    
    const authService = new AuthService(mockKeycloak);
    const isAuthenticated = await authService.init();
    
    expect(isAuthenticated).toBe(true);
    expect(authService.getUser()).toEqual(mockUser);
  });
});
```

### Integration Tests

```javascript
// API integration test
describe('Protected API Endpoints', () => {
  test('should access premium endpoint with premium role', async () => {
    const token = await getTestToken('premium_user');
    
    const response = await fetch('/api/premium', {
      headers: {
        'Authorization': `Bearer ${token}`
      }
    });
    
    expect(response.status).toBe(200);
    const data = await response.json();
    expect(data.message).toBe('Premium content');
  });
});
```

## 📚 Additional Resources

### Keycloak Documentation
- [Keycloak Documentation](https://www.keycloak.org/documentation)
- [OpenID Connect Specification](https://openid.net/connect/)
- [OAuth 2.0 Specification](https://tools.ietf.org/html/rfc6749)

### SDKs and Libraries
- [Keycloak JavaScript Adapter](https://www.keycloak.org/docs/latest/securing_apps/#_javascript_adapter)
- [OpenID Connect Libraries](https://openid.net/developers/libraries/)
- [JWT Libraries](https://jwt.io/libraries)

### Security Guidelines
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [OAuth 2.0 Security Best Practices](https://tools.ietf.org/html/draft-ietf-oauth-security-topics)

---

This integration guide provides comprehensive examples for integrating with the Centuries Mutual Keycloak system across all platforms and use cases.
