#!/usr/bin/env python3
"""
Centuries Mutual API with Keycloak Integration
Python Flask API with JWT token verification
"""

import os
import jwt
import requests
from functools import wraps
from flask import Flask, request, jsonify
from flask_cors import CORS
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

# Keycloak configuration
KEYCLOAK_URL = os.getenv('KEYCLOAK_URL', 'https://keycloak.centuriesmutual.com')
REALM = os.getenv('KEYCLOAK_REALM', 'CenturiesMutual-Users')
CLIENT_ID = os.getenv('KEYCLOAK_CLIENT_ID', 'home-ios')

# Cache for JWKS
jwks_cache = {}

def get_jwks():
    """Get JSON Web Key Set from Keycloak"""
    global jwks_cache
    
    if not jwks_cache:
        try:
            jwks_url = f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/certs"
            response = requests.get(jwks_url, timeout=10)
            response.raise_for_status()
            jwks_cache = response.json()
            logger.info("JWKS loaded successfully")
        except Exception as e:
            logger.error(f"Failed to load JWKS: {e}")
            raise
    
    return jwks_cache

def get_signing_key(token):
    """Get the signing key for JWT verification"""
    try:
        # Decode header without verification to get kid
        header = jwt.get_unverified_header(token)
        kid = header.get('kid')
        
        if not kid:
            raise ValueError("No 'kid' in token header")
        
        # Get JWKS
        jwks = get_jwks()
        
        # Find the key with matching kid
        for key in jwks.get('keys', []):
            if key.get('kid') == kid:
                # Convert JWK to PEM format
                from cryptography.hazmat.primitives import serialization
                from cryptography.hazmat.primitives.asymmetric import rsa
                import base64
                
                # Extract RSA components
                n = base64.urlsafe_b64decode(key['n'] + '==')
                e = base64.urlsafe_b64decode(key['e'] + '==')
                
                # Convert to integers
                n_int = int.from_bytes(n, 'big')
                e_int = int.from_bytes(e, 'big')
                
                # Create RSA public key
                public_key = rsa.RSAPublicNumbers(e_int, n_int).public_key()
                
                # Serialize to PEM
                pem = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                
                return pem
        
        raise ValueError(f"Key with kid '{kid}' not found")
        
    except Exception as e:
        logger.error(f"Failed to get signing key: {e}")
        raise

def verify_token(f):
    """Decorator to verify JWT token"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = None
        
        # Get token from Authorization header
        auth_header = request.headers.get('Authorization')
        if auth_header:
            try:
                token = auth_header.split(' ')[1]  # Bearer <token>
            except IndexError:
                return jsonify({'error': 'Invalid authorization header format'}), 401
        
        if not token:
            return jsonify({'error': 'No token provided'}), 401
        
        try:
            # Get signing key
            signing_key = get_signing_key(token)
            
            # Verify token
            payload = jwt.decode(
                token,
                signing_key,
                algorithms=['RS256'],
                audience=CLIENT_ID,
                issuer=f"{KEYCLOAK_URL}/realms/{REALM}"
            )
            
            # Add user info to request context
            request.user = payload
            
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired'}), 401
        except jwt.InvalidTokenError as e:
            logger.error(f"Invalid token: {e}")
            return jsonify({'error': 'Invalid token'}), 401
        except Exception as e:
            logger.error(f"Token verification error: {e}")
            return jsonify({'error': 'Token verification failed'}), 401
        
        return f(*args, **kwargs)
    
    return decorated_function

def require_role(role):
    """Decorator to require specific role"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user_roles = request.user.get('realm_access', {}).get('roles', [])
            
            if role not in user_roles:
                return jsonify({
                    'error': 'Insufficient permissions',
                    'required': role,
                    'user_roles': user_roles
                }), 403
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Routes

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': str(datetime.utcnow().isoformat())
    })

@app.route('/api/public', methods=['GET'])
def public_endpoint():
    """Public endpoint - no authentication required"""
    return jsonify({
        'message': 'This is a public endpoint',
        'timestamp': str(datetime.utcnow().isoformat())
    })

@app.route('/api/protected', methods=['GET'])
@verify_token
def protected_endpoint():
    """Protected endpoint - requires authentication"""
    return jsonify({
        'message': 'This is a protected endpoint',
        'user': {
            'sub': request.user.get('sub'),
            'preferred_username': request.user.get('preferred_username'),
            'email': request.user.get('email'),
            'roles': request.user.get('realm_access', {}).get('roles', [])
        },
        'timestamp': str(datetime.utcnow().isoformat())
    })

@app.route('/api/premium', methods=['GET'])
@verify_token
@require_role('premium_user')
def premium_endpoint():
    """Premium endpoint - requires premium_user role"""
    return jsonify({
        'message': 'This is a premium endpoint',
        'user': request.user.get('preferred_username'),
        'features': [
            'Advanced analytics',
            'Priority support',
            'Custom themes',
            'API access'
        ],
        'timestamp': str(datetime.utcnow().isoformat())
    })

@app.route('/api/beta', methods=['GET'])
@verify_token
@require_role('beta_tester')
def beta_endpoint():
    """Beta features endpoint - requires beta_tester role"""
    return jsonify({
        'message': 'This is a beta features endpoint',
        'user': request.user.get('preferred_username'),
        'beta_features': [
            'Experimental UI',
            'New authentication flows',
            'Advanced reporting',
            'AI-powered insights'
        ],
        'timestamp': str(datetime.utcnow().isoformat())
    })

@app.route('/api/profile', methods=['GET'])
@verify_token
def user_profile():
    """Get user profile information"""
    return jsonify({
        'profile': {
            'id': request.user.get('sub'),
            'username': request.user.get('preferred_username'),
            'email': request.user.get('email'),
            'first_name': request.user.get('given_name'),
            'last_name': request.user.get('family_name'),
            'roles': request.user.get('realm_access', {}).get('roles', []),
            'groups': request.user.get('groups', []),
            'email_verified': request.user.get('email_verified')
        },
        'timestamp': str(datetime.utcnow().isoformat())
    })

@app.route('/api/admin/users', methods=['GET'])
@verify_token
@require_role('admin')
def admin_users():
    """Admin endpoint - requires admin role (for staff realm)"""
    return jsonify({
        'message': 'Admin endpoint - user management',
        'users': [
            {'id': 1, 'username': 'john.doe', 'email': 'john.doe@centuriesmutual.com', 'role': 'basic_user'},
            {'id': 2, 'username': 'jane.premium', 'email': 'jane.premium@centuriesmutual.com', 'role': 'premium_user'},
            {'id': 3, 'username': 'bob.tester', 'email': 'bob.tester@centuriesmutual.com', 'role': 'beta_tester'}
        ],
        'timestamp': str(datetime.utcnow().isoformat())
    })

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal server error: {error}")
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    from datetime import datetime
    
    port = int(os.getenv('PORT', 5001))
    debug = os.getenv('FLASK_ENV') == 'development'
    
    logger.info(f"Starting Centuries Mutual API server on port {port}")
    logger.info(f"Keycloak URL: {KEYCLOAK_URL}")
    logger.info(f"Realm: {REALM}")
    logger.info(f"Client ID: {CLIENT_ID}")
    
    app.run(host='0.0.0.0', port=port, debug=debug)
