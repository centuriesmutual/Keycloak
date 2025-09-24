import React, { createContext, useContext, useState, useEffect } from 'react';
import Keycloak from 'keycloak-js';

const AuthContext = createContext();

// Keycloak configuration
const keycloakConfig = {
  url: process.env.REACT_APP_KEYCLOAK_URL || 'https://keycloak.centuriesmutual.com',
  realm: process.env.REACT_APP_KEYCLOAK_REALM || 'CenturiesMutual-Users',
  clientId: process.env.REACT_APP_KEYCLOAK_CLIENT_ID || 'home-ios',
};

export const AuthProvider = ({ children }) => {
  const [keycloak, setKeycloak] = useState(null);
  const [user, setUser] = useState(null);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const initKeycloak = async () => {
      try {
        const kc = new Keycloak(keycloakConfig);
        
        const authenticated = await kc.init({
          onLoad: 'check-sso',
          silentCheckSsoRedirectUri: window.location.origin + '/silent-check-sso.html',
          pkceMethod: 'S256'
        });

        setKeycloak(kc);
        setIsAuthenticated(authenticated);

        if (authenticated) {
          setUser(kc.tokenParsed);
        }

        setLoading(false);
      } catch (error) {
        console.error('Keycloak initialization failed:', error);
        setLoading(false);
      }
    };

    initKeycloak();
  }, []);

  const login = () => {
    if (keycloak) {
      keycloak.login();
    }
  };

  const logout = () => {
    if (keycloak) {
      keycloak.logout();
    }
  };

  const hasRole = (role) => {
    if (!keycloak || !isAuthenticated) return false;
    return keycloak.hasRealmRole(role);
  };

  const hasAnyRole = (roles) => {
    if (!keycloak || !isAuthenticated) return false;
    return roles.some(role => keycloak.hasRealmRole(role));
  };

  const getToken = () => {
    if (keycloak && isAuthenticated) {
      return keycloak.token;
    }
    return null;
  };

  const refreshToken = async () => {
    if (keycloak) {
      try {
        const refreshed = await keycloak.updateToken(30);
        if (refreshed) {
          setUser(keycloak.tokenParsed);
        }
        return refreshed;
      } catch (error) {
        console.error('Token refresh failed:', error);
        logout();
        return false;
      }
    }
    return false;
  };

  const value = {
    keycloak,
    user,
    isAuthenticated,
    loading,
    login,
    logout,
    hasRole,
    hasAnyRole,
    getToken,
    refreshToken
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
