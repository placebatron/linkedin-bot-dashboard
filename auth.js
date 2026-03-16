/**
 * auth.js — BaumAgents Shared Authentication Module
 * Microsoft Entra ID (Azure AD) SSO via MSAL.js 2.x
 * Authorization Code + PKCE flow (SPA)
 *
 * Include this file on every page. It exposes:
 *   BaumAuth.init()         — initialize MSAL, handle redirect callback, return user or null
 *   BaumAuth.login()        — trigger interactive login (redirect)
 *   BaumAuth.logout()       — sign out and redirect to index.html
 *   BaumAuth.getUser()      — returns cached user object or null
 *   BaumAuth.getToken()     — returns current access token (for API calls to Workers)
 *   BaumAuth.isAdmin()      — true if user is in BaumAgents-Admins group
 *   BaumAuth.isBroker()     — true if user is in BaumAgents-Brokers group
 *   BaumAuth.hasLeasing()   — true if user is in BaumAgents-LeasingAccess group
 *   BaumAuth.hasGroup(id)   — true if user is in the specified group
 *   BaumAuth.requireAuth()  — convenience: init + redirect to login if not signed in
 *   BaumAuth.onReady(cb)    — register callback for when auth state is resolved
 */

(function (global) {
  'use strict';

  // ── Entra Configuration ──
  const CONFIG = {
    clientId: 'a56207ef-72d0-4d3f-9d00-3d5121e6c15d',
    tenantId: '4f69d2fb-f3d3-4cd8-8387-0a535355170b',
    redirectUri: 'https://baumagents.com/index.html',
    scopes: ['openid', 'profile', 'email'],
    groups: {
      admins:  '77847c26-7281-456d-a064-57b53481022f',
      brokers: '2771698b-ee50-4198-8c45-74e5d1f64690',
      leasing: '8875efd3-d6fc-46cf-a49b-1b7ebc60e917'
    }
  };

  const AUTHORITY = `https://login.microsoftonline.com/${CONFIG.tenantId}`;

  // ── State ──
  let msalInstance = null;
  let currentUser = null;   // { name, email, groups[], accountId, idToken }
  let readyCallbacks = [];
  let isReady = false;
  let initPromise = null;   // guards against double-init (MSAL throws on 2nd handleRedirectPromise)

  // ── MSAL Instance Creation ──
  function createMsalInstance() {
    if (typeof msal === 'undefined' || !msal.PublicClientApplication) {
      throw new Error('MSAL.js not loaded. Include the MSAL browser script before auth.js');
    }
    const msalConfig = {
      auth: {
        clientId: CONFIG.clientId,
        authority: AUTHORITY,
        redirectUri: CONFIG.redirectUri,
        navigateToLoginRequestUrl: true
      },
      cache: {
        cacheLocation: 'sessionStorage',
        storeAuthStateInCookie: false
      },
      system: {
        loggerOptions: {
          logLevel: msal.LogLevel ? msal.LogLevel.Warning : 2
        }
      }
    };
    return new msal.PublicClientApplication(msalConfig);
  }

  // ── Parse user from MSAL account + ID token claims ──
  function parseUser(account) {
    if (!account) return null;
    const claims = account.idTokenClaims || {};
    const groups = claims.groups || [];
    return {
      name: account.name || claims.name || '',
      email: (account.username || claims.preferred_username || claims.email || '').toLowerCase(),
      groups: groups,
      accountId: account.homeAccountId,
      idToken: account.idToken || null,
      // convenience flags
      isAdmin: groups.includes(CONFIG.groups.admins),
      isBroker: groups.includes(CONFIG.groups.brokers),
      hasLeasing: groups.includes(CONFIG.groups.leasing)
    };
  }

  // ── Fire ready callbacks ──
  function fireReady() {
    isReady = true;
    readyCallbacks.forEach(function (cb) {
      try { cb(currentUser); } catch (e) { console.error('[BaumAuth] onReady callback error:', e); }
    });
    readyCallbacks = [];
  }

  // ── Public API ──
  const BaumAuth = {

    /**
     * Initialize MSAL, handle any redirect response, resolve current user.
     * Returns a promise that resolves to the user object or null.
     */
    init: async function () {
      // Idempotent — return cached promise if already initializing/initialized
      if (initPromise) return initPromise;
      initPromise = BaumAuth._doInit();
      return initPromise;
    },

    _doInit: async function () {
      try {
        msalInstance = createMsalInstance();

        // Handle redirect callback (returns AuthenticationResult or null)
        const response = await msalInstance.handleRedirectPromise();

        if (response && response.account) {
          // Just came back from login redirect
          msalInstance.setActiveAccount(response.account);
          currentUser = parseUser(response.account);
        } else {
          // Check for existing session
          const accounts = msalInstance.getAllAccounts();
          if (accounts.length > 0) {
            // Filter to our tenant
            const tenantAccount = accounts.find(function (a) {
              return a.tenantId === CONFIG.tenantId;
            }) || accounts[0];
            msalInstance.setActiveAccount(tenantAccount);
            currentUser = parseUser(tenantAccount);
          }
        }

        // If we have a user, try silent token acquisition to ensure token is fresh
        // and to get the latest group claims
        if (currentUser) {
          try {
            const silentResult = await msalInstance.acquireTokenSilent({
              scopes: CONFIG.scopes,
              account: msalInstance.getActiveAccount()
            });
            if (silentResult && silentResult.account) {
              currentUser = parseUser(silentResult.account);
              currentUser.idToken = silentResult.idToken;
            }
          } catch (silentErr) {
            // Silent refresh failed — token might be expired.
            // User is still "known" but may need interactive re-auth for API calls.
            console.warn('[BaumAuth] Silent token refresh failed:', silentErr.message);
          }
        }

        fireReady();
        return currentUser;

      } catch (err) {
        console.error('[BaumAuth] Init error:', err);
        fireReady();
        return null;
      }
    },

    /**
     * Trigger interactive login via redirect.
     * After login, user lands back on redirectUri and init() picks up the response.
     */
    login: function () {
      if (!msalInstance) {
        console.error('[BaumAuth] Call init() before login()');
        return;
      }
      msalInstance.loginRedirect({
        scopes: CONFIG.scopes
      });
    },

    /**
     * Trigger interactive login via popup (fallback for token refresh).
     * Returns promise resolving to user object or null.
     */
    loginPopup: async function () {
      if (!msalInstance) {
        console.error('[BaumAuth] Call init() before loginPopup()');
        return null;
      }
      try {
        const response = await msalInstance.loginPopup({
          scopes: CONFIG.scopes
        });
        if (response && response.account) {
          msalInstance.setActiveAccount(response.account);
          currentUser = parseUser(response.account);
          currentUser.idToken = response.idToken;
        }
        return currentUser;
      } catch (err) {
        console.error('[BaumAuth] Popup login error:', err);
        return null;
      }
    },

    /**
     * Sign out — clears MSAL cache, redirects to index.html.
     */
    logout: function () {
      if (!msalInstance) {
        window.location.href = 'index.html';
        return;
      }
      const account = msalInstance.getActiveAccount();
      msalInstance.logoutRedirect({
        account: account,
        postLogoutRedirectUri: 'https://baumagents.com/index.html'
      });
    },

    /**
     * Get current authenticated user (synchronous, returns cached value).
     */
    getUser: function () {
      return currentUser;
    },

    /**
     * Get a valid ID token for API calls.
     * Tries silent acquisition first, falls back to popup.
     */
    getToken: async function () {
      if (!msalInstance || !currentUser) return null;
      try {
        const result = await msalInstance.acquireTokenSilent({
          scopes: CONFIG.scopes,
          account: msalInstance.getActiveAccount()
        });
        currentUser.idToken = result.idToken;
        return result.idToken;
      } catch (err) {
        // Silent failed — try popup
        console.warn('[BaumAuth] Silent token acquisition failed, trying popup...');
        try {
          const result = await msalInstance.acquireTokenPopup({
            scopes: CONFIG.scopes
          });
          currentUser.idToken = result.idToken;
          return result.idToken;
        } catch (popupErr) {
          console.error('[BaumAuth] Token acquisition failed:', popupErr);
          return null;
        }
      }
    },

    // ── Group checks ──
    isAdmin: function ()    { return currentUser ? currentUser.isAdmin : false; },
    isBroker: function ()   { return currentUser ? currentUser.isBroker : false; },
    hasLeasing: function () { return currentUser ? currentUser.hasLeasing : false; },
    hasGroup: function (groupId) {
      return currentUser ? currentUser.groups.includes(groupId) : false;
    },

    /**
     * Convenience: init + redirect to login if not signed in.
     * Use on pages that require authentication.
     */
    requireAuth: async function () {
      const user = await BaumAuth.init();
      if (!user) {
        BaumAuth.login();
        return null;
      }
      return user;
    },

    /**
     * Register a callback for when auth state is resolved.
     * If already resolved, fires immediately.
     */
    onReady: function (cb) {
      if (isReady) {
        try { cb(currentUser); } catch (e) { console.error('[BaumAuth] onReady error:', e); }
      } else {
        readyCallbacks.push(cb);
      }
    },

    /**
     * Expose config for admin panel / debugging.
     */
    getConfig: function () {
      return {
        clientId: CONFIG.clientId,
        tenantId: CONFIG.tenantId,
        groups: Object.assign({}, CONFIG.groups)
      };
    }
  };

  global.BaumAuth = BaumAuth;

})(window);
