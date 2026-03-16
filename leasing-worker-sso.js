// ── Leasing Reports API Worker (SSO Edition) ─────────────────
// Cloudflare Worker + KV persistence for BaumAgents Leasing Reports
// KV Bindings: LEASING_KV, JWKS_CACHE
// Now validates Microsoft Entra ID JWT tokens instead of shared passphrase

const ALLOWED_ORIGINS = [
  'https://baumagents.com',
  'https://placebatron.github.io',
  'http://localhost:8080'
];

// Entra SSO configuration
const ENTRA_TENANT_ID = '4f69d2fb-f3d3-4cd8-8387-0a535355170b';
const ENTRA_CLIENT_ID = 'a56207ef-72d0-4d3f-9d00-3d5121e6c15d';
const ENTRA_ISSUER = `https://login.microsoftonline.com/${ENTRA_TENANT_ID}/v2.0`;
const ENTRA_JWKS_URI = `https://login.microsoftonline.com/${ENTRA_TENANT_ID}/discovery/v2.0/keys`;

// JWKS cache TTL (4 hours)
const JWKS_CACHE_TTL = 4 * 60 * 60;

function corsHeaders(request) {
  const origin = request.headers.get('Origin') || '';
  const allowed = ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0];
  return {
    'Access-Control-Allow-Origin': allowed,
    'Access-Control-Allow-Methods': 'GET, PUT, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '86400'
  };
}

function jsonResponse(data, status, request) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...corsHeaders(request) }
  });
}

// ── JWT Validation ────────────────────────────────────────────

// Base64URL decode
function base64UrlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return Uint8Array.from(atob(str), c => c.charCodeAt(0));
}

// Fetch and cache JWKS from Microsoft
async function getJWKS(env) {
  // Try KV cache first
  if (env.LEASING_KV) {
    try {
      const cached = await env.LEASING_KV.get('_jwks_cache', { type: 'json' });
      if (cached && cached.keys && cached.cachedAt && (Date.now() / 1000 - cached.cachedAt) < JWKS_CACHE_TTL) {
        return cached.keys;
      }
    } catch (e) { /* cache miss, fetch fresh */ }
  }

  const res = await fetch(ENTRA_JWKS_URI);
  if (!res.ok) throw new Error('Failed to fetch JWKS');
  const jwks = await res.json();

  // Cache in KV
  if (env.LEASING_KV) {
    try {
      await env.LEASING_KV.put('_jwks_cache', JSON.stringify({
        keys: jwks.keys,
        cachedAt: Math.floor(Date.now() / 1000)
      }));
    } catch (e) { /* non-fatal */ }
  }

  return jwks.keys;
}

// Import a JWK as a CryptoKey for verification
async function importJWK(jwk) {
  return crypto.subtle.importKey(
    'jwk',
    { kty: jwk.kty, n: jwk.n, e: jwk.e },
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['verify']
  );
}

// Validate an Entra ID token
async function validateToken(token, env) {
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('Invalid JWT format');

  // Decode header to get kid
  const header = JSON.parse(new TextDecoder().decode(base64UrlDecode(parts[0])));
  if (!header.kid) throw new Error('Missing kid in JWT header');

  // Get matching key from JWKS
  const keys = await getJWKS(env);
  const jwk = keys.find(k => k.kid === header.kid);
  if (!jwk) throw new Error('No matching key found in JWKS');

  // Verify signature
  const cryptoKey = await importJWK(jwk);
  const data = new TextEncoder().encode(parts[0] + '.' + parts[1]);
  const signature = base64UrlDecode(parts[2]);
  const valid = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', cryptoKey, signature, data);
  if (!valid) throw new Error('Invalid JWT signature');

  // Decode and validate claims
  const claims = JSON.parse(new TextDecoder().decode(base64UrlDecode(parts[1])));

  // Check expiration
  const now = Math.floor(Date.now() / 1000);
  if (claims.exp && claims.exp < now) throw new Error('Token expired');

  // Check not-before
  if (claims.nbf && claims.nbf > now + 60) throw new Error('Token not yet valid');

  // Check issuer
  if (claims.iss !== ENTRA_ISSUER) throw new Error('Invalid issuer: ' + claims.iss);

  // Check audience
  if (claims.aud !== ENTRA_CLIENT_ID) throw new Error('Invalid audience: ' + claims.aud);

  return claims;
}

// ── Main Handler ──────────────────────────────────────────────

export default {
  async fetch(request, env) {
    // CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(request) });
    }

    // Health check (no auth required)
    const url = new URL(request.url);
    if (request.method === 'GET' && (url.pathname === '/' || url.pathname === '/health')) {
      return jsonResponse({ status: 'ok', service: 'leasing-api', auth: 'entra-sso' }, 200, request);
    }

    // Auth check — validate Entra JWT
    const authHeader = request.headers.get('Authorization') || '';
    const token = authHeader.replace('Bearer ', '').trim();
    if (!token) {
      return jsonResponse({ error: 'Unauthorized — no token provided' }, 401, request);
    }

    let claims;
    try {
      claims = await validateToken(token, env);
    } catch (err) {
      return jsonResponse({ error: 'Unauthorized — ' + err.message }, 401, request);
    }

    const path = url.pathname;

    try {
      // GET /data/:key — Read from KV
      if (request.method === 'GET' && path.startsWith('/data/')) {
        const key = decodeURIComponent(path.slice(6));
        if (!key) return jsonResponse({ error: 'Key required' }, 400, request);

        const value = await env.LEASING_KV.get(key);
        if (value === null) {
          return jsonResponse({ data: null }, 200, request);
        }
        return jsonResponse({ data: JSON.parse(value) }, 200, request);
      }

      // PUT /data/:key — Write to KV
      if (request.method === 'PUT' && path.startsWith('/data/')) {
        const key = decodeURIComponent(path.slice(6));
        if (!key) return jsonResponse({ error: 'Key required' }, 400, request);

        const body = await request.json();
        await env.LEASING_KV.put(key, JSON.stringify(body.data));
        return jsonResponse({ success: true, user: claims.preferred_username }, 200, request);
      }

      // POST /migrate — Bulk write from localStorage to KV
      if (request.method === 'POST' && path === '/migrate') {
        const body = await request.json();
        const writes = [];

        if (body.brokers) {
          writes.push(env.LEASING_KV.put('leasingBrokers', JSON.stringify(body.brokers)));
        }

        if (body.brokerData) {
          for (const [bid, data] of Object.entries(body.brokerData)) {
            if (data.properties) writes.push(env.LEASING_KV.put('leasing_' + bid + '_properties', JSON.stringify(data.properties)));
            if (data.prospects)  writes.push(env.LEASING_KV.put('leasing_' + bid + '_prospects',  JSON.stringify(data.prospects)));
            if (data.snapshots)  writes.push(env.LEASING_KV.put('leasing_' + bid + '_snapshots',  JSON.stringify(data.snapshots)));
            if (data.settings)   writes.push(env.LEASING_KV.put('leasing_' + bid + '_settings',   JSON.stringify(data.settings)));
          }
        }

        await Promise.all(writes);
        return jsonResponse({ success: true, synced: true, keysWritten: writes.length, user: claims.preferred_username }, 200, request);
      }

      return jsonResponse({ error: 'Not found' }, 404, request);

    } catch (err) {
      return jsonResponse({ error: 'Internal error', message: err.message }, 500, request);
    }
  }
};
