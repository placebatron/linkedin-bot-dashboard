// ── Voss Email Rewriter Proxy Worker (SSO Edition) ────────────
// Cloudflare Worker that proxies Anthropic API calls for the Voss Email Rewriter
// Now validates Microsoft Entra ID JWT tokens instead of shared passphrase
// Environment variable required: ANTHROPIC_API_KEY

const ALLOWED_ORIGINS = [
  'https://baumagents.com',
  'https://placebatron.github.io',
  'http://localhost:8080'
];

const ANTHROPIC_API_URL = 'https://api.anthropic.com/v1/messages';

// Entra SSO configuration
const ENTRA_TENANT_ID = '4f69d2fb-f3d3-4cd8-8387-0a535355170b';
const ENTRA_CLIENT_ID = 'a56207ef-72d0-4d3f-9d00-3d5121e6c15d';
const ENTRA_ISSUER = `https://login.microsoftonline.com/${ENTRA_TENANT_ID}/v2.0`;
const ENTRA_JWKS_URI = `https://login.microsoftonline.com/${ENTRA_TENANT_ID}/discovery/v2.0/keys`;

// In-memory JWKS cache (per worker instance)
let jwksCache = null;
let jwksCachedAt = 0;
const JWKS_CACHE_TTL = 4 * 60 * 60 * 1000; // 4 hours in ms

function corsHeaders(request) {
  const origin = request.headers.get('Origin') || '';
  const allowed = ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0];
  return {
    'Access-Control-Allow-Origin': allowed,
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
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

function base64UrlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return Uint8Array.from(atob(str), c => c.charCodeAt(0));
}

async function getJWKS() {
  if (jwksCache && (Date.now() - jwksCachedAt) < JWKS_CACHE_TTL) {
    return jwksCache;
  }
  const res = await fetch(ENTRA_JWKS_URI);
  if (!res.ok) throw new Error('Failed to fetch JWKS');
  const jwks = await res.json();
  jwksCache = jwks.keys;
  jwksCachedAt = Date.now();
  return jwksCache;
}

async function importJWK(jwk) {
  return crypto.subtle.importKey(
    'jwk',
    { kty: jwk.kty, n: jwk.n, e: jwk.e },
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['verify']
  );
}

async function validateToken(token) {
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('Invalid JWT format');

  const header = JSON.parse(new TextDecoder().decode(base64UrlDecode(parts[0])));
  if (!header.kid) throw new Error('Missing kid in JWT header');

  const keys = await getJWKS();
  const jwk = keys.find(k => k.kid === header.kid);
  if (!jwk) throw new Error('No matching key found in JWKS');

  const cryptoKey = await importJWK(jwk);
  const data = new TextEncoder().encode(parts[0] + '.' + parts[1]);
  const signature = base64UrlDecode(parts[2]);
  const valid = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', cryptoKey, signature, data);
  if (!valid) throw new Error('Invalid JWT signature');

  const claims = JSON.parse(new TextDecoder().decode(base64UrlDecode(parts[1])));
  const now = Math.floor(Date.now() / 1000);

  if (claims.exp && claims.exp < now) throw new Error('Token expired');
  if (claims.nbf && claims.nbf > now + 60) throw new Error('Token not yet valid');
  if (claims.iss !== ENTRA_ISSUER) throw new Error('Invalid issuer');
  if (claims.aud !== ENTRA_CLIENT_ID) throw new Error('Invalid audience');

  return claims;
}

// ── Main Handler ──────────────────────────────────────────────

export default {
  async fetch(request, env) {
    // CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(request) });
    }

    const url = new URL(request.url);

    // Health check
    if (request.method === 'GET' && (url.pathname === '/' || url.pathname === '/health')) {
      return jsonResponse({ status: 'ok', service: 'voss-proxy', auth: 'entra-sso' }, 200, request);
    }

    // Only accept POST to /v1/messages
    if (request.method !== 'POST' || url.pathname !== '/v1/messages') {
      return jsonResponse({ error: 'Not found' }, 404, request);
    }

    // Validate Entra JWT
    const authHeader = request.headers.get('Authorization') || '';
    const token = authHeader.replace('Bearer ', '').trim();
    if (!token) {
      return jsonResponse({ error: 'Unauthorized — no token provided' }, 401, request);
    }

    try {
      await validateToken(token);
    } catch (err) {
      return jsonResponse({ error: 'Unauthorized — ' + err.message }, 401, request);
    }

    // Proxy to Anthropic API
    try {
      const body = await request.text();
      const anthropicRes = await fetch(ANTHROPIC_API_URL, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': env.ANTHROPIC_API_KEY,
          'anthropic-version': '2023-06-01'
        },
        body: body
      });

      const responseBody = await anthropicRes.text();
      return new Response(responseBody, {
        status: anthropicRes.status,
        headers: {
          'Content-Type': 'application/json',
          ...corsHeaders(request)
        }
      });
    } catch (err) {
      return jsonResponse({ error: 'Proxy error', message: err.message }, 500, request);
    }
  }
};
