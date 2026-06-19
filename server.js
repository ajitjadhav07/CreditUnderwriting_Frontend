/**
 * Axis Underwriting Agent — Web Tier (Web EC2)
 *
 * Responsibilities:
 *   - Serve the static frontend (public/: index.html, login.html, compliance.html,
 *     siem-docs.html, styles.css, logo.png)
 *   - Gate the auth-sensitive pages (/, /compliance, /siem-docs) the same way
 *     server.js used to — by reading the session
 *
 * Deliberately does NOT do:
 *   - The Azure AD / Office 365 OAuth handshake (/auth/signin, /auth/callback,
 *     /auth/logout) — that stays on App EC2, which holds the OIDC client secret
 *   - Any /api/* business logic — proxied (or routed via ALB) to App EC2
 *
 * For auth to work across two physical servers, both this server and App EC2's
 * server.js MUST point at the SAME Redis (ElastiCache) instance and use the
 * SAME SESSION_SECRET / cookie name. See .env.example.
 */

require('dotenv').config();

const express = require('express');
const path = require('path');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const RedisStore = require('connect-redis').default;
const Redis = require('ioredis');
const passport = require('passport');
const { createProxyMiddleware } = require('http-proxy-middleware');

const {
    ROLES,
    registerPassportSerialization,
    ensureAuthenticated,
    ensureNotAuthenticated,
    requireRole
} = require('./lib/auth-guards');

const app = express();
const PORT = process.env.PORT || 8080;

// ==================== ENV VALIDATION ====================
const required = ['REDIS_URL', 'SESSION_SECRET'];
if (process.env.NODE_ENV === 'production') {
    const missing = required.filter((k) => !process.env[k]);
    if (missing.length) {
        console.error('❌ CRITICAL: Missing required env vars:', missing.join(', '));
        console.error('   These MUST match the values used on App EC2 or sessions will not be shared.');
        process.exit(1);
    }
}

// ==================== SECURITY HEADERS ====================
app.use(helmet({
    contentSecurityPolicy: false // index.html is a large inline-script app; CSP tuning left to caller if needed
}));

// ==================== SESSION (shared with App EC2 via Redis) ====================
app.use(cookieParser());

const redisClient = process.env.REDIS_URL ? new Redis(process.env.REDIS_URL) : null;
if (redisClient) {
    redisClient.on('error', (err) => console.error('⚠️ [SESSION-REDIS] Error:', err.message));
}

app.use(session({
    store: redisClient ? new RedisStore({ client: redisClient, prefix: 'acc-sess:' }) : undefined,
    secret: process.env.SESSION_SECRET || 'dev-only-secret-not-for-production',
    resave: false,
    saveUninitialized: true,
    proxy: true,
    name: 'acc.sid', // MUST match App EC2's session cookie name exactly
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        maxAge: 8 * 60 * 60 * 1000,
        sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
        path: '/',
        domain: undefined
    }
}));

registerPassportSerialization(passport);
app.use(passport.initialize());
app.use(passport.session());

// ==================== OPTIONAL: PROXY FALLBACK TO APP EC2 ====================
// Primary routing should be ALB path rules (/api/*, /auth/*, /socket.io/* -> App
// EC2 target group). This proxy is a defense-in-depth fallback for the case
// where this server is hit directly (health checks, internal tooling, or if the
// ALB rule isn't in place yet). Set APP_SERVER_URL to enable it.
if (process.env.APP_SERVER_URL) {
    const proxy = createProxyMiddleware({
        target: process.env.APP_SERVER_URL,
        changeOrigin: true,
        ws: true // for /socket.io
    });
    app.use('/api', proxy);
    app.use('/auth', proxy);
    app.use('/socket.io', proxy);
    console.log(`✓ Proxy fallback to App EC2 enabled: ${process.env.APP_SERVER_URL}`);
}

// ==================== STATIC ASSETS ====================
// CSS, images, etc. — anything that isn't one of the auth-gated HTML pages below.
app.use(express.static(path.join(__dirname, 'public'), { index: false }));

// ==================== PAGE ROUTES ====================
app.get('/login', ensureNotAuthenticated, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/', ensureAuthenticated, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/siem-docs', ensureAuthenticated, requireRole(ROLES.SUPER_ADMIN), (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'siem-docs.html'));
});

app.get('/compliance', ensureAuthenticated, requireRole(ROLES.SUPER_ADMIN), (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'compliance.html'));
});

// Simple health check for the ALB target group
app.get('/healthz', (req, res) => res.status(200).send('ok'));

app.listen(PORT, () => {
    console.log(`✅ Web tier listening on port ${PORT}`);
});
