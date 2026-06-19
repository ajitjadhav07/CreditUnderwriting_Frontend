/**
 * Auth Guards — Web EC2 tier
 *
 * Deliberately does NOT contain the Azure AD client secret, the OIDC
 * strategy, or the employee whitelist (lib/user-manager.js on App EC2).
 * Those stay on App EC2 — only that tier can complete the OAuth handshake
 * or know who's on the whitelist.
 *
 * This file only needs to read the session that App EC2 already wrote to
 * the shared Redis store (see server.js) and decide whether a request is
 * allowed through. passport.serializeUser() on App EC2 stores the *entire*
 * user object (id, email, role, ...) directly in the session, so deserialize
 * here is a trivial pass-through — no DB/whitelist lookup needed.
 */

const ROLES = {
    SUPER_ADMIN: 'super_admin',
    ADMIN: 'admin',
    UNDERWRITER: 'underwriter',
    AUDITOR: 'auditor'
};

function registerPassportSerialization(passport) {
    passport.serializeUser((user, done) => done(null, user));
    passport.deserializeUser((user, done) => done(null, user));
}

function ensureAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    req.session.returnTo = req.originalUrl;
    res.redirect('/login');
}

function ensureNotAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return res.redirect('/');
    }
    next();
}

function requireRole(...allowedRoles) {
    return function (req, res, next) {
        if (!req.isAuthenticated()) {
            req.session.returnTo = req.originalUrl;
            return res.redirect('/login');
        }
        const userRole = req.user?.role;
        if (!userRole || !allowedRoles.includes(userRole)) {
            return res.status(403).json({ error: 'Forbidden: Insufficient permissions' });
        }
        next();
    };
}

module.exports = {
    ROLES,
    registerPassportSerialization,
    ensureAuthenticated,
    ensureNotAuthenticated,
    requireRole
};
