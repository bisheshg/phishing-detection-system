import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import mongoSanitize from 'express-mongo-sanitize';
import xss from 'xss-clean';
import hpp from 'hpp';
import cors from 'cors';

/**
 * Security Middleware Collection
 * Implements comprehensive security measures for production
 */

// ==================== RATE LIMITERS ====================

// General API rate limiter
const generalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,  // 15 minutes
    max: 300,  // 300 requests per IP (React SPA makes many auth-check calls)
    skip: () => process.env.NODE_ENV !== 'production',  // disabled in development
    message: {
        error: 'Too many requests from this IP, please try again later',
        retryAfter: '15 minutes'
    },
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
        res.status(429).json({
            error: 'Rate limit exceeded',
            message: 'Too many requests. Please slow down.',
            retryAfter: res.getHeader('Retry-After')
        });
    }
});

// Analysis endpoint limiter (stricter)
const analyzeRateLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,  // 15 minutes
    max: async (req) => {
        // Premium users get higher limit
        if (req.user && req.user.isPremium) {
            return 500;
        }
        // Free users
        return 50;
    },
    skip: () => process.env.NODE_ENV !== 'production',  // disabled in development
    message: {
        error: 'Analysis rate limit exceeded',
        message: 'Too many URL scans. Please upgrade to premium for higher limits.'
    },
    standardHeaders: true,
    legacyHeaders: false,
    skipSuccessfulRequests: false
});

// Report endpoint limiter (prevent spam)
const reportRateLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,  // 1 hour
    max: 10,  // 10 reports per hour
    skip: () => process.env.NODE_ENV !== 'production',  // disabled in development
    message: {
        error: 'Too many reports submitted',
        message: 'You can only submit 10 reports per hour. Please try again later.'
    },
    skipSuccessfulRequests: false
});

// Auth endpoint limiter (prevent brute force)
const authRateLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,  // 15 minutes
    max: 10,                    // 10 failed attempts per 15 min in production
    skip: () => process.env.NODE_ENV !== 'production',  // disabled in development
    message: {
        error: 'Too many login attempts',
        message: 'Too many login attempts. Please try again in 15 minutes.'
    },
    skipSuccessfulRequests: true  // Don't count successful logins
});

// Registration limiter
const registerRateLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,  // 1 hour
    max: 3,                     // 3 registrations per hour in production
    skip: () => process.env.NODE_ENV !== 'production',  // disabled in development
    message: {
        error: 'Too many accounts created',
        message: 'Maximum 3 accounts per hour from this IP.'
    }
});

// ==================== SECURITY HEADERS ====================

const helmetConfig = helmet({
    // Content Security Policy
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com"],
            scriptSrc: ["'self'"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'", "http://localhost:5002"],  // Flask ML service
            frameSrc: ["'none'"],
            objectSrc: ["'none'"]
        }
    },

    // HTTP Strict Transport Security
    hsts: {
        maxAge: 31536000,  // 1 year
        includeSubDomains: true,
        preload: true
    },

    // Prevent clickjacking
    frameguard: {
        action: 'deny'
    },

    // Prevent MIME type sniffing
    noSniff: true,

    // Disable X-Powered-By header
    hidePoweredBy: true,

    // Referrer Policy
    referrerPolicy: {
        policy: 'strict-origin-when-cross-origin'
    }
});

// ==================== CORS CONFIGURATION ====================

const corsOptions = {
    origin: function (origin, callback) {
        const allowedOrigins = [
            'http://localhost:3000',
            'http://localhost:8800',
            'http://127.0.0.1:3000',
            process.env.FRONTEND_URL
        ].filter(Boolean);

        // Allow requests with no origin (mobile apps, Postman, etc.)
        if (!origin) return callback(null, true);

        // Allow Chrome extension origins
        if (origin.startsWith('chrome-extension://')) return callback(null, true);

        if (allowedOrigins.indexOf(origin) !== -1) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
    exposedHeaders: ['X-Total-Count', 'X-Rate-Limit-Remaining'],
    maxAge: 86400  // 24 hours
};

// ==================== SANITIZATION ====================

// MongoDB injection prevention
const mongoSanitizeConfig = {
    replaceWith: '_',
    onSanitize: ({ req, key }) => {
        console.warn(`Sanitized ${key} in request from ${req.ip}`);
    }
};

// ==================== ABUSE DETECTION ====================

const abuseDetection = (req, res, next) => {
    // Check for suspicious patterns
    const suspiciousPatterns = [
        /\.\.\//g,  // Directory traversal
        /<script/gi,  // XSS attempts
        /union.*select/gi,  // SQL injection
        /javascript:/gi,  // JavaScript protocol
        /on\w+\s*=/gi  // Event handlers
    ];

    const checkString = JSON.stringify(req.body) + JSON.stringify(req.query);

    for (const pattern of suspiciousPatterns) {
        if (pattern.test(checkString)) {
            console.error(`Abuse detected from ${req.ip}: ${pattern}`);
            return res.status(403).json({
                error: 'Forbidden',
                message: 'Suspicious request detected'
            });
        }
    }

    next();
};

// ==================== REQUEST LOGGING ====================

const securityLogger = (req, res, next) => {
    // Log security-relevant requests
    const sensitiveEndpoints = ['/api/auth/', '/api/phishing/report', '/api/admin/'];
    const isSensitive = sensitiveEndpoints.some(endpoint => req.path.startsWith(endpoint));

    if (isSensitive) {
        console.log(`[SECURITY] ${req.method} ${req.path} from ${req.ip} - User: ${req.user?.username || 'anonymous'}`);
    }

    next();
};

// ==================== MAIN SECURITY MIDDLEWARE ====================

const applySecurityMiddleware = (app) => {
    // 1. Helmet - Security headers
    app.use(helmetConfig);

    // 2. CORS - Cross-origin requests
    app.use(cors(corsOptions));

    // 3. MongoDB injection prevention
    app.use(mongoSanitize(mongoSanitizeConfig));

    // 4. XSS protection
    app.use(xss());

    // 5. HTTP Parameter Pollution prevention
    app.use(hpp({
        whitelist: ['url', 'domain', 'category', 'status']  // Allow arrays for these params
    }));

    // 6. Abuse detection
    app.use(abuseDetection);

    // 7. Security logging
    app.use(securityLogger);

    // 8. General rate limiting
    app.use('/api/', generalLimiter);

    console.log('✅ Security middleware initialized');
};

// ==================== EXPORTS ====================

export {
    applySecurityMiddleware,
    analyzeRateLimiter,
    reportRateLimiter,
    authRateLimiter,
    registerRateLimiter,
    generalLimiter,
    corsOptions,
    helmetConfig
};
