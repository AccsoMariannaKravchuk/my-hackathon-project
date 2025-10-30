# Security Guidelines Instructions

Comprehensive security guidelines for building secure Node.js Express applications in this hackathon project.

---

## 🛡️ Input Validation and Sanitization Requirements

### Input Validation Principles

#### Validate All Inputs

- **Never trust user input** - Validate everything at API boundaries
- **Whitelist approach** - Define what is allowed, reject everything else
- **Server-side validation** - Never rely on client-side validation alone
- **Fail securely** - Default to rejection when validation fails

#### Validation Layers

```javascript
// Layer 1: Schema validation (express-validator)
const validateUserInput = [
  body('email').isEmail().normalizeEmail(),
  body('name').trim().isLength({ min: 2, max: 50 }).escape(),
  body('age').isInt({ min: 18, max: 120 }),
];

// Layer 2: Business logic validation
const validateBusinessRules = userData => {
  if (userData.role === 'admin' && !userData.adminCode) {
    throw new ValidationError('Admin code required for admin role');
  }
};

// Layer 3: Data sanitization before storage
const sanitizeUserData = userData => {
  return {
    email: validator.normalizeEmail(userData.email),
    name: sanitizeHtml(userData.name, { allowedTags: [] }),
    age: parseInt(userData.age, 10),
  };
};
```

### Input Sanitization Patterns

#### String Sanitization

```javascript
const sanitize = require('sanitize-html');
const validator = require('validator');

// HTML sanitization - remove all HTML tags
const sanitizeText = input => {
  if (typeof input !== 'string') return '';

  return sanitize(input, {
    allowedTags: [], // No HTML tags allowed
    allowedAttributes: {},
    disallowedTagsMode: 'discard',
  });
};

// SQL injection prevention
const sanitizeSqlInput = input => {
  if (typeof input !== 'string') return input;

  // Remove/escape dangerous SQL characters
  return input.replace(/[';\\]/g, '');
};

// XSS prevention for display data
const escapeForDisplay = input => {
  if (typeof input !== 'string') return input;

  return validator.escape(input);
};
```

#### File Upload Sanitization

```javascript
const path = require('path');
const multer = require('multer');

// Safe file upload configuration
const upload = multer({
  dest: 'uploads/',
  fileFilter: (req, file, cb) => {
    // Whitelist allowed file types
    const allowedTypes = ['.jpg', '.jpeg', '.png', '.pdf', '.txt'];
    const ext = path.extname(file.originalname).toLowerCase();

    if (allowedTypes.includes(ext)) {
      cb(null, true);
    } else {
      cb(new Error('File type not allowed'), false);
    }
  },
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB max
    files: 1, // Single file only
  },
});

// Sanitize uploaded file names
const sanitizeFileName = filename => {
  return filename
    .replace(/[^a-zA-Z0-9.-]/g, '') // Remove special characters
    .substring(0, 100); // Limit length
};
```

#### API Input Validation Middleware

```javascript
// src/middleware/input-validation.js
const { body, param, query, validationResult } = require('express-validator');

const createValidationMiddleware = rules => {
  return [
    ...rules,
    (req, res, next) => {
      const errors = validationResult(req);

      if (!errors.isEmpty()) {
        // Log validation attempt for security monitoring
        console.warn('Validation failed:', {
          ip: req.ip,
          endpoint: req.path,
          errors: errors.array(),
          timestamp: new Date().toISOString(),
        });

        return res.status(422).json({
          success: false,
          error: {
            code: 'VALIDATION_ERROR',
            message: 'Invalid input data',
            details: errors.array().map(err => ({
              field: err.path,
              message: 'Invalid value provided',
              code: 'INVALID_INPUT',
            })),
          },
        });
      }

      next();
    },
  ];
};

// Common validation rules
const commonValidations = {
  email: body('email')
    .isEmail()
    .normalizeEmail()
    .isLength({ max: 254 })
    .withMessage('Valid email required'),

  password: body('password')
    .isLength({ min: 8, max: 128 })
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .withMessage('Password must meet complexity requirements'),

  id: param('id').isInt({ min: 1 }).toInt().withMessage('Valid ID required'),

  pagination: [
    query('page').optional().isInt({ min: 1 }).toInt(),
    query('limit').optional().isInt({ min: 1, max: 100 }).toInt(),
  ],
};

module.exports = { createValidationMiddleware, commonValidations };
```

---

## 🔐 Authentication and Session Management

### JWT Token Security

#### Secure Token Generation

```javascript
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

class TokenService {
  // Generate secure JWT tokens
  static generateAccessToken(payload) {
    return jwt.sign(
      {
        ...payload,
        iat: Math.floor(Date.now() / 1000),
        jti: crypto.randomUUID(), // Unique token ID
      },
      process.env.JWT_SECRET,
      {
        expiresIn: '15m', // Short-lived access tokens
        issuer: 'hackathon-app',
        audience: 'hackathon-users',
      }
    );
  }

  // Generate refresh tokens
  static generateRefreshToken(userId) {
    return jwt.sign(
      {
        userId,
        type: 'refresh',
        jti: crypto.randomUUID(),
      },
      process.env.JWT_REFRESH_SECRET,
      {
        expiresIn: '7d',
        issuer: 'hackathon-app',
      }
    );
  }

  // Verify token with comprehensive checks
  static verifyToken(token, secret = process.env.JWT_SECRET) {
    try {
      const decoded = jwt.verify(token, secret, {
        issuer: 'hackathon-app',
        audience: 'hackathon-users',
      });

      // Additional security checks
      if (decoded.type === 'refresh' && secret === process.env.JWT_SECRET) {
        throw new Error('Invalid token type');
      }

      return decoded;
    } catch (error) {
      throw new AuthenticationError('Invalid or expired token');
    }
  }
}
```

#### Authentication Middleware

```javascript
// src/middleware/auth.js
const rateLimit = require('express-rate-limit');

// Rate limiting for auth endpoints
const authRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts per window
  message: {
    success: false,
    error: {
      code: 'RATE_LIMIT_EXCEEDED',
      message: 'Too many authentication attempts',
      details: 'Please try again later',
    },
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// Secure authentication middleware
const authenticateToken = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;

    // Check for Authorization header
    if (!authHeader?.startsWith('Bearer ')) {
      return res.status(401).json({
        success: false,
        error: {
          code: 'MISSING_TOKEN',
          message: 'Authentication required',
          details: 'Please provide a valid Bearer token',
        },
      });
    }

    const token = authHeader.substring(7);

    // Verify token
    const decoded = TokenService.verifyToken(token);

    // Check token blacklist (for logout functionality)
    const isBlacklisted = await TokenBlacklist.isBlacklisted(decoded.jti);
    if (isBlacklisted) {
      return res.status(401).json({
        success: false,
        error: {
          code: 'TOKEN_REVOKED',
          message: 'Token has been revoked',
          details: 'Please login again',
        },
      });
    }

    // Attach user info to request
    req.user = decoded;
    req.tokenId = decoded.jti;

    // Log successful authentication
    console.log('Authentication successful:', {
      userId: decoded.id,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      timestamp: new Date().toISOString(),
    });

    next();
  } catch (error) {
    // Log failed authentication attempt
    console.warn('Authentication failed:', {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      error: error.message,
      timestamp: new Date().toISOString(),
    });

    return res.status(401).json({
      success: false,
      error: {
        code: 'AUTHENTICATION_FAILED',
        message: 'Authentication failed',
        details: 'Please login with valid credentials',
      },
    });
  }
};

module.exports = { authenticateToken, authRateLimit };
```

### Password Security

#### Secure Password Handling

```javascript
const bcrypt = require('bcrypt');
const zxcvbn = require('zxcvbn');

class PasswordService {
  // Hash passwords securely
  static async hashPassword(plainPassword) {
    // Check password strength
    const strength = zxcvbn(plainPassword);
    if (strength.score < 3) {
      throw new ValidationError('Password is too weak', {
        suggestions: strength.feedback.suggestions,
      });
    }

    // Generate salt and hash
    const saltRounds = 12;
    return await bcrypt.hash(plainPassword, saltRounds);
  }

  // Verify passwords with timing attack protection
  static async verifyPassword(plainPassword, hashedPassword) {
    const startTime = process.hrtime.bigint();

    try {
      const isValid = await bcrypt.compare(plainPassword, hashedPassword);

      // Constant time delay to prevent timing attacks
      const endTime = process.hrtime.bigint();
      const elapsedMs = Number(endTime - startTime) / 1000000;
      const minDelay = 100; // Minimum 100ms delay

      if (elapsedMs < minDelay) {
        await new Promise(resolve => setTimeout(resolve, minDelay - elapsedMs));
      }

      return isValid;
    } catch (error) {
      // Ensure consistent timing even on errors
      await new Promise(resolve => setTimeout(resolve, 100));
      return false;
    }
  }

  // Generate secure temporary passwords
  static generateTemporaryPassword(length = 16) {
    const chars =
      'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789@$!%*?&';
    let result = '';

    for (let i = 0; i < length; i++) {
      result += chars.charAt(Math.floor(Math.random() * chars.length));
    }

    return result;
  }
}
```

---

## 🔑 Environment Variables and Secrets Management

### Environment Configuration

#### Secure Environment Setup

```javascript
// src/config/environment.js
const dotenv = require('dotenv');
const Joi = require('joi');

// Load environment variables
dotenv.config();

// Define environment schema for validation
const envSchema = Joi.object({
  NODE_ENV: Joi.string()
    .valid('development', 'test', 'production')
    .default('development'),

  PORT: Joi.number().port().default(3000),

  JWT_SECRET: Joi.string()
    .min(32)
    .required()
    .description('JWT signing secret (min 32 characters)'),

  JWT_REFRESH_SECRET: Joi.string()
    .min(32)
    .required()
    .description('JWT refresh token secret'),

  DATABASE_URL: Joi.string()
    .uri()
    .required()
    .description('Database connection string'),

  ENCRYPTION_KEY: Joi.string()
    .length(64)
    .pattern(/^[0-9a-f]+$/)
    .required()
    .description('256-bit encryption key (64 hex chars)'),

  API_RATE_LIMIT_MAX: Joi.number().integer().min(1).default(100),

  // Security headers
  CORS_ORIGIN: Joi.alternatives()
    .try(Joi.string().uri(), Joi.array().items(Joi.string().uri()))
    .default('http://localhost:3000'),

  // External service secrets
  EMAIL_API_KEY: Joi.string().optional(),
  PAYMENT_API_SECRET: Joi.string().optional(),
}).unknown();

// Validate environment variables
const { error, value: env } = envSchema.validate(process.env);

if (error) {
  console.error('❌ Invalid environment configuration:');
  error.details.forEach(detail => {
    console.error(`  - ${detail.message}`);
  });
  process.exit(1);
}

// Export validated configuration
module.exports = {
  nodeEnv: env.NODE_ENV,
  port: env.PORT,
  jwt: {
    secret: env.JWT_SECRET,
    refreshSecret: env.JWT_REFRESH_SECRET,
    accessTokenExpiry: '15m',
    refreshTokenExpiry: '7d',
  },
  database: {
    url: env.DATABASE_URL,
  },
  security: {
    encryptionKey: env.ENCRYPTION_KEY,
    rateLimitMax: env.API_RATE_LIMIT_MAX,
    corsOrigin: env.CORS_ORIGIN,
  },
  external: {
    emailApiKey: env.EMAIL_API_KEY,
    paymentApiSecret: env.PAYMENT_API_SECRET,
  },
};
```

#### Secrets Encryption Utility

```javascript
// src/utils/encryption.js
const crypto = require('crypto');
const config = require('../config/environment');

class EncryptionService {
  static algorithm = 'aes-256-gcm';

  // Encrypt sensitive data
  static encrypt(text) {
    if (!text) return null;

    try {
      const iv = crypto.randomBytes(16);
      const key = Buffer.from(config.security.encryptionKey, 'hex');

      const cipher = crypto.createCipher(this.algorithm, key, iv);

      let encrypted = cipher.update(text, 'utf8', 'hex');
      encrypted += cipher.final('hex');

      const authTag = cipher.getAuthTag();

      return {
        encrypted,
        iv: iv.toString('hex'),
        authTag: authTag.toString('hex'),
      };
    } catch (error) {
      throw new Error('Encryption failed');
    }
  }

  // Decrypt sensitive data
  static decrypt(encryptedData) {
    if (!encryptedData) return null;

    try {
      const { encrypted, iv, authTag } = encryptedData;
      const key = Buffer.from(config.security.encryptionKey, 'hex');

      const decipher = crypto.createDecipher(
        this.algorithm,
        key,
        Buffer.from(iv, 'hex')
      );

      decipher.setAuthTag(Buffer.from(authTag, 'hex'));

      let decrypted = decipher.update(encrypted, 'hex', 'utf8');
      decrypted += decipher.final('utf8');

      return decrypted;
    } catch (error) {
      throw new Error('Decryption failed');
    }
  }

  // Generate secure random strings
  static generateSecureRandom(length = 32) {
    return crypto.randomBytes(length).toString('hex');
  }
}

module.exports = EncryptionService;
```

### Environment Files Structure

#### .env.example (Template for team)

```bash
# Server Configuration
NODE_ENV=development
PORT=3000

# Security Secrets (Generate new ones for each environment)
JWT_SECRET=your-super-secure-jwt-secret-min-32-chars-long
JWT_REFRESH_SECRET=your-super-secure-refresh-secret-min-32-chars
ENCRYPTION_KEY=64-character-hex-string-for-aes-256-encryption-key

# Database
DATABASE_URL=postgresql://user:pass@localhost:5432/hackathon_db

# Rate Limiting
API_RATE_LIMIT_MAX=100

# CORS
CORS_ORIGIN=http://localhost:3000

# External Services (Optional)
EMAIL_API_KEY=your-email-service-api-key
PAYMENT_API_SECRET=your-payment-service-secret
```

#### .env.production (Production secrets - never commit)

```bash
# Production configuration
NODE_ENV=production
PORT=8080

# Strong production secrets
JWT_SECRET=${PRODUCTION_JWT_SECRET}
JWT_REFRESH_SECRET=${PRODUCTION_REFRESH_SECRET}
ENCRYPTION_KEY=${PRODUCTION_ENCRYPTION_KEY}

# Production database
DATABASE_URL=${DATABASE_URL}

# Production rate limits
API_RATE_LIMIT_MAX=1000

# Production CORS
CORS_ORIGIN=https://yourdomain.com
```

---

## 🚨 Common Vulnerability Prevention (OWASP Top 10)

### A01 - Broken Access Control

#### Authorization Middleware

```javascript
// src/middleware/authorization.js
const ForbiddenError = require('../errors/forbidden-error');

// Role-based access control
const requireRole = allowedRoles => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        error: { code: 'UNAUTHORIZED', message: 'Authentication required' },
      });
    }

    const userRoles = Array.isArray(req.user.roles)
      ? req.user.roles
      : [req.user.role];
    const hasPermission = allowedRoles.some(role => userRoles.includes(role));

    if (!hasPermission) {
      // Log unauthorized access attempt
      console.warn('Unauthorized access attempt:', {
        userId: req.user.id,
        requiredRoles: allowedRoles,
        userRoles,
        endpoint: req.path,
        ip: req.ip,
        timestamp: new Date().toISOString(),
      });

      return res.status(403).json({
        success: false,
        error: {
          code: 'INSUFFICIENT_PERMISSIONS',
          message: 'Access denied',
          details: 'You do not have permission to access this resource',
        },
      });
    }

    next();
  };
};

// Resource ownership verification
const requireOwnership = (resourceIdParam = 'id') => {
  return async (req, res, next) => {
    try {
      const resourceId = req.params[resourceIdParam];
      const userId = req.user.id;

      // Admin bypass
      if (req.user.role === 'admin') {
        return next();
      }

      // Verify ownership
      const resource = await getResourceById(resourceId);
      if (!resource || resource.userId !== userId) {
        return res.status(403).json({
          success: false,
          error: {
            code: 'ACCESS_DENIED',
            message: 'Access denied',
            details: 'You can only access your own resources',
          },
        });
      }

      req.resource = resource;
      next();
    } catch (error) {
      next(error);
    }
  };
};
```

### A02 - Cryptographic Failures

#### Secure Data Handling

```javascript
// src/utils/crypto-security.js
const crypto = require('crypto');

class CryptoSecurity {
  // Secure password reset tokens
  static generatePasswordResetToken() {
    const token = crypto.randomBytes(32).toString('hex');
    const expiry = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes

    return {
      token,
      expiry,
      hash: crypto.createHash('sha256').update(token).digest('hex'),
    };
  }

  // Secure API keys
  static generateApiKey() {
    const prefix = 'hk_'; // Hackathon key prefix
    const randomPart = crypto.randomBytes(32).toString('hex');
    return prefix + randomPart;
  }

  // Hash sensitive data for storage
  static hashSensitiveData(data) {
    return crypto.createHash('sha256').update(data).digest('hex');
  }

  // Secure comparison to prevent timing attacks
  static secureCompare(a, b) {
    if (a.length !== b.length) {
      return false;
    }

    return crypto.timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex'));
  }
}
```

### A03 - Injection Attacks

#### SQL Injection Prevention

```javascript
// src/database/secure-queries.js
const { Pool } = require('pg');

class SecureDatabase {
  constructor(connectionString) {
    this.pool = new Pool({ connectionString });
  }

  // Parameterized queries only
  async query(text, params = []) {
    try {
      // Log query for security monitoring (without sensitive data)
      console.log('Database query:', {
        query: text.substring(0, 100),
        paramCount: params.length,
      });

      const result = await this.pool.query(text, params);
      return result;
    } catch (error) {
      console.error('Database error:', error.message);
      throw new Error('Database operation failed');
    }
  }

  // Safe user lookup
  async findUserByEmail(email) {
    const query = 'SELECT * FROM users WHERE email = $1';
    const result = await this.query(query, [email]);
    return result.rows[0] || null;
  }

  // Safe user creation
  async createUser(userData) {
    const query = `
      INSERT INTO users (name, email, password_hash, role, created_at)
      VALUES ($1, $2, $3, $4, NOW())
      RETURNING id, name, email, role, created_at
    `;

    const values = [
      userData.name,
      userData.email,
      userData.passwordHash,
      userData.role || 'user',
    ];

    const result = await this.query(query, values);
    return result.rows[0];
  }
}
```

### A04 - Insecure Design

#### Security-First Architecture

```javascript
// src/middleware/security-headers.js
const helmet = require('helmet');

// Comprehensive security headers
const securityHeaders = helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", 'data:', 'https:'],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
    },
  },
  crossOriginEmbedderPolicy: true,
  crossOriginOpenerPolicy: true,
  crossOriginResourcePolicy: { policy: 'cross-origin' },
  dnsPrefetchControl: true,
  frameguard: { action: 'deny' },
  hidePoweredBy: true,
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true,
  },
  ieNoOpen: true,
  noSniff: true,
  originAgentCluster: true,
  permittedCrossDomainPolicies: false,
  referrerPolicy: { policy: 'no-referrer' },
  xssFilter: true,
});

// Request size limiting
const requestSizeLimit = require('express').raw({
  limit: '10mb', // Prevent DoS via large payloads
});

module.exports = { securityHeaders, requestSizeLimit };
```

### A05 - Security Misconfiguration

#### Secure Express Configuration

```javascript
// src/app.js - Security configuration
const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const { securityHeaders } = require('./middleware/security-headers');
const config = require('./config/environment');

const app = express();

// Security middleware (order matters!)
app.use(securityHeaders);

// CORS configuration
app.use(
  cors({
    origin: config.security.corsOrigin,
    credentials: true,
    optionsSuccessStatus: 200,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
    allowedHeaders: ['Content-Type', 'Authorization'],
  })
);

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: config.security.rateLimitMax,
  message: {
    success: false,
    error: {
      code: 'RATE_LIMIT_EXCEEDED',
      message: 'Too many requests',
      details: 'Please try again later',
    },
  },
  standardHeaders: true,
  legacyHeaders: false,
});

app.use(limiter);

// Body parsing with size limits
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Disable unnecessary headers
app.disable('x-powered-by');

// Security logging
app.use((req, res, next) => {
  console.log('Request:', {
    method: req.method,
    url: req.url,
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    timestamp: new Date().toISOString(),
  });
  next();
});

module.exports = app;
```

---

## 🧪 Security Testing Requirements

### Security Test Categories

#### Authentication Tests

```javascript
// tests/security/authentication.test.js
describe('Authentication Security', () => {
  describe('Login Endpoint', () => {
    it('should prevent brute force attacks', async () => {
      const loginData = {
        email: 'test@example.com',
        password: 'wrongpassword',
      };

      // Make multiple failed login attempts
      const requests = Array(6)
        .fill()
        .map(() => request(app).post('/api/auth/login').send(loginData));

      const responses = await Promise.all(requests);

      // Should be rate limited after 5 attempts
      expect(responses[5].status).toBe(429);
      expect(responses[5].body.error.code).toBe('RATE_LIMIT_EXCEEDED');
    });

    it('should prevent timing attacks', async () => {
      const startTime = Date.now();

      await request(app).post('/api/auth/login').send({
        email: 'nonexistent@example.com',
        password: 'anypassword',
      });

      const endTime = Date.now();
      const duration1 = endTime - startTime;

      const startTime2 = Date.now();

      await request(app).post('/api/auth/login').send({
        email: 'valid@example.com',
        password: 'wrongpassword',
      });

      const endTime2 = Date.now();
      const duration2 = endTime2 - startTime2;

      // Response times should be similar (within 50ms)
      expect(Math.abs(duration1 - duration2)).toBeLessThan(50);
    });
  });

  describe('JWT Token Security', () => {
    it('should reject tampered tokens', async () => {
      const validToken = await generateTestToken();
      const tamperedToken = validToken.slice(0, -10) + 'tampereddd';

      const response = await request(app)
        .get('/api/auth/me')
        .set('Authorization', `Bearer ${tamperedToken}`);

      expect(response.status).toBe(401);
      expect(response.body.error.code).toBe('AUTHENTICATION_FAILED');
    });

    it('should reject expired tokens', async () => {
      const expiredToken = jwt.sign(
        { id: 1, email: 'test@example.com' },
        process.env.JWT_SECRET,
        { expiresIn: '-1h' } // Already expired
      );

      const response = await request(app)
        .get('/api/auth/me')
        .set('Authorization', `Bearer ${expiredToken}`);

      expect(response.status).toBe(401);
    });
  });
});
```

#### Input Validation Tests

```javascript
// tests/security/input-validation.test.js
describe('Input Validation Security', () => {
  describe('XSS Prevention', () => {
    it('should sanitize HTML in user inputs', async () => {
      const maliciousInput = {
        name: '<script>alert("xss")</script>John',
        bio: '<img src=x onerror=alert("xss")>Bio text',
      };

      const response = await request(app)
        .post('/api/users')
        .set('Authorization', `Bearer ${validToken}`)
        .send(maliciousInput);

      expect(response.status).toBe(201);
      expect(response.body.data.name).not.toContain('<script>');
      expect(response.body.data.bio).not.toContain('<img');
    });
  });

  describe('SQL Injection Prevention', () => {
    it('should handle malicious SQL in inputs', async () => {
      const sqlInjection = {
        email: "'; DROP TABLE users; --",
        name: "Robert'); DELETE FROM users WHERE ('1'='1",
      };

      const response = await request(app).post('/api/users').send(sqlInjection);

      // Should return validation error, not crash
      expect(response.status).toBe(422);

      // Verify database integrity
      const usersCount = await db.query('SELECT COUNT(*) FROM users');
      expect(usersCount.rows[0].count).toBeGreaterThan(0);
    });
  });

  describe('File Upload Security', () => {
    it('should reject dangerous file types', async () => {
      const response = await request(app)
        .post('/api/upload')
        .set('Authorization', `Bearer ${validToken}`)
        .attach('file', Buffer.from('<?php echo "hack"; ?>'), 'malicious.php');

      expect(response.status).toBe(400);
      expect(response.body.error.message).toContain('File type not allowed');
    });

    it('should limit file size', async () => {
      const largeBuffer = Buffer.alloc(10 * 1024 * 1024); // 10MB

      const response = await request(app)
        .post('/api/upload')
        .set('Authorization', `Bearer ${validToken}`)
        .attach('file', largeBuffer, 'large.txt');

      expect(response.status).toBe(413); // Payload Too Large
    });
  });
});
```

#### Authorization Tests

```javascript
// tests/security/authorization.test.js
describe('Authorization Security', () => {
  describe('Role-Based Access Control', () => {
    it('should prevent users from accessing admin endpoints', async () => {
      const userToken = await generateTokenForRole('user');

      const response = await request(app)
        .get('/api/admin/users')
        .set('Authorization', `Bearer ${userToken}`);

      expect(response.status).toBe(403);
      expect(response.body.error.code).toBe('INSUFFICIENT_PERMISSIONS');
    });

    it('should prevent accessing other users resources', async () => {
      const user1Token = await generateTokenForUser(1);

      const response = await request(app)
        .get('/api/users/2/profile')
        .set('Authorization', `Bearer ${user1Token}`);

      expect(response.status).toBe(403);
      expect(response.body.error.code).toBe('ACCESS_DENIED');
    });
  });

  describe('Privilege Escalation Prevention', () => {
    it('should prevent users from elevating their role', async () => {
      const userToken = await generateTokenForRole('user');

      const response = await request(app)
        .patch('/api/users/1')
        .set('Authorization', `Bearer ${userToken}`)
        .send({ role: 'admin' });

      expect(response.status).toBe(403);
    });
  });
});
```

### Security Test Automation

#### Security Test Suite Integration

```javascript
// tests/security/security-suite.js
const { execSync } = require('child_process');

describe('Security Test Suite', () => {
  describe('Dependency Security', () => {
    it('should have no high-severity vulnerabilities', async () => {
      try {
        execSync('npm audit --audit-level high', { stdio: 'pipe' });
      } catch (error) {
        // npm audit exits with code 1 if vulnerabilities found
        if (error.status === 1) {
          const output = error.stdout.toString();
          console.log('Security vulnerabilities found:', output);
          throw new Error('High-severity vulnerabilities detected');
        }
      }
    });
  });

  describe('Environment Security', () => {
    it('should have secure environment configuration', () => {
      // Check for required security environment variables
      expect(process.env.JWT_SECRET).toBeDefined();
      expect(process.env.JWT_SECRET.length).toBeGreaterThanOrEqual(32);

      expect(process.env.ENCRYPTION_KEY).toBeDefined();
      expect(process.env.ENCRYPTION_KEY.length).toBe(64);

      // Ensure not using default/weak secrets in production
      if (process.env.NODE_ENV === 'production') {
        expect(process.env.JWT_SECRET).not.toContain('default');
        expect(process.env.JWT_SECRET).not.toContain('secret');
      }
    });
  });

  describe('Security Headers', () => {
    it('should set security headers correctly', async () => {
      const response = await request(app).get('/');

      expect(response.headers['x-frame-options']).toBe('DENY');
      expect(response.headers['x-content-type-options']).toBe('nosniff');
      expect(response.headers['x-xss-protection']).toBe('1; mode=block');
      expect(response.headers['strict-transport-security']).toContain(
        'max-age'
      );
      expect(response.headers['content-security-policy']).toBeDefined();
    });
  });
});
```

### Security Monitoring

#### Security Event Logging

```javascript
// src/middleware/security-monitor.js
const fs = require('fs').promises;
const path = require('path');

class SecurityMonitor {
  static async logSecurityEvent(event, details) {
    const logEntry = {
      timestamp: new Date().toISOString(),
      event,
      details,
      severity: this.getSeverity(event),
    };

    // Log to console
    console.warn('Security Event:', logEntry);

    // Log to file
    const logFile = path.join(process.cwd(), 'logs', 'security.log');
    await fs.appendFile(logFile, JSON.stringify(logEntry) + '\n');

    // Alert on high-severity events
    if (logEntry.severity === 'HIGH') {
      await this.sendSecurityAlert(logEntry);
    }
  }

  static getSeverity(event) {
    const highSeverityEvents = [
      'UNAUTHORIZED_ACCESS_ATTEMPT',
      'SQL_INJECTION_ATTEMPT',
      'XSS_ATTEMPT',
      'PRIVILEGE_ESCALATION_ATTEMPT',
    ];

    return highSeverityEvents.includes(event) ? 'HIGH' : 'MEDIUM';
  }

  static async sendSecurityAlert(logEntry) {
    // In a real app, send email/SMS/Slack notification
    console.error('🚨 HIGH SEVERITY SECURITY EVENT:', logEntry);
  }
}

module.exports = SecurityMonitor;
```

---

## 🚀 Security Implementation Checklist

### Development Phase Security

- [ ] **Input Validation**: All inputs validated and sanitized
- [ ] **Authentication**: JWT tokens with proper expiry and secrets
- [ ] **Authorization**: Role-based access control implemented
- [ ] **Encryption**: Sensitive data encrypted at rest
- [ ] **Security Headers**: Helmet.js configured properly
- [ ] **Rate Limiting**: API rate limiting enabled
- [ ] **CORS**: Proper CORS configuration
- [ ] **Error Handling**: No sensitive data in error responses

### Testing Phase Security

- [ ] **Security Tests**: Comprehensive security test suite
- [ ] **Penetration Testing**: Basic penetration testing completed
- [ ] **Vulnerability Scanning**: npm audit clean
- [ ] **Code Review**: Security-focused code review
- [ ] **Authentication Tests**: All auth flows tested
- [ ] **Authorization Tests**: Access control verified
- [ ] **Input Validation Tests**: XSS and injection prevention verified

### Deployment Phase Security

- [ ] **Environment Variables**: All secrets properly configured
- [ ] **HTTPS**: SSL/TLS enabled in production
- [ ] **Security Monitoring**: Logging and monitoring enabled
- [ ] **Backup Strategy**: Secure backup procedures
- [ ] **Incident Response**: Security incident response plan
- [ ] **Documentation**: Security documentation complete

---

**💡 Pro Tips for Hackathon Security:**

1. **Security by Default**: Use secure defaults, opt-out if needed
2. **Layer Security**: Multiple layers of protection (defense in depth)
3. **Validate Everything**: Trust nothing, validate everything
4. **Fail Securely**: When in doubt, deny access
5. **Monitor Continuously**: Log security events for analysis
6. **Keep Dependencies Updated**: Use `npm audit` regularly
7. **Test Security Early**: Don't leave security testing until the end
