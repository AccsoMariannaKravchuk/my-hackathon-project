# API Design Instructions

Comprehensive guide for designing consistent, maintainable REST APIs in this hackathon project.

---

## 📋 REST Endpoint Naming Conventions

### Resource Naming Rules

- **Use nouns, not verbs** for resource names
- **Plural nouns** for collections: `/api/users`, `/api/orders`
- **Lowercase with hyphens** for multi-word resources: `/api/user-profiles`
- **Consistent hierarchy** for nested resources

### URL Structure Patterns

```bash
# Collection operations
GET    /api/users              # List all users
POST   /api/users              # Create new user
GET    /api/users?role=admin   # Filter users by query params

# Resource operations
GET    /api/users/123          # Get specific user
PUT    /api/users/123          # Update entire user
PATCH  /api/users/123          # Partial user update
DELETE /api/users/123          # Delete user

# Nested resources
GET    /api/users/123/orders   # Get user's orders
POST   /api/users/123/orders   # Create order for user
GET    /api/users/123/orders/456  # Get specific user order

# Actions (when needed)
POST   /api/users/123/activate      # Activate user account
POST   /api/orders/456/cancel       # Cancel order
POST   /api/auth/login              # Authentication action
POST   /api/auth/logout             # Logout action
```

### Query Parameter Conventions

```bash
# Filtering
GET /api/users?status=active&role=admin

# Sorting
GET /api/users?sort=created_at&order=desc
GET /api/users?sort=-created_at  # Alternative desc syntax

# Pagination
GET /api/users?page=2&limit=20
GET /api/users?offset=20&limit=20

# Field selection
GET /api/users?fields=id,name,email

# Search
GET /api/users?search=john
GET /api/users?q=john+doe
```

---

## 📊 Request/Response Structure Standards

### Request Headers

```javascript
// Required headers for all requests
{
  "Content-Type": "application/json",
  "Accept": "application/json",
  "User-Agent": "HackathonApp/1.0"
}

// Authentication requests
{
  "Authorization": "Bearer {jwt_token}",
  "Content-Type": "application/json"
}
```

### Request Body Format

```javascript
// POST /api/users - Create user
{
  "name": "John Doe",
  "email": "john@example.com",
  "role": "user",
  "preferences": {
    "theme": "dark",
    "notifications": true
  }
}

// PATCH /api/users/123 - Partial update
{
  "name": "John Smith",
  "preferences": {
    "theme": "light"
  }
}
```

### Success Response Format

```javascript
// Single resource response
{
  "success": true,
  "data": {
    "id": 123,
    "name": "John Doe",
    "email": "john@example.com",
    "created_at": "2025-10-30T13:22:26.000Z",
    "updated_at": "2025-10-30T13:22:26.000Z"
  },
  "meta": {
    "timestamp": "2025-10-30T13:22:26.000Z",
    "version": "1.0"
  }
}

// Collection response
{
  "success": true,
  "data": [
    {
      "id": 123,
      "name": "John Doe",
      "email": "john@example.com"
    },
    {
      "id": 124,
      "name": "Jane Smith",
      "email": "jane@example.com"
    }
  ],
  "pagination": {
    "page": 1,
    "limit": 20,
    "total": 156,
    "total_pages": 8,
    "has_next": true,
    "has_prev": false
  },
  "meta": {
    "timestamp": "2025-10-30T13:22:26.000Z",
    "count": 2
  }
}

// Creation response (201)
{
  "success": true,
  "message": "User created successfully",
  "data": {
    "id": 123,
    "name": "John Doe",
    "email": "john@example.com"
  },
  "meta": {
    "timestamp": "2025-10-30T13:22:26.000Z",
    "location": "/api/users/123"
  }
}
```

---

## ❌ Error Response Formats

### Standard Error Structure

```javascript
{
  "success": false,
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Validation failed for user data",
    "details": [
      {
        "field": "email",
        "message": "Email is required",
        "code": "REQUIRED_FIELD"
      },
      {
        "field": "password",
        "message": "Password must be at least 8 characters",
        "code": "MIN_LENGTH"
      }
    ]
  },
  "meta": {
    "timestamp": "2025-10-30T13:22:26.000Z",
    "request_id": "req_123456789"
  }
}
```

### HTTP Status Code Guidelines

#### 4xx Client Errors

```javascript
// 400 Bad Request - Invalid request data
{
  "success": false,
  "error": {
    "code": "BAD_REQUEST",
    "message": "Invalid JSON in request body",
    "details": "Unexpected token at position 15"
  }
}

// 401 Unauthorized - Missing or invalid authentication
{
  "success": false,
  "error": {
    "code": "UNAUTHORIZED",
    "message": "Authentication required",
    "details": "Please provide a valid JWT token"
  }
}

// 403 Forbidden - Valid auth but insufficient permissions
{
  "success": false,
  "error": {
    "code": "FORBIDDEN",
    "message": "Insufficient permissions",
    "details": "Admin role required for this operation"
  }
}

// 404 Not Found - Resource doesn't exist
{
  "success": false,
  "error": {
    "code": "NOT_FOUND",
    "message": "User not found",
    "details": "No user exists with ID 123"
  }
}

// 409 Conflict - Resource conflict (duplicate email, etc.)
{
  "success": false,
  "error": {
    "code": "CONFLICT",
    "message": "Email already exists",
    "details": "A user with email john@example.com already exists"
  }
}

// 422 Unprocessable Entity - Validation errors
{
  "success": false,
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Validation failed",
    "details": [
      {
        "field": "age",
        "message": "Age must be between 18 and 120",
        "code": "OUT_OF_RANGE"
      }
    ]
  }
}

// 429 Too Many Requests - Rate limiting
{
  "success": false,
  "error": {
    "code": "RATE_LIMIT_EXCEEDED",
    "message": "Rate limit exceeded",
    "details": "Maximum 100 requests per minute allowed"
  }
}
```

#### 5xx Server Errors

```javascript
// 500 Internal Server Error - Unexpected server error
{
  "success": false,
  "error": {
    "code": "INTERNAL_SERVER_ERROR",
    "message": "An unexpected error occurred",
    "details": "Please try again later or contact support"
  }
}

// 503 Service Unavailable - Service temporarily down
{
  "success": false,
  "error": {
    "code": "SERVICE_UNAVAILABLE",
    "message": "Service temporarily unavailable",
    "details": "Database connection failed, retrying..."
  }
}
```

---

## ✅ Validation Rules and Middleware Patterns

### Input Validation Middleware

```javascript
// src/middleware/validation.js
const { body, param, query, validationResult } = require('express-validator');

// User creation validation
const validateUserCreation = [
  body('name')
    .trim()
    .isLength({ min: 2, max: 50 })
    .withMessage('Name must be between 2 and 50 characters'),

  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Please provide a valid email address'),

  body('password')
    .isLength({ min: 8 })
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
    .withMessage(
      'Password must be at least 8 characters with uppercase, lowercase, and number'
    ),

  body('role')
    .optional()
    .isIn(['user', 'admin', 'moderator'])
    .withMessage('Role must be user, admin, or moderator'),

  // Custom validation middleware
  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(422).json({
        success: false,
        error: {
          code: 'VALIDATION_ERROR',
          message: 'Validation failed',
          details: errors.array().map(err => ({
            field: err.path,
            message: err.msg,
            code: 'INVALID_VALUE',
          })),
        },
      });
    }
    next();
  },
];

// ID parameter validation
const validateId = [
  param('id').isInt({ min: 1 }).withMessage('ID must be a positive integer'),

  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        error: {
          code: 'INVALID_PARAMETER',
          message: 'Invalid ID parameter',
          details: errors.array()[0].msg,
        },
      });
    }
    next();
  },
];

// Query parameter validation
const validatePagination = [
  query('page')
    .optional()
    .isInt({ min: 1 })
    .withMessage('Page must be a positive integer'),

  query('limit')
    .optional()
    .isInt({ min: 1, max: 100 })
    .withMessage('Limit must be between 1 and 100'),

  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        error: {
          code: 'INVALID_QUERY',
          message: 'Invalid query parameters',
          details: errors.array().map(err => ({
            field: err.path,
            message: err.msg,
          })),
        },
      });
    }
    next();
  },
];
```

### Custom Validation Functions

```javascript
// src/utils/validation.js
const validator = require('validator');

const customValidators = {
  // Phone number validation
  isPhoneNumber: value => {
    return /^\+?[\d\s\-\(\)]{10,}$/.test(value);
  },

  // Strong password validation
  isStrongPassword: password => {
    return /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/.test(
      password
    );
  },

  // Business email validation
  isBusinessEmail: email => {
    const personalDomains = ['gmail.com', 'yahoo.com', 'hotmail.com'];
    const domain = email.split('@')[1];
    return !personalDomains.includes(domain);
  },
};

module.exports = customValidators;
```

---

## 🔐 Authentication and Authorization Patterns

### JWT Authentication Middleware

```javascript
// src/middleware/auth.js
const jwt = require('jsonwebtoken');
const config = require('../config');

// Basic authentication middleware
const authenticateToken = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        success: false,
        error: {
          code: 'MISSING_TOKEN',
          message: 'Authentication token required',
          details: 'Please provide a Bearer token in the Authorization header',
        },
      });
    }

    const token = authHeader.substring(7); // Remove 'Bearer ' prefix

    const decoded = jwt.verify(token, config.JWT_SECRET);
    req.user = decoded;

    next();
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({
        success: false,
        error: {
          code: 'TOKEN_EXPIRED',
          message: 'Authentication token has expired',
          details: 'Please login again to get a new token',
        },
      });
    }

    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({
        success: false,
        error: {
          code: 'INVALID_TOKEN',
          message: 'Invalid authentication token',
          details: 'Please provide a valid JWT token',
        },
      });
    }

    return res.status(500).json({
      success: false,
      error: {
        code: 'AUTH_ERROR',
        message: 'Authentication failed',
        details: 'Please try again',
      },
    });
  }
};

// Role-based authorization middleware
const requireRole = requiredRoles => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        error: {
          code: 'UNAUTHORIZED',
          message: 'Authentication required',
        },
      });
    }

    const userRoles = Array.isArray(req.user.roles)
      ? req.user.roles
      : [req.user.role];
    const hasRequiredRole = requiredRoles.some(role =>
      userRoles.includes(role)
    );

    if (!hasRequiredRole) {
      return res.status(403).json({
        success: false,
        error: {
          code: 'INSUFFICIENT_PERMISSIONS',
          message: 'Insufficient permissions',
          details: `Required roles: ${requiredRoles.join(', ')}`,
        },
      });
    }

    next();
  };
};

// Resource ownership middleware
const requireOwnership = (resourceIdParam = 'id') => {
  return (req, res, next) => {
    const resourceId = req.params[resourceIdParam];
    const userId = req.user.id;

    // Admin can access any resource
    if (req.user.role === 'admin') {
      return next();
    }

    // Check if user owns the resource
    if (parseInt(resourceId) !== parseInt(userId)) {
      return res.status(403).json({
        success: false,
        error: {
          code: 'ACCESS_DENIED',
          message: 'Access denied',
          details: 'You can only access your own resources',
        },
      });
    }

    next();
  };
};

module.exports = {
  authenticateToken,
  requireRole,
  requireOwnership,
};
```

### Authentication Routes Pattern

```javascript
// src/routes/auth.js
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const {
  validateUserCreation,
  validateLogin,
} = require('../middleware/validation');
const { authenticateToken } = require('../middleware/auth');

const router = express.Router();

// Register new user
router.post('/register', validateUserCreation, async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // Check if user exists
    const existingUser = await User.findByEmail(email);
    if (existingUser) {
      return res.status(409).json({
        success: false,
        error: {
          code: 'USER_EXISTS',
          message: 'User already exists',
          details: 'A user with this email already exists',
        },
      });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);

    // Create user
    const user = await User.create({
      name,
      email,
      password: hashedPassword,
    });

    // Generate token
    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      config.JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.status(201).json({
      success: true,
      message: 'User registered successfully',
      data: {
        user: {
          id: user.id,
          name: user.name,
          email: user.email,
          role: user.role,
        },
        token,
      },
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: {
        code: 'REGISTRATION_FAILED',
        message: 'Registration failed',
        details: 'Please try again',
      },
    });
  }
});

// Login user
router.post('/login', validateLogin, async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find user
    const user = await User.findByEmail(email);
    if (!user) {
      return res.status(401).json({
        success: false,
        error: {
          code: 'INVALID_CREDENTIALS',
          message: 'Invalid credentials',
          details: 'Email or password is incorrect',
        },
      });
    }

    // Verify password
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({
        success: false,
        error: {
          code: 'INVALID_CREDENTIALS',
          message: 'Invalid credentials',
          details: 'Email or password is incorrect',
        },
      });
    }

    // Generate token
    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      config.JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      success: true,
      message: 'Login successful',
      data: {
        user: {
          id: user.id,
          name: user.name,
          email: user.email,
          role: user.role,
        },
        token,
      },
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: {
        code: 'LOGIN_FAILED',
        message: 'Login failed',
        details: 'Please try again',
      },
    });
  }
});

// Get current user profile
router.get('/me', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);

    res.json({
      success: true,
      data: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        created_at: user.created_at,
      },
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: {
        code: 'PROFILE_FETCH_FAILED',
        message: 'Failed to fetch profile',
        details: 'Please try again',
      },
    });
  }
});

module.exports = router;
```

---

## 🚀 Implementation Guidelines

### Route Organization Pattern

```javascript
// src/routes/users.js - Example resource routes
const express = require('express');
const {
  validateUserCreation,
  validateUserUpdate,
  validateId,
  validatePagination,
} = require('../middleware/validation');
const {
  authenticateToken,
  requireRole,
  requireOwnership,
} = require('../middleware/auth');

const router = express.Router();

// Public routes (no auth required)
router.get('/', validatePagination, getUserList);

// Protected routes (auth required)
router.use(authenticateToken);

router.get('/:id', validateId, getUser);
router.post('/', validateUserCreation, createUser);
router.put(
  '/:id',
  validateId,
  validateUserUpdate,
  requireOwnership('id'),
  updateUser
);
router.delete('/:id', validateId, requireOwnership('id'), deleteUser);

// Admin only routes
router.get('/:id/admin-data', validateId, requireRole(['admin']), getAdminData);

module.exports = router;
```

### Error Handling Best Practices

```javascript
// src/middleware/errorHandler.js
const errorHandler = (err, req, res, next) => {
  // Log error for debugging (not in production logs)
  console.error('Error:', err);

  // Default error response
  let statusCode = 500;
  let errorResponse = {
    success: false,
    error: {
      code: 'INTERNAL_SERVER_ERROR',
      message: 'An unexpected error occurred',
      details: 'Please try again later',
    },
  };

  // Custom error handling
  if (err.name === 'ValidationError') {
    statusCode = 422;
    errorResponse.error = {
      code: 'VALIDATION_ERROR',
      message: 'Validation failed',
      details: err.message,
    };
  }

  if (err.code === 'ENOTFOUND' || err.code === 'ECONNREFUSED') {
    statusCode = 503;
    errorResponse.error = {
      code: 'SERVICE_UNAVAILABLE',
      message: 'External service unavailable',
      details: 'Please try again later',
    };
  }

  res.status(statusCode).json(errorResponse);
};

module.exports = errorHandler;
```

---

**💡 Pro Tips for Hackathon APIs:**

1. **Start Simple**: Begin with basic CRUD operations, add complexity later
2. **Consistent Structure**: Use the same response format across all endpoints
3. **Clear Error Messages**: Help frontend developers understand what went wrong
4. **Authentication Last**: Build core functionality first, add auth when needed
5. **Document Everything**: Good API docs save hours of debugging time
6. **Test Early**: Use tools like Postman or curl to test endpoints immediately
