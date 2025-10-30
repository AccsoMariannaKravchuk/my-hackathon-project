# Testing Strategy Instructions

Comprehensive testing guidelines for building reliable, maintainable test suites in this hackathon project.

---

## 🧪 Test Structure and Boundaries

### Test Pyramid Overview

```
        🔺 E2E Tests (Few)
       🔸🔸🔸 Integration Tests (Some)
    🔹🔹🔹🔹🔹🔹🔹 Unit Tests (Many)
```

### Test Type Definitions

#### Unit Tests (70-80% of tests)

**Purpose:** Test individual functions/methods in isolation
**Scope:** Single function, class, or module
**Speed:** Fast (<1ms per test)
**Dependencies:** All external dependencies mocked

```javascript
// Example: Unit test for utility function
describe('validateEmail', () => {
  it('should return true for valid email', () => {
    const result = validateEmail('user@example.com');
    expect(result).toBe(true);
  });

  it('should return false for invalid email', () => {
    const result = validateEmail('invalid-email');
    expect(result).toBe(false);
  });
});
```

#### Integration Tests (15-25% of tests)

**Purpose:** Test component interactions and API endpoints
**Scope:** Multiple modules, database interactions, API routes
**Speed:** Medium (10-100ms per test)
**Dependencies:** Real database (test env), mocked external APIs

```javascript
// Example: Integration test for API endpoint
describe('POST /api/users', () => {
  beforeEach(async () => {
    await clearTestDatabase();
  });

  it('should create user and return 201', async () => {
    const userData = {
      name: 'John Doe',
      email: 'john@example.com',
      password: 'password123',
    };

    const response = await request(app)
      .post('/api/users')
      .send(userData)
      .expect(201);

    expect(response.body.success).toBe(true);
    expect(response.body.data.email).toBe(userData.email);
  });
});
```

#### End-to-End Tests (5-10% of tests)

**Purpose:** Test complete user workflows
**Scope:** Full application stack, real user scenarios  
**Speed:** Slow (1-10s per test)
**Dependencies:** Real or staging environment

```javascript
// Example: E2E test for user registration flow
describe('User Registration Flow', () => {
  it('should allow user to register and login', async () => {
    // Register new user
    const registerResponse = await request(app)
      .post('/api/auth/register')
      .send({
        name: 'Test User',
        email: 'test@example.com',
        password: 'password123',
      })
      .expect(201);

    const token = registerResponse.body.data.token;

    // Use token to access protected route
    const profileResponse = await request(app)
      .get('/api/auth/me')
      .set('Authorization', `Bearer ${token}`)
      .expect(200);

    expect(profileResponse.body.data.email).toBe('test@example.com');
  });
});
```

---

## 📁 Test Organization and File Structure

### Directory Structure

```
tests/
├── unit/                    # Unit tests mirror src structure
│   ├── utils/
│   │   ├── validation.test.js
│   │   └── helpers.test.js
│   ├── middleware/
│   │   ├── auth.test.js
│   │   └── validation.test.js
│   └── services/
│       └── user-service.test.js
├── integration/             # Integration tests by feature
│   ├── routes/
│   │   ├── users.test.js
│   │   ├── auth.test.js
│   │   └── orders.test.js
│   └── middleware/
│       └── auth-flow.test.js
├── e2e/                     # End-to-end tests by user journey
│   ├── user-registration.test.js
│   ├── order-management.test.js
│   └── admin-workflows.test.js
├── fixtures/                # Test data and fixtures
│   ├── users.json
│   └── sample-requests.json
├── helpers/                 # Test utilities and setup
│   ├── test-setup.js
│   ├── database-helpers.js
│   └── mock-helpers.js
└── __mocks__/              # Manual mocks for modules
    ├── jwt.js
    └── bcrypt.js
```

### File Naming Conventions

#### Test Files

```bash
# Unit tests - mirror source file structure
src/utils/validation.js     → tests/unit/utils/validation.test.js
src/middleware/auth.js      → tests/unit/middleware/auth.test.js

# Integration tests - group by feature/route
/api/users endpoints        → tests/integration/routes/users.test.js
/api/auth endpoints         → tests/integration/routes/auth.test.js

# E2E tests - describe user workflows
User registration journey   → tests/e2e/user-registration.test.js
Admin management flow      → tests/e2e/admin-workflows.test.js
```

#### Test Suite Naming

```javascript
// Format: [Component] - [Functionality]
describe('UserService - createUser', () => {});
describe('AuthMiddleware - token validation', () => {});
describe('POST /api/users - user creation', () => {});

// For nested functionality
describe('UserService', () => {
  describe('createUser', () => {
    describe('with valid data', () => {});
    describe('with invalid email', () => {});
  });
});
```

#### Test Case Naming

```javascript
// Format: should [expected behavior] when [condition]
it('should return user data when valid ID provided', () => {});
it('should throw error when user not found', () => {});
it('should hash password when creating user', () => {});

// For negative cases
it('should reject invalid email format', () => {});
it('should handle database connection error', () => {});

// For edge cases
it('should handle empty request body gracefully', () => {});
it('should limit results when no pagination specified', () => {});
```

---

## 🎭 Mock vs Real Dependencies Guidelines

### When to Use Mocks

#### External Services (Always Mock)

```javascript
// Mock external APIs
jest.mock('axios');
const mockedAxios = axios as jest.Mocked<typeof axios>;

describe('PaymentService', () => {
  it('should process payment via external API', async () => {
    mockedAxios.post.mockResolvedValue({
      data: { success: true, transaction_id: '123' }
    });

    const result = await paymentService.processPayment(paymentData);
    expect(result.success).toBe(true);
  });
});

// Mock email service
jest.mock('../services/email-service');
const mockEmailService = emailService as jest.Mocked<typeof emailService>;

beforeEach(() => {
  mockEmailService.sendEmail.mockClear();
});
```

#### Time-Dependent Functions

```javascript
// Mock Date for consistent tests
jest.useFakeTimers();
jest.setSystemTime(new Date('2025-10-30T12:00:00Z'));

describe('TokenService', () => {
  it('should generate token with correct expiry', () => {
    const token = tokenService.generateToken(userId);
    const decoded = jwt.decode(token);
    expect(decoded.exp).toBe(Math.floor(Date.now() / 1000) + 3600);
  });
});
```

#### File System Operations

```javascript
// Mock fs operations
jest.mock('fs/promises');
const mockFs = fs as jest.Mocked<typeof fs>;

describe('FileService', () => {
  it('should read config file', async () => {
    mockFs.readFile.mockResolvedValue('{"setting": "value"}');

    const config = await fileService.loadConfig();
    expect(config.setting).toBe('value');
  });
});
```

### When to Use Real Dependencies

#### Database Operations (Integration Tests)

```javascript
// Use real database for integration tests
describe('UserRepository Integration', () => {
  let testDb;

  beforeAll(async () => {
    testDb = await setupTestDatabase();
  });

  beforeEach(async () => {
    await clearTestDatabase();
  });

  afterAll(async () => {
    await teardownTestDatabase();
  });

  it('should save and retrieve user', async () => {
    const userData = { name: 'John', email: 'john@example.com' };
    const savedUser = await userRepository.create(userData);
    const retrievedUser = await userRepository.findById(savedUser.id);

    expect(retrievedUser.email).toBe(userData.email);
  });
});
```

#### Internal Module Dependencies

```javascript
// Don't mock internal modules in integration tests
describe('UserService Integration', () => {
  it('should validate and save user', async () => {
    // Real validation + real repository
    const userData = {
      name: 'John',
      email: 'john@example.com',
      password: '123456',
    };

    await expect(userService.createUser(userData)).rejects.toThrow(
      'Password too weak'
    );
  });
});
```

### Mock Implementation Patterns

#### Service Layer Mocks

```javascript
// src/services/__mocks__/user-service.js
const mockUserService = {
  createUser: jest.fn(),
  findById: jest.fn(),
  updateUser: jest.fn(),
  deleteUser: jest.fn(),
};

// Default implementations
mockUserService.findById.mockImplementation(id => {
  if (id === 999) return null;
  return { id, name: 'Mock User', email: 'mock@example.com' };
});

module.exports = mockUserService;
```

#### Database Mocks

```javascript
// tests/helpers/mock-database.js
const createMockDatabase = () => {
  const data = new Map();

  return {
    users: {
      create: jest.fn().mockImplementation(userData => {
        const user = { id: Date.now(), ...userData };
        data.set(user.id, user);
        return user;
      }),

      findById: jest.fn().mockImplementation(id => {
        return data.get(id) || null;
      }),

      findAll: jest.fn().mockImplementation(() => {
        return Array.from(data.values());
      }),
    },

    clear: () => data.clear(),
  };
};

module.exports = createMockDatabase;
```

---

## 📊 Coverage Expectations and Quality Metrics

### Coverage Targets

#### Overall Coverage Goals

```bash
# Minimum acceptable coverage
Statement Coverage:   ≥ 80%
Branch Coverage:      ≥ 75%
Function Coverage:    ≥ 85%
Line Coverage:        ≥ 80%

# Hackathon realistic targets
Statement Coverage:   ≥ 70%
Branch Coverage:      ≥ 65%
Function Coverage:    ≥ 75%
Line Coverage:        ≥ 70%
```

#### Component-Specific Targets

```javascript
// High-risk areas (require higher coverage)
// Authentication: ≥ 95%
// Validation: ≥ 90%
// Payment processing: ≥ 95%
// Data sanitization: ≥ 90%

// Medium-risk areas
// Business logic: ≥ 80%
// API routes: ≥ 75%
// Utilities: ≥ 80%

// Lower-risk areas
// Configuration: ≥ 60%
// Logging: ≥ 50%
// Static content: ≥ 40%
```

### Jest Configuration

```javascript
// jest.config.js
module.exports = {
  testEnvironment: 'node',
  roots: ['<rootDir>/src', '<rootDir>/tests'],
  testMatch: ['**/__tests__/**/*.js', '**/?(*.)+(spec|test).js'],
  collectCoverageFrom: [
    'src/**/*.{js,jsx}',
    '!src/**/*.d.ts',
    '!src/config/**',
    '!src/**/*.config.js',
  ],
  coverageThreshold: {
    global: {
      branches: 70,
      functions: 75,
      lines: 70,
      statements: 70,
    },
    './src/middleware/auth.js': {
      branches: 90,
      functions: 95,
      lines: 90,
      statements: 90,
    },
    './src/utils/validation.js': {
      branches: 85,
      functions: 90,
      lines: 85,
      statements: 85,
    },
  },
  coverageReporters: ['text', 'lcov', 'html'],
  setupFilesAfterEnv: ['<rootDir>/tests/helpers/test-setup.js'],
};
```

### Quality Metrics Beyond Coverage

#### Test Quality Indicators

```javascript
// Mutation testing score (if time permits)
// Target: >75% mutation score

// Test execution speed
// Unit tests: <100ms total
// Integration tests: <5s total
// E2E tests: <30s total

// Test maintenance metrics
// Test-to-code ratio: 1:1 to 2:1
// Test update frequency: Updated with every feature
// Flaky test rate: <2% of all tests
```

#### Coverage Reporting

```bash
# Generate coverage reports
npm test -- --coverage

# Coverage badges for README
npm install --save-dev jest-coverage-badges
npx jest-coverage-badges

# HTML coverage report
npm test -- --coverage --coverageReporters=html
# Open coverage/lcov-report/index.html
```

---

## 🔄 TDD Workflow and Best Practices

### Red-Green-Refactor Cycle

#### 1. Red Phase (Write Failing Test)

```javascript
// Example: Testing user creation validation
describe('UserService - createUser', () => {
  it('should throw error when email is missing', async () => {
    const userData = { name: 'John Doe', password: 'password123' };

    // This should fail because we haven't implemented validation yet
    await expect(userService.createUser(userData)).rejects.toThrow(
      'Email is required'
    );
  });
});

// Run test: npm test
// Expected result: ❌ Test fails (no implementation yet)
```

#### 2. Green Phase (Make Test Pass)

```javascript
// src/services/user-service.js
const createUser = async userData => {
  // Minimal implementation to make test pass
  if (!userData.email) {
    throw new Error('Email is required');
  }

  // TODO: Add full implementation
  return { id: 1, ...userData };
};
```

#### 3. Refactor Phase (Improve Code Quality)

```javascript
// Refactor with proper validation and error handling
const createUser = async userData => {
  // Extract validation to separate function
  validateUserData(userData);

  // Hash password
  const hashedPassword = await hashPassword(userData.password);

  // Save to database
  return await userRepository.create({
    ...userData,
    password: hashedPassword,
  });
};

const validateUserData = userData => {
  if (!userData.email) {
    throw new ValidationError('Email is required');
  }
  if (!isValidEmail(userData.email)) {
    throw new ValidationError('Invalid email format');
  }
  // Additional validations...
};
```

### TDD Best Practices

#### Start with the Interface

```javascript
// Design the API first through tests
describe('PaymentService', () => {
  it('should process credit card payment', async () => {
    const paymentData = {
      amount: 100.0,
      currency: 'USD',
      cardNumber: '4111111111111111',
      expiryDate: '12/25',
      cvv: '123',
    };

    const result = await paymentService.processPayment(paymentData);

    expect(result.success).toBe(true);
    expect(result.transactionId).toBeDefined();
    expect(result.amount).toBe(100.0);
  });
});
```

#### Test Edge Cases Early

```javascript
describe('UserService - createUser', () => {
  // Happy path first
  it('should create user with valid data', async () => {
    // Implementation...
  });

  // Edge cases next
  it('should handle duplicate email gracefully', async () => {
    await userService.createUser(validUserData);

    await expect(userService.createUser(validUserData)).rejects.toThrow(
      'Email already exists'
    );
  });

  it('should handle database connection error', async () => {
    // Mock database failure
    jest
      .spyOn(database, 'insert')
      .mockRejectedValue(new Error('Connection lost'));

    await expect(userService.createUser(validUserData)).rejects.toThrow(
      'User creation failed'
    );
  });
});
```

#### Triangulation Technique

```javascript
// Test multiple examples to drive out the general solution
describe('calculateDiscount', () => {
  it('should calculate 10% discount for regular customers', () => {
    expect(calculateDiscount(100, 'regular')).toBe(10);
  });

  it('should calculate 20% discount for premium customers', () => {
    expect(calculateDiscount(100, 'premium')).toBe(20);
  });

  it('should calculate 0% discount for new customers', () => {
    expect(calculateDiscount(100, 'new')).toBe(0);
  });

  // This drives out the general implementation
});
```

### TDD Workflow Integration

#### Pre-commit TDD Checklist

```bash
# Before committing any feature
- [ ] Test written first (Red)
- [ ] Minimal implementation (Green)
- [ ] Code refactored (Clean)
- [ ] All tests pass
- [ ] No test skipped or disabled
- [ ] Coverage maintained/improved
```

#### TDD with Save Command Integration

```bash
# The save command runs tests automatically
save "Implement user validation with TDD"

# This ensures:
# 1. All tests pass (including new TDD tests)
# 2. Code style is consistent
# 3. App starts without errors
# 4. Smoke tests verify integration
```

### Common TDD Pitfalls to Avoid

#### Don't Write Too Much Test Code

```javascript
// ❌ Bad: Testing implementation details
it('should call bcrypt.hash with salt rounds 12', async () => {
  const spy = jest.spyOn(bcrypt, 'hash');
  await userService.createUser(userData);
  expect(spy).toHaveBeenCalledWith(userData.password, 12);
});

// ✅ Good: Testing behavior
it('should store hashed password, not plain text', async () => {
  const user = await userService.createUser(userData);
  const storedUser = await userRepository.findById(user.id);
  expect(storedUser.password).not.toBe(userData.password);
  expect(storedUser.password).toMatch(/^\$2[aby]\$\d+\$/); // bcrypt format
});
```

#### Don't Skip the Red Phase

```javascript
// ❌ Bad: Writing test after implementation
// (Test might pass accidentally)

// ✅ Good: Always verify the test fails first
// 1. Write test
// 2. Run test (should fail)
// 3. Implement feature
// 4. Run test (should pass)
```

#### Keep Tests Simple and Focused

```javascript
// ❌ Bad: Testing multiple things in one test
it('should create user, send email, and log activity', async () => {
  // Too much responsibility
});

// ✅ Good: One assertion per test
it('should create user with hashed password', async () => {
  // Focus on user creation
});

it('should send welcome email after user creation', async () => {
  // Focus on email sending
});

it('should log user creation activity', async () => {
  // Focus on logging
});
```

---

## 🚀 Hackathon-Specific Testing Strategy

### Time-Boxed Testing Approach

#### Phase 1: Core Functionality (Hours 0-4)

```bash
Priority 1: Critical path tests only
- User registration/login
- Core API endpoints
- Basic validation
Target: 40-50% coverage
```

#### Phase 2: Error Handling (Hours 4-8)

```bash
Priority 2: Error scenarios
- Invalid inputs
- Authentication failures
- Database errors
Target: 60-70% coverage
```

#### Phase 3: Edge Cases (Hours 8-12)

```bash
Priority 3: Polish and edge cases
- Performance edge cases
- Integration scenarios
- Full user workflows
Target: 70-80% coverage
```

### Quick Testing Templates

#### API Endpoint Test Template

```javascript
describe('{{HTTP_METHOD}} {{ENDPOINT}}', () => {
  describe('Success Cases', () => {
    it('should return {{EXPECTED_STATUS}} with valid data', async () => {
      const response = await request(app)
        .{{method}}('{{endpoint}}')
        .send({{validData}})
        .expect({{expectedStatus}});

      expect(response.body.success).toBe(true);
      // Add specific assertions
    });
  });

  describe('Error Cases', () => {
    it('should return 400 with invalid data', async () => {
      const response = await request(app)
        .{{method}}('{{endpoint}}')
        .send({{invalidData}})
        .expect(400);

      expect(response.body.success).toBe(false);
      expect(response.body.error.code).toBe('VALIDATION_ERROR');
    });

    it('should return 401 without authentication', async () => {
      await request(app)
        .{{method}}('{{endpoint}}')
        .send({{validData}})
        .expect(401);
    });
  });
});
```

#### Service Layer Test Template

```javascript
describe('{{ServiceName}}', () => {
  describe('{{methodName}}', () => {
    beforeEach(() => {
      // Setup mocks
    });

    it('should {{expected_behavior}} when {{condition}}', async () => {
      // Arrange
      const input = {{testData}};

      // Act
      const result = await service.{{methodName}}(input);

      // Assert
      expect(result).toEqual({{expectedResult}});
    });

    it('should throw {{ErrorType}} when {{errorCondition}}', async () => {
      const input = {{invalidData}};

      await expect(service.{{methodName}}(input))
        .rejects
        .toThrow('{{expectedErrorMessage}}');
    });
  });
});
```

---

**💡 Pro Tips for Hackathon Testing:**

1. **Start with Happy Path**: Get basic functionality working first
2. **Test API Contracts**: Ensure frontend/backend integration works
3. **Mock External Services**: Don't depend on third-party APIs for tests
4. **Use Test Data Builders**: Create reusable test data factories
5. **Parallel Test Execution**: Configure Jest for faster test runs
6. **Continuous Testing**: Use `npm run test:watch` during development
7. **Test the Demo Flow**: Write E2E tests for your demo scenarios
