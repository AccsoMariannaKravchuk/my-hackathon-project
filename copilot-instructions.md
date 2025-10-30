# Copilot Instructions - Hackathon Node.js Express Project

## Project Overview

**Goal:** [TODO: Define your hackathon project goal here - e.g., "Build a REST API for real-time chat application"]

**Timeline:** Hackathon sprint (optimized for rapid, quality development)

## Technology Stack

- **Runtime:** Node.js 20+
- **Framework:** Express.js 4.x
- **Testing:** Jest with Supertest
- **Code Quality:** ESLint + Prettier
- **Development:** Nodemon for hot reload
- **Version Control:** Git with automated quality gates

## Coding Standards & Rules

### Test-Driven Development (TDD)

- **Always write tests first** or alongside implementation
- Every function must have corresponding test coverage
- Tests should be clear, focused, and fast
- Use `describe()` and `it()` for readable test structure

### Function Design

- **Maximum 20 lines per function** (excluding whitespace/comments)
- Single responsibility principle
- Pure functions where possible
- Descriptive function and variable names

### Async Programming

- **Use async/await exclusively** (no callbacks or raw Promises)
- Always handle async errors with try/catch
- Never use synchronous file system operations in production code

### Error Handling

- **Comprehensive error handling** in all async operations
- Use custom error classes for different error types
- Include meaningful error messages and status codes
- Log errors appropriately (see logging rules below)

### Logging Rules

- **NO `console.log()` in production code**
- Use structured logging for debugging during development
- Remove debug logs before committing
- Use proper HTTP status codes instead of console output

## File Organization

```
src/
├── app.js              # Express app configuration
├── server.js           # Server startup
├── routes/             # Route handlers
│   ├── index.js        # Main routes
│   ├── users.js        # User-related routes
│   └── ...
├── middleware/         # Custom middleware
├── utils/              # Utility functions
├── models/             # Data models (if applicable)
└── config/             # Configuration files

tests/
├── routes/             # Route tests (mirrors src/routes/)
├── middleware/         # Middleware tests
├── utils/              # Utility function tests
└── integration/        # End-to-end tests
```

### Naming Conventions

- **Files:** kebab-case (`user-service.js`)
- **Folders:** kebab-case (`user-routes/`)
- **Functions:** camelCase (`getUserById`)
- **Constants:** UPPER_SNAKE_CASE (`MAX_RETRY_ATTEMPTS`)

## Code Generation Guidelines

When generating code, always provide:

### 1. Implementation (< 50 lines)

```javascript
// Example: Keep functions focused and concise
const validateUser = async userData => {
  if (!userData.email) {
    throw new Error('Email is required');
  }
  // Implementation...
};
```

### 2. Corresponding Test

```javascript
// Example: Test the implementation
describe('validateUser', () => {
  it('should throw error when email is missing', async () => {
    await expect(validateUser({})).rejects.toThrow('Email is required');
  });
});
```

### 3. Integration Explanation

- Where the code fits in the project structure
- Dependencies and imports needed
- Any configuration changes required

### 4. Tradeoff Analysis

- Performance implications
- Security considerations
- Maintainability impact
- Alternative approaches considered

## Quality Gates

Before any code is committed, ensure:

### ✅ Automated Checks

```bash
npm test          # All tests must pass
npm run lint      # ESLint must pass with no errors
npm start         # App must start without errors
curl http://localhost:3000  # Basic smoke test
```

### ✅ Manual Review

- Code follows the 20-line function rule
- Tests cover new functionality
- No `console.log()` statements in production code
- Error handling is comprehensive
- Documentation is updated if needed

## Development Workflow

### Adding New Features

1. **Write failing test first** (red)
2. **Implement minimal code** to pass test (green)
3. **Refactor** for quality and maintainability
4. **Run quality gates** before commit
5. **Use `save` command** for automated commit pipeline

### Code Review Checklist

- [ ] Functions are < 20 lines
- [ ] Tests are comprehensive and pass
- [ ] Error handling is present
- [ ] No debug/console statements
- [ ] Async/await used correctly
- [ ] Files are properly organized
- [ ] Code is self-documenting

## Performance Considerations

- **Minimize dependencies** (hackathon constraint)
- **Use streaming for large data** when applicable
- **Implement proper caching** for repeated operations
- **Optimize database queries** if using persistence
- **Consider rate limiting** for public APIs

## Security Guidelines

- **Validate all inputs** at route level
- **Use helmet.js** for security headers
- **Sanitize user data** before processing
- **Implement proper CORS** configuration
- **Never expose sensitive data** in error messages
- **Use environment variables** for configuration

## Hackathon-Specific Notes

### Speed vs Quality Balance

- **Prioritize working features** over perfect architecture
- **Use proven patterns** over experimental approaches
- **Keep dependencies minimal** and well-tested
- **Focus on core functionality** first

### Common Pitfalls to Avoid

- Over-engineering early features
- Skipping tests (leads to debugging hell)
- Ignoring error handling (causes demo failures)
- Poor file organization (slows development)
- Not using the automated quality pipeline

---

## Quick Commands Reference

```bash
# Development
npm run dev         # Start with hot reload
npm test           # Run tests with coverage
npm run lint       # Check code style
npm run lint:fix   # Auto-fix style issues

# Quality Pipeline
save               # Auto: test → lint → smoke test → commit → push
save "Custom message"  # With custom commit message
```

Remember: **Quality at speed is the hackathon advantage!**
