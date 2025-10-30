# Feature Request Prompt Template

Use this template when requesting new features from AI assistance. Copy and fill in the placeholders before submitting your request.

---

## 🎯 Feature Context

### Feature Name

`[FEATURE_NAME]` - Brief, descriptive name for the feature

### Problem Statement

**What problem does this solve?**

```
[Describe the current pain point or missing functionality]
```

**Why is this needed now?**

```
[Business justification, user need, or technical requirement]
```

### Constraints & Requirements

- **Timeline:** `[e.g., "Must be completed in next 2 hours for demo"]`
- **Performance:** `[e.g., "Response time < 200ms", "Handle 1000 concurrent users"]`
- **Dependencies:** `[e.g., "Must work with existing auth middleware"]`
- **Browser/Platform:** `[e.g., "Chrome/Firefox support required"]`
- **Data Format:** `[e.g., "JSON API responses", "RESTful endpoints"]`

---

## 📋 Implementation Requirements

### Technical Specifications

```
[Detailed technical requirements - API endpoints, data structures, algorithms, etc.]
```

### Acceptance Criteria

- [ ] `[Specific, testable criteria 1]`
- [ ] `[Specific, testable criteria 2]`
- [ ] `[Specific, testable criteria 3]`
- [ ] `[Additional criteria as needed]`

### Affected Files

**New Files:**

```
[List new files to be created with their purposes]
src/routes/[feature-name].js     # Route handlers
src/utils/[feature-name].js      # Business logic
tests/routes/[feature-name].test.js  # Route tests
tests/utils/[feature-name].test.js   # Unit tests
```

**Modified Files:**

```
[List existing files that need changes]
src/app.js                       # [Why: Add new route registration]
package.json                     # [Why: New dependencies if needed]
README.md                        # [Why: Update API documentation]
```

---

## 🧪 Quality Requirements

### Testing Strategy

- [ ] **Unit Tests:** All new functions have comprehensive test coverage
- [ ] **Integration Tests:** API endpoints tested with supertest
- [ ] **Edge Cases:** Error scenarios and boundary conditions covered
- [ ] **Happy Path:** Main use case thoroughly tested

### Error Handling Requirements

- [ ] **Input Validation:** All user inputs validated and sanitized
- [ ] **Async Error Handling:** All async operations wrapped in try/catch
- [ ] **HTTP Status Codes:** Appropriate status codes for all responses
- [ ] **Error Messages:** User-friendly error messages (no stack traces)

### Code Quality Standards

- [ ] **Function Size:** All functions ≤ 20 lines
- [ ] **Async/Await:** No callbacks or raw promises
- [ ] **No Console.log:** Production code free of debug statements
- [ ] **ESLint Clean:** Code passes all linting rules
- [ ] **Documentation:** JSDoc comments for public functions

---

## 📚 Documentation Requirements

### API Documentation

```
[Specify what API docs need to be created/updated]

Endpoint: [METHOD] /api/[endpoint]
Description: [What it does]
Request Format: [JSON schema or example]
Response Format: [JSON schema or example]
Error Responses: [List possible error codes and meanings]
```

### Code Documentation

- [ ] **README Updates:** Feature usage instructions added
- [ ] **Inline Comments:** Complex logic explained
- [ ] **JSDoc:** Function signatures documented
- [ ] **Examples:** Usage examples provided

---

## ✅ Success Criteria Checklist

### Functionality

- [ ] Feature works as specified in acceptance criteria
- [ ] All edge cases handled gracefully
- [ ] Performance meets specified requirements
- [ ] Integration with existing code seamless

### Code Quality

- [ ] All tests pass (`npm test`)
- [ ] Code style consistent (`npm run lint`)
- [ ] App starts without errors (`npm start`)
- [ ] Smoke tests pass (`curl` basic endpoints)

### Documentation

- [ ] API endpoints documented
- [ ] README updated with new feature info
- [ ] Code is self-documenting with good naming

### Security & Performance

- [ ] Input validation implemented
- [ ] No sensitive data exposed
- [ ] Performance benchmarks met
- [ ] Error handling comprehensive

---

## 🚀 Implementation Guidance

### Preferred Patterns

```
[Specify any architectural patterns or existing code styles to follow]
```

### Example Code Style

```javascript
// Preferred async function pattern
const createUser = async userData => {
  try {
    validateUserData(userData);
    const user = await userService.create(userData);
    return { success: true, data: user };
  } catch (error) {
    throw new APIError('User creation failed', 400, error);
  }
};
```

### Dependencies

**Allowed:** `[List approved libraries/packages]`
**Restricted:** `[List packages to avoid and why]`

---

## 📝 Template Usage Example

```markdown
## 🎯 Feature Context

### Feature Name

`user-authentication` - JWT-based user login/logout system

### Problem Statement

**What problem does this solve?**
Currently, the API has no authentication mechanism, making all endpoints publicly accessible.

**Why is this needed now?**
Demo requires user-specific data and admin-only endpoints for the hackathon presentation.

### Constraints & Requirements

- **Timeline:** Must be completed in next 3 hours for demo
- **Performance:** Login response time < 100ms
- **Dependencies:** Must work with existing Express middleware
- **Security:** JWT tokens, bcrypt password hashing

### Acceptance Criteria

- [ ] POST /api/auth/login accepts email/password and returns JWT
- [ ] POST /api/auth/logout invalidates JWT token
- [ ] Middleware protects routes requiring authentication
- [ ] Passwords are hashed with bcrypt
- [ ] Invalid credentials return 401 status
```

---

**💡 Pro Tip:** The more specific and detailed your request, the better the AI can help you implement exactly what you need for your hackathon success!
