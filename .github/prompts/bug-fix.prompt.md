# Bug Fix Prompt Template

Use this template when reporting bugs and requesting fixes from AI assistance. Copy and fill in the placeholders before submitting your request.

---

## 🐛 Bug Report

### Bug Title

`[BUG_TITLE]` - Clear, concise description of the issue

### Severity Level

- [ ] 🚨 **Critical** - Blocks demo/deployment
- [ ] ⚠️ **High** - Major feature broken
- [ ] 🟡 **Medium** - Minor feature issue
- [ ] 🔵 **Low** - Cosmetic/enhancement

### Environment

- **Node.js Version:** `[e.g., v20.19.5]`
- **OS:** `[e.g., Linux, macOS, Windows]`
- **Browser:** `[e.g., Chrome 118, Firefox 119, N/A for API]`
- **Deployment:** `[e.g., Local dev, Docker container, Production]`

---

## 📋 Error Information

### Error Message

```
[Paste the exact error message, stack trace, or console output]
```

### Steps to Reproduce

1. `[Step 1: e.g., Start the server with npm start]`
2. `[Step 2: e.g., Send POST request to /api/users]`
3. `[Step 3: e.g., Check response status]`
4. `[Result: Error occurs]`

### Expected Behavior

```
[Describe what should happen]
```

### Actual Behavior

```
[Describe what actually happens]
```

### Screenshots/Logs (if applicable)

```
[Paste relevant log entries, error screenshots, or network traces]
```

---

## 🔍 Investigation Checklist

### Recent Changes

- [ ] **Last Working Version:** `[Git commit hash or timestamp when it worked]`
- [ ] **Recent Commits:** `[List any recent changes that might be related]`
- [ ] **Dependencies:** `[Any recently added/updated packages]`
- [ ] **Configuration:** `[Environment variables, config files changed]`

### Current Status Check

- [ ] **Tests Status:**
  ```bash
  npm test
  # Output: [PASS/FAIL with details]
  ```
- [ ] **Linting Status:**
  ```bash
  npm run lint
  # Output: [PASS/FAIL with details]
  ```
- [ ] **Server Status:**
  ```bash
  npm start
  # Output: [SUCCESS/ERROR with details]
  ```

### Log Analysis

```bash
# Check for relevant logs
[Include any relevant log entries from:]
- Console output
- Error logs
- Network requests
- Database queries (if applicable)
```

### Affected Components

- [ ] **Routes:** `[List affected API endpoints]`
- [ ] **Middleware:** `[List affected middleware functions]`
- [ ] **Utils:** `[List affected utility functions]`
- [ ] **Tests:** `[List failing test files]`
- [ ] **Dependencies:** `[List suspect packages]`

---

## 🔧 Fix Requirements

### Root Cause Analysis

```
[What is causing this issue? Fill after investigation or leave for AI to determine]

Suspected Causes:
- [ ] Logic error in [specific function/file]
- [ ] Missing error handling
- [ ] Race condition in async code
- [ ] Invalid input validation
- [ ] Dependency version conflict
- [ ] Configuration issue
- [ ] Environment-specific problem
```

### Fix Specifications

- [ ] **Preserve Existing Functionality:** Don't break working features
- [ ] **Minimal Impact:** Change as little code as possible
- [ ] **Follow Standards:** Maintain code quality standards
- [ ] **Performance:** Don't degrade performance
- [ ] **Security:** Don't introduce security vulnerabilities

### Testing Requirements

- [ ] **Fix Verification:** Test that reproduces the bug now passes
- [ ] **Regression Tests:** Existing tests still pass
- [ ] **Edge Cases:** Related edge cases are covered
- [ ] **Integration:** End-to-end functionality works

### Error Handling Improvements

- [ ] **Input Validation:** Add/improve input validation if needed
- [ ] **Error Messages:** Provide clear, actionable error messages
- [ ] **Logging:** Add appropriate logging for debugging
- [ ] **Graceful Degradation:** Handle errors gracefully

---

## 📚 Documentation Requirements

### Code Documentation

- [ ] **Inline Comments:** Explain complex fix logic
- [ ] **JSDoc Updates:** Update function documentation if signatures change
- [ ] **README Updates:** Update docs if user-facing behavior changes

### Fix Documentation

```
[Document the fix approach and reasoning]

Fix Summary:
- Root Cause: [Brief explanation]
- Solution: [What was changed and why]
- Prevention: [How to avoid this in future]
```

---

## ✅ Success Criteria

### Functional Requirements

- [ ] Bug no longer reproducible using original steps
- [ ] All existing functionality remains intact
- [ ] Performance is maintained or improved
- [ ] Error handling is robust

### Quality Gates

- [ ] All tests pass (`npm test`)
- [ ] Code style consistent (`npm run lint`)
- [ ] App starts without errors (`npm start`)
- [ ] Smoke tests pass (`curl` basic endpoints)

### Long-term Stability

- [ ] Fix addresses root cause, not just symptoms
- [ ] Added tests prevent regression
- [ ] Code is maintainable and understandable
- [ ] Documentation is updated

---

## 🚀 Implementation Guidance

### Debugging Strategy

```
[Preferred debugging approach for this type of issue]

1. Reproduce the issue consistently
2. Isolate the failing component
3. Add targeted logging/debugging
4. Identify root cause
5. Implement minimal fix
6. Verify fix with comprehensive testing
```

### Code Quality Standards

```javascript
// Example: Proper error handling pattern
const processUserData = async userData => {
  try {
    validateUserInput(userData);
    const result = await userService.process(userData);
    return { success: true, data: result };
  } catch (error) {
    logger.error('User processing failed', { userData, error });
    throw new APIError('User processing failed', 400, error);
  }
};
```

### Testing Pattern

```javascript
// Example: Test for the bug fix
describe('Bug Fix: [BUG_TITLE]', () => {
  it('should handle [specific scenario] correctly', async () => {
    // Arrange: Set up the exact conditions that caused the bug
    const testData = {
      /* data that triggered the bug */
    };

    // Act: Perform the action that was failing
    const result = await functionThatWasBroken(testData);

    // Assert: Verify the fix works
    expect(result).toMatchExpected();
    expect(result.error).toBeUndefined();
  });
});
```

---

## 📝 Template Usage Example

```markdown
## 🐛 Bug Report

### Bug Title

`POST /api/users returns 500 instead of validation error`

### Severity Level

- [x] ⚠️ **High** - Major feature broken

### Environment

- **Node.js Version:** v20.19.5
- **OS:** Linux (Docker container)
- **Browser:** N/A (API issue)
- **Deployment:** Local dev

## 📋 Error Information

### Error Message
```

Error: Cannot read property 'email' of undefined
at validateUser (/workspace/src/utils/validation.js:15:23)
at /workspace/src/routes/users.js:12:24

```

### Steps to Reproduce
1. Start server with `npm start`
2. Send POST to `/api/users` with empty body: `curl -X POST http://localhost:3000/api/users -H "Content-Type: application/json" -d "{}"`
3. Server returns 500 error instead of 400 validation error

### Expected Behavior
Should return 400 status with validation error message: "Email is required"

### Actual Behavior
Returns 500 status with generic error message, crashes validation function
```

---

**💡 Pro Tip:** Include as much detail as possible. The more context you provide, the faster and more accurate the fix will be!
