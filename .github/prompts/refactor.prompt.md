# Refactoring Prompt Template

Use this template when requesting code refactoring from AI assistance. Copy and fill in the placeholders before submitting your request.

---

## 🔄 Refactoring Request

### Target Component

`[COMPONENT_NAME]` - File/function/module to be refactored

### Refactoring Type

- [ ] 🏗️ **Architectural** - Major structure changes
- [ ] ⚡ **Performance** - Speed/memory optimization
- [ ] 📖 **Readability** - Code clarity improvement
- [ ] 🧹 **Technical Debt** - Legacy code cleanup
- [ ] 🔧 **Maintainability** - Easier future changes
- [ ] 🛡️ **Security** - Security improvements
- [ ] 📏 **Standards** - Code style compliance

---

## 📋 Current Code Assessment

### Code Location

**Primary Files:**

```
[List the main files to be refactored]
src/[component].js           # [Brief description of current state]
tests/[component].test.js    # [Current test coverage status]
```

**Related Files:**

```
[List files that might be affected by the refactoring]
src/app.js                   # [How it's connected]
src/routes/[related].js      # [Dependencies]
```

### Current Code State

```javascript
// Paste the current code that needs refactoring
[CURRENT_CODE_BLOCK];
```

### Issues with Current Code

- [ ] **Performance Issues:** `[e.g., O(n²) algorithm, memory leaks, blocking operations]`
- [ ] **Readability Problems:** `[e.g., unclear naming, complex nested logic, missing comments]`
- [ ] **Maintainability Issues:** `[e.g., code duplication, tight coupling, hard to test]`
- [ ] **Technical Debt:** `[e.g., outdated patterns, deprecated APIs, workarounds]`
- [ ] **Standards Violations:** `[e.g., functions >20 lines, console.log usage, missing error handling]`
- [ ] **Security Concerns:** `[e.g., input validation, data exposure, unsafe operations]`

### Code Metrics (Current State)

```
[If available, include current metrics]
- Function length: [X lines]
- Cyclomatic complexity: [X]
- Test coverage: [X%]
- Performance benchmarks: [X ms/operations]
- Dependencies: [X external packages]
```

---

## 🎯 Refactoring Goals

### Primary Objectives

- [ ] **Performance:** `[Specific performance target, e.g., "Reduce API response time from 500ms to <100ms"]`
- [ ] **Readability:** `[Specific readability goal, e.g., "Make function purpose clear to junior developers"]`
- [ ] **Maintainability:** `[Specific maintainability goal, e.g., "Enable easy addition of new validation rules"]`
- [ ] **Testability:** `[Specific testing goal, e.g., "Achieve 100% unit test coverage"]`
- [ ] **Standards Compliance:** `[Specific standards, e.g., "Follow 20-line function rule, async/await only"]`

### Success Metrics

**Performance Targets:**

```
[Define measurable performance improvements]
- Response time: [current] → [target]
- Memory usage: [current] → [target]
- Throughput: [current] → [target]
```

**Code Quality Targets:**

```
[Define measurable quality improvements]
- Function length: [current avg] → [target max 20 lines]
- Test coverage: [current %] → [target 100%]
- Complexity: [current] → [target]
```

### Business Impact

```
[Explain why this refactoring matters for the hackathon/project]
- User Experience: [How it improves UX]
- Development Speed: [How it helps team velocity]
- Demo Readiness: [How it supports demo/presentation]
- Technical Foundation: [How it enables future features]
```

---

## 🛡️ Safety Requirements

### Behavior Preservation

- [ ] **Functional Equivalence:** All existing functionality must work identically
- [ ] **API Compatibility:** Public interfaces must remain unchanged
- [ ] **Data Integrity:** No data loss or corruption
- [ ] **Error Handling:** Existing error scenarios handled consistently

### Testing Strategy

```
[Define comprehensive testing approach]

Pre-Refactoring:
1. Document current behavior with tests
2. Establish baseline performance metrics
3. Create integration test suite
4. Verify all existing tests pass

During Refactoring:
1. Maintain test-first approach
2. Refactor tests alongside code
3. Use red-green-refactor cycle
4. Verify tests at each step

Post-Refactoring:
1. All tests must pass
2. Performance benchmarks met
3. Code coverage maintained/improved
4. Integration tests verify behavior
```

### Rollback Plan

```
[Define how to rollback if issues arise]
- Git branch strategy: [e.g., feature/refactor-component-name]
- Backup approach: [e.g., tag current version before starting]
- Testing checkpoints: [e.g., commit after each major step]
- Deployment safety: [e.g., can deploy without breaking demo]
```

### Risk Mitigation

- [ ] **Small Steps:** Break refactoring into small, testable chunks
- [ ] **Incremental Changes:** Commit frequently with working code
- [ ] **Parallel Testing:** Keep old and new implementations during transition
- [ ] **Performance Monitoring:** Benchmark before/after each change
- [ ] **Code Review:** Have changes reviewed before merging

---

## 📚 Implementation Requirements

### Code Standards Compliance

- [ ] **Function Size:** All functions ≤ 20 lines
- [ ] **Async Patterns:** Use async/await consistently
- [ ] **Error Handling:** Comprehensive try/catch blocks
- [ ] **No Debug Code:** Remove console.log statements
- [ ] **Naming:** Clear, descriptive function/variable names
- [ ] **Documentation:** JSDoc for public interfaces

### Architecture Patterns

```
[Specify preferred architectural patterns to follow]

Preferred Patterns:
- [e.g., Pure functions where possible]
- [e.g., Dependency injection for testability]
- [e.g., Single responsibility principle]
- [e.g., Factory pattern for object creation]
```

### Performance Considerations

- [ ] **Algorithm Efficiency:** Use optimal algorithms (O(n) vs O(n²))
- [ ] **Memory Management:** Avoid memory leaks and excessive allocations
- [ ] **Async Operations:** Don't block the event loop
- [ ] **Caching:** Implement appropriate caching strategies
- [ ] **Database Queries:** Optimize query patterns if applicable

### Security Requirements

- [ ] **Input Validation:** Validate all inputs
- [ ] **Output Sanitization:** Sanitize all outputs
- [ ] **Error Information:** Don't expose sensitive data in errors
- [ ] **Dependencies:** Use secure, up-to-date packages

---

## ✅ Quality Assurance

### Pre-Refactoring Checklist

- [ ] Current code is fully tested
- [ ] Performance baseline established
- [ ] Dependencies documented
- [ ] Backup/branch created

### During Refactoring Checklist

- [ ] Tests updated alongside code changes
- [ ] Each commit maintains working state
- [ ] Performance monitored at each step
- [ ] Code standards followed

### Post-Refactoring Checklist

- [ ] All tests pass (`npm test`)
- [ ] Code style consistent (`npm run lint`)
- [ ] App starts without errors (`npm start`)
- [ ] Smoke tests pass (`curl` basic endpoints)
- [ ] Performance targets met
- [ ] Documentation updated

### Final Validation

```
[Define final validation steps]

Functional Testing:
- [ ] All original test cases pass
- [ ] New edge cases covered
- [ ] Integration tests pass
- [ ] Manual testing completed

Performance Testing:
- [ ] Benchmark comparisons documented
- [ ] Performance targets achieved
- [ ] No regression in other areas
- [ ] Memory usage acceptable

Code Quality:
- [ ] Peer review completed
- [ ] Standards compliance verified
- [ ] Documentation complete
- [ ] Technical debt reduced
```

---

## 🚀 Implementation Guidance

### Refactoring Strategy

```
[Recommended approach for this specific refactoring]

1. Analysis Phase:
   - Profile current performance
   - Document current behavior
   - Identify refactoring boundaries
   - Plan incremental steps

2. Preparation Phase:
   - Create comprehensive test suite
   - Set up performance monitoring
   - Establish success criteria
   - Create rollback plan

3. Implementation Phase:
   - Follow red-green-refactor cycle
   - Make small, incremental changes
   - Commit frequently
   - Monitor performance continuously

4. Validation Phase:
   - Run full test suite
   - Performance benchmark comparison
   - Code review and approval
   - Documentation update
```

### Code Examples

**Before (Current Pattern):**

```javascript
// Example of code that needs refactoring
[CURRENT_CODE_EXAMPLE];
```

**After (Target Pattern):**

```javascript
// Example of improved code structure
[TARGET_CODE_EXAMPLE];
```

### Testing Pattern

```javascript
// Refactoring test pattern
describe('Refactored [COMPONENT_NAME]', () => {
  describe('Behavioral Compatibility', () => {
    it('should maintain existing functionality', async () => {
      // Test that behavior is preserved
    });
  });

  describe('Performance Improvements', () => {
    it('should meet performance targets', async () => {
      // Test performance improvements
    });
  });

  describe('Code Quality', () => {
    it('should follow coding standards', () => {
      // Test code structure and patterns
    });
  });
});
```

---

## 📝 Template Usage Example

```markdown
## 🔄 Refactoring Request

### Target Component

`user-validation` - Input validation utilities in src/utils/validation.js

### Refactoring Type

- [x] ⚡ **Performance** - Speed optimization
- [x] 📖 **Readability** - Code clarity improvement
- [x] 📏 **Standards** - Code style compliance

## 📋 Current Code Assessment

### Issues with Current Code

- [x] **Performance Issues:** Nested loops causing O(n²) complexity for user data validation
- [x] **Readability Problems:** 45-line validation function with nested conditionals
- [x] **Standards Violations:** Function exceeds 20-line limit, uses callbacks instead of async/await

### Code Metrics (Current State)

- Function length: 45 lines
- Cyclomatic complexity: 12
- Test coverage: 60%
- Performance: 150ms for 100 user validation

## 🎯 Refactoring Goals

### Primary Objectives

- [x] **Performance:** Reduce validation time from 150ms to <50ms for 100 users
- [x] **Readability:** Break into smaller, single-purpose functions
- [x] **Standards Compliance:** Follow 20-line function rule, use async/await

### Success Metrics

**Performance Targets:**

- Validation time: 150ms → <50ms (for 100 users)
- Algorithm complexity: O(n²) → O(n)

**Code Quality Targets:**

- Function length: 45 lines → max 20 lines per function
- Test coverage: 60% → 95%
- Complexity: 12 → <5 per function
```

---

**💡 Pro Tip:** Start with the smallest possible refactoring that provides value. Big refactors are risky in hackathon environments!
