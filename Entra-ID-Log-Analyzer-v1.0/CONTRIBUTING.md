# Contributing to Entra ID Log Analyzer

Thank you for your interest in contributing to the Entra ID Log Analyzer! This document provides guidelines and information for contributors.

## How to Contribute

### 1. Fork and Clone
```bash
# Fork the repository on GitHub, then clone your fork
git clone https://github.com/your-username/entra-id-log-analyzer.git
cd entra-id-log-analyzer

# Add upstream remote
git remote add upstream https://github.com/original-owner/entra-id-log-analyzer.git
```

### 2. Set Up Development Environment
```bash
# Install dependencies
npm install

# Start development server
npm run dev
```

### 3. Create a Branch
```bash
# Create a feature branch
git checkout -b feature/your-feature-name

# Or a bug fix branch
git checkout -b fix/bug-description
```

## Development Guidelines

### Code Style
- **TypeScript**: All new code should be written in TypeScript
- **ESLint**: Follow the existing ESLint configuration
- **Prettier**: Code formatting is handled automatically
- **Components**: Use functional components with hooks
- **Styling**: Use Tailwind CSS classes, follow existing patterns

### Component Structure
```typescript
// Component template
import { useState } from 'react'
import { SomeIcon } from '@phosphor-icons/react'
import { Button } from '@/components/ui/button'

interface ComponentProps {
  prop1: string
  prop2?: number
}

export function ComponentName({ prop1, prop2 = 0 }: ComponentProps) {
  const [state, setState] = useState('')

  return (
    <div className="space-y-4">
      {/* Component content */}
    </div>
  )
}
```

### File Naming
- **Components**: PascalCase (e.g., `ThreatSummary.tsx`)
- **Utilities**: camelCase (e.g., `securityUtils.ts`)
- **Types**: camelCase with `.types.ts` suffix (e.g., `security.types.ts`)

## Bug Reports

When reporting bugs, please include:

1. **Description**: Clear description of the issue
2. **Steps to Reproduce**: Detailed steps to reproduce the bug
3. **Expected Behavior**: What should happen
4. **Actual Behavior**: What actually happens
5. **Environment**: Browser, OS, Node.js version
6. **Screenshots**: If applicable

### Bug Report Template
```markdown
**Bug Description**
A clear description of the bug.

**To Reproduce**
1. Go to '...'
2. Click on '...'
3. See error

**Expected Behavior**
What you expected to happen.

**Screenshots**
Add screenshots if helpful.

**Environment**
- Browser: [e.g., Chrome 120]
- OS: [e.g., Windows 11]
- Node.js: [e.g., 18.17.0]
```

## Feature Requests

For new features:

1. **Check existing issues** to avoid duplicates
2. **Describe the problem** the feature would solve
3. **Propose a solution** with implementation details
4. **Consider alternatives** and their trade-offs

### Feature Request Template
```markdown
**Problem Statement**
What problem does this feature solve?

**Proposed Solution**
Detailed description of the proposed feature.

**Alternatives Considered**
Other solutions you've considered.

**Additional Context**
Screenshots, mockups, or other context.
```

## Development Areas

### Priority Areas for Contribution

1. **Security Enhancements**
   - New threat detection algorithms
   - Additional security metrics
   - Risk scoring improvements

2. **Data Visualization**
   - New chart types
   - Interactive features
   - Performance optimizations

3. **User Experience**
   - Accessibility improvements
   - Mobile responsiveness
   - Performance enhancements

4. **Documentation**
   - Code documentation
   - User guides
   - API documentation

5. **Testing**
   - Unit tests
   - Integration tests
   - E2E tests

### Code Areas
- `/src/components/` - React components
- `/src/types/` - TypeScript definitions
- `/src/lib/` - Utility functions
- `/src/hooks/` - Custom React hooks

## 🧪 Testing

### Running Tests
```bash
# Run all tests
npm test

# Run tests with coverage
npm run test:coverage

# Run linting
npm run lint

# Fix linting issues
npm run lint:fix
```

### Writing Tests
- Write tests for new components and utilities
- Follow existing test patterns
- Aim for meaningful test coverage
- Test both happy path and edge cases

## 📝 Commit Guidelines

### Commit Message Format
```
type(scope): description

[optional body]

[optional footer]
```

### Types
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Build process or auxiliary tool changes

### Examples
```bash
git commit -m "feat(analysis): add new threat correlation algorithm"
git commit -m "fix(upload): handle large file uploads correctly"
git commit -m "docs(readme): update installation instructions"
```

## 🔄 Pull Request Process

1. **Update your branch**
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

2. **Run tests and linting**
   ```bash
   npm test
   npm run lint
   ```

3. **Create pull request**
   - Use a descriptive title
   - Reference related issues
   - Provide detailed description
   - Include screenshots if UI changes

4. **PR Review Process**
   - Automated checks must pass
   - Code review by maintainers
   - Address feedback promptly
   - Maintain clean commit history

### PR Template
```markdown
## Description
Brief description of changes.

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Tests pass locally
- [ ] Added new tests
- [ ] Manual testing completed

## Screenshots
Include if UI changes.

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] No breaking changes
```

## 🎯 Getting Started Tasks

Good first issues for new contributors:

1. **Documentation improvements**
2. **UI/UX enhancements**
3. **Accessibility fixes**
4. **Performance optimizations**
5. **Test coverage improvements**

Look for issues labeled `good-first-issue` or `help-wanted`.

## 💬 Communication

- **Discussions**: Use GitHub Discussions for questions
- **Issues**: Use GitHub Issues for bugs and features
- **Code Review**: Participate in PR reviews
- **Be Respectful**: Follow our Code of Conduct

## 📚 Resources

- [React Documentation](https://react.dev/)
- [TypeScript Handbook](https://www.typescriptlang.org/docs/)
- [Tailwind CSS](https://tailwindcss.com/docs)
- [Vite Guide](https://vitejs.dev/guide/)

Thank you for contributing to Entra ID Log Analyzer! 🙏
