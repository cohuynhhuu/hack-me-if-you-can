# Project Coding Standards

> **⚠️ IMPORTANT**: All code in this project MUST follow the guidelines in [.github/copilot-instructions.md](.github/copilot-instructions.md)

## Quick Reference

### Security (NON-NEGOTIABLE)

- ✅ **ALWAYS** validate input server-side with DataAnnotations
- ✅ **ALWAYS** hash passwords using `IPasswordHasher<T>`
- ✅ **NEVER** store passwords in plain text
- ✅ **NEVER** log sensitive data (passwords, tokens, PII)
- ✅ **NEVER** concatenate SQL strings - use EF Core or parameterized queries

### C# Standards

- Use **PascalCase** for public members
- Use **camelCase** with `_` prefix for private fields
- Use **async/await** for I/O operations (no `.Result` or `.Wait()`)
- Use **dependency injection** for all services
- Enable **nullable reference types** (`#nullable enable`)

### ASP.NET Core

- Controllers should be thin - business logic in services
- Use `[ApiController]` attribute for automatic validation
- Return proper HTTP status codes (200, 201, 400, 401, 404, 500)
- Log errors with `ILogger<T>`
- Use structured logging

### Entity Framework Core

- Use `AsNoTracking()` for read-only queries
- Use `Include()` to avoid N+1 queries
- Select only needed columns with `.Select()`
- Use migrations for schema changes

### Error Handling

- Catch specific exceptions first
- Log errors before returning responses
- Return generic error messages to clients
- Never expose stack traces or internal details

---

## Enforcement

**All pull requests will be reviewed against these standards.**

For complete guidelines, see: [.github/copilot-instructions.md](.github/copilot-instructions.md)
