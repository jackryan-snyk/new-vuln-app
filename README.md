# Vulnerable Application for Security Testing

This is a deliberately vulnerable Node.js application designed for security testing and educational purposes. It contains both SAST (Static Application Security Testing) and SCA (Software Composition Analysis) vulnerabilities.

## ⚠️ WARNING

**DO NOT USE THIS APPLICATION IN PRODUCTION OR EXPOSE IT TO THE INTERNET.** This application is intentionally insecure and should only be used in isolated environments for security testing and education.

## Vulnerabilities Included

### SAST (Static Application Security Testing) Vulnerabilities

1. **SQL Injection** - Multiple endpoints with unsanitized user input in SQL queries
2. **Cross-Site Scripting (XSS)** - Reflected and stored XSS vulnerabilities
3. **Insecure Deserialization** - Using `eval()` on user input
4. **Prototype Pollution** - Unsafe use of lodash merge
5. **Insecure JWT** - Weak secret and no expiration
6. **Server-Side Request Forgery (SSRF)** - Unvalidated URL fetching
7. **Command Injection** - Unsafe command execution
8. **Path Traversal** - Unvalidated file path access
9. **Insecure Random Number Generation** - Using Math.random() for tokens
10. **Hardcoded Credentials** - Plaintext credentials in code
11. **Missing Security Headers** - No security headers configured
12. **Insecure Cookies** - Cookies without security flags
13. **Information Disclosure** - Stack traces exposed in error responses

### SCA (Software Composition Analysis) Vulnerabilities

The application uses outdated dependencies with known vulnerabilities:

- `express@4.17.1` - Multiple security vulnerabilities
- `mysql@2.18.1` - Known vulnerabilities
- `lodash@4.17.15` - Prototype pollution vulnerabilities
- `serialize-javascript@2.1.2` - Remote Code Execution vulnerability
- `jsonwebtoken@8.5.1` - Security vulnerabilities
- `axios@0.19.2` - Known vulnerabilities

## Setup Instructions

1. Install Node.js (v12 or higher)

2. Install dependencies:
```bash
npm install
```

3. Start the server:
```bash
npm start
```

The server will run on `http://localhost:3000`

## Testing with Snyk

### SCA Scan
```bash
snyk test
```

### SAST Scan (Snyk Code)
```bash
snyk code test
```

### Full Scan
```bash
snyk test && snyk code test
```

## Vulnerable Endpoints

- `GET /users?id=<user_id>` - SQL Injection
- `GET /search?q=<search_term>` - SQL Injection
- `GET /echo?message=<message>` - Reflected XSS
- `POST /comment` - Stored XSS (body: `{ "comment": "<script>alert('XSS')</script>" }`)
- `POST /deserialize` - Insecure Deserialization (body: `{ "data": "malicious code" }`)
- `POST /merge` - Prototype Pollution (body: `{ "obj": { "__proto__": { "isAdmin": true } } }`)
- `POST /login` - Insecure JWT (body: `{ "username": "user", "password": "pass" }`)
- `GET /fetch?url=<url>` - SSRF
- `POST /ping` - Command Injection (body: `{ "host": "127.0.0.1; rm -rf /" }`)
- `GET /file?name=<filename>` - Path Traversal
- `GET /token` - Insecure Random
- `POST /admin` - Hardcoded Credentials (username: `admin`, password: `admin123`)
- `GET /profile?user=<username>` - XSS in template
- `POST /set-cookie` - Insecure Cookie

## License

ISC

