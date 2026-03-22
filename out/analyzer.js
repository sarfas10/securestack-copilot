"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.analyzeCode = analyzeCode;
// Deduplication helper
function push(issues, line, message) {
    if (!issues.some(i => i.line === line && i.message === message)) {
        issues.push({ line, message, severity: "warning" });
    }
}
function analyzeCode(code) {
    const issues = [];
    if (!code || code.trim().length === 0) {
        return issues;
    }
    const lines = code.split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        // ── 1. SQL INJECTION ──────────────────────────────────────────────────
        // String concatenation or template literal inside a SELECT/INSERT/UPDATE/DELETE statement
        if (/\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION)\b.*?(\+\s*\w|\$\{)/i.test(line)) {
            push(issues, i, "SQL Injection: User input concatenated into SQL query. Use parameterized queries.");
        }
        // ── 2. XSS ────────────────────────────────────────────────────────────
        // innerHTML assigned to a non-literal value
        if (/\.innerHTML\s*=/.test(line) && !/\.innerHTML\s*=\s*['"`][^'"`]*['"`]\s*;/.test(line)) {
            push(issues, i, "XSS: Dynamic value assigned to innerHTML. Use textContent or sanitize with DOMPurify.");
        }
        // dangerouslySetInnerHTML (React)
        if (/dangerouslySetInnerHTML/.test(line)) {
            push(issues, i, "XSS: dangerouslySetInnerHTML detected. Ensure value is sanitized.");
        }
        // document.write with dynamic content
        if (/document\.write\s*\(/.test(line) && !/document\.write\s*\(\s*['"`][^'"`]*['"`]\s*\)/.test(line)) {
            push(issues, i, "XSS: document.write with dynamic content can enable script injection.");
        }
        // ── 3. HARDCODED SECRETS ──────────────────────────────────────────────
        // Common secret variable names assigned to string literals
        if (/\b(?:apiKey|api_key|accessKeyId|token|secret(?:Key)?|password|passwd|dbPassword|awsAccessKey\w*)\s*[=:]\s*['"`][^'"`]{4,}['"`]/i.test(line)) {
            push(issues, i, "Sensitive Data Exposure: Hardcoded secret detected. Use environment variables instead.");
        }
        // High-entropy / format-specific tokens (AWS keys, JWTs, etc.)
        if (/['"`](AKIA[0-9A-Z]{16}|ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})['"`]/.test(line)) {
            push(issues, i, "Sensitive Data Exposure: API key or JWT token hardcoded. Move to environment variables.");
        }
        // ── 4. EVAL / CODE INJECTION ──────────────────────────────────────────
        // Direct eval() call with a variable or expression (not a plain literal)
        if (/\beval\s*\(/.test(line) && !/eval\s*\(\s*['"`][^'"`]*['"`]\s*\)/.test(line)) {
            push(issues, i, "Code Injection: eval() with dynamic input is a critical code injection risk. Avoid eval().");
        }
        // eval literal is also risky
        if (/\beval\s*\(\s*['"`]/.test(line)) {
            push(issues, i, "Code Injection: eval() usage detected. Even literal eval can be exploited. Remove eval().");
        }
        // setTimeout/setInterval with a string argument
        if (/\b(?:setTimeout|setInterval)\s*\(\s*['"`]/.test(line)) {
            push(issues, i, "Code Injection: setTimeout/setInterval with a string argument executes code like eval. Use a function reference.");
        }
        // ── 5. COMMAND INJECTION ──────────────────────────────────────────────
        // exec/execSync/spawn called with string concatenation or template literals
        if (/\b(?:exec|execSync|execFile|spawn|spawnSync|system)\s*\(/.test(line) &&
            /(\+\s*\w|\$\{|req\.|params\.|query\.|body\.)/.test(line)) {
            push(issues, i, "Command Injection: Shell command built with dynamic input. Sanitize arguments or use safer APIs.");
        }
        // exec called with any string concatenation (even local vars can be tainted)
        if (/\b(?:exec|execSync)\s*\(\s*['"`][^'"`]+['"`]\s*\+/.test(line) ||
            /\b(?:exec|execSync)\s*\(\s*`[^`]*\$\{/.test(line)) {
            push(issues, i, "Command Injection: Shell command built with concatenated or interpolated string. Use execFile() with an args array.");
        }
        // ── 6. PATH TRAVERSAL ─────────────────────────────────────────────────
        // fs read/write with concatenation or template literals
        if (/\bfs\.(readFile|readFileSync|writeFile|writeFileSync|appendFile|createReadStream)\s*\(/.test(line) &&
            /(\+\s*\w|\$\{|req\.|params\.|query\.|body\.)/.test(line)) {
            push(issues, i, "Path Traversal: File path built from dynamic input. Use path.resolve() and validate against an allowed base directory.");
        }
        // path.join with user input
        if (/path\.join\s*\(/.test(line) && /(\+\s*\w|\$\{|req\.|params\.|query\.|body\.)/.test(line)) {
            push(issues, i, "Path Traversal: path.join with user-controlled input. Validate the resolved path is within the intended directory.");
        }
        // String containing ../
        if (/['"`][^'"`]*\.\.[/\\]/.test(line)) {
            push(issues, i, "Path Traversal: Literal path traversal sequence '../' detected in string.");
        }
        // ── 7. INSECURE DESERIALIZATION ───────────────────────────────────────
        // node-serialize.unserialize with dynamic data
        if (/(?:serialize\.unserialize|unserialize)\s*\(/.test(line)) {
            push(issues, i, "Insecure Deserialization: node-serialize.unserialize can execute embedded functions (RCE). Avoid deserializing untrusted data.");
        }
        // js-yaml unsafe load
        if (/yaml\.load\s*\(/.test(line) && !/yaml\.safeLoad/.test(line)) {
            push(issues, i, "Insecure Deserialization: yaml.load() can execute arbitrary JS. Use yaml.safeLoad() or js-yaml's DEFAULT_SAFE_SCHEMA.");
        }
        // JSON.parse is generally safe but flag if the result is passed to eval or exec
        if (/JSON\.parse\s*\([^)]*\).*(?:eval|exec|unserialize)/.test(line)) {
            push(issues, i, "Insecure Deserialization: Parsed JSON immediately passed to eval/exec. This can lead to code execution.");
        }
        // ── 8. SSRF ───────────────────────────────────────────────────────────
        // fetch/axios/http.get/got called with a variable URL (not a plain string literal)
        if (/\b(?:fetch|axios\.(?:get|post|put|delete|request)|http\.get|http\.request|got|needle|superagent\.get)\s*\(/.test(line) &&
            !/\(\s*['"`]https?:\/\/[^'"`]+['"`]\s*[,)]/.test(line)) {
            push(issues, i, "SSRF: HTTP request with a potentially user-controlled URL. Validate and whitelist allowed hosts.");
        }
        // Known internal/metadata URLs hardcoded (cloud metadata endpoints)
        if (/169\.254\.169\.254|metadata\.google\.internal|169\.254\.170\.2/.test(line)) {
            push(issues, i, "SSRF: Cloud instance metadata endpoint detected. Accessing this URL from user input can expose credentials.");
        }
        // ── 9. OPEN REDIRECT ──────────────────────────────────────────────────
        // window.location / document.location assigned to a variable
        if (/(?:window\.location(?:\.href)?|document\.location)\s*=/.test(line) &&
            !/=\s*['"`]https?:\/\/[^'"`]+['"`]\s*;/.test(line)) {
            push(issues, i, "Open Redirect: window.location/document.location set to a dynamic value. Validate redirect targets against an allowlist.");
        }
        if (/window\.location\.replace\s*\(/.test(line) && /(\+\s*\w|\$\{|\bvar\b|\bconst\b|\blet\b|\w+Url|\w+URL)/.test(line)) {
            push(issues, i, "Open Redirect: window.location.replace with dynamic URL. Validate redirect targets.");
        }
        // ── 10. WEAK CRYPTOGRAPHY ─────────────────────────────────────────────
        // Weak hash algorithms: MD5, SHA1
        if (/createHash\s*\(\s*['"`](?:md5|sha1|sha-1)['"`]\s*\)/i.test(line)) {
            push(issues, i, "Weak Cryptography: MD5/SHA1 are cryptographically broken for security use. Use SHA-256 or SHA-3.");
        }
        // Broken ciphers: DES, RC4, RC2, 3DES
        if (/createCipher(?:iv)?\s*\(\s*['"`](?:des|rc4|rc2|3des|bf|blowfish)[^'"`]*['"`]/i.test(line)) {
            push(issues, i, "Weak Cryptography: Broken cipher (DES/RC4/RC2) detected. Use AES-256-GCM.");
        }
        // Math.random for security-sensitive purposes (tokens, OTPs, salts)
        if (/Math\.random\s*\(\s*\)/.test(line) &&
            /(?:token|otp|salt|key|secret|nonce|session|password|rand|id)/i.test(line)) {
            push(issues, i, "Insecure Randomness: Math.random() is not cryptographically secure. Use crypto.randomBytes() or crypto.getRandomValues().");
        }
        // ── 11. SENSITIVE DATA IN URLS ────────────────────────────────────────
        // URLs containing password/token/secret in query string
        if (/['"`]https?:\/\/[^'"`]*[?&](?:password|token|secret|apiKey|api_key|key)=/i.test(line)) {
            push(issues, i, "Sensitive Data Exposure: Credentials or tokens in URL query string. Use HTTP headers (Authorization) instead.");
        }
        // fetch/window.location with a token variable appended
        if (/(?:fetch|window\.location\.href|axios)\s*\([^)]*\+\s*(?:token|apiKey|secret|password)\b/.test(line)) {
            push(issues, i, "Sensitive Data Exposure: Secret or token appended to URL. Use Authorization headers instead of query parameters.");
        }
        // ── 12. PROTOTYPE POLLUTION ───────────────────────────────────────────
        // Object property assigned via bracket notation with __proto__ or constructor
        if (/\[['"`]__proto__['"`]\]|\.__proto__\s*\[/.test(line)) {
            push(issues, i, "Prototype Pollution: __proto__ assignment detected. This can corrupt the prototype chain for all objects.");
        }
        // Generic key-value merge loops without hasOwnProperty check (heuristic)
        if (/for\s*\(\s*(?:const|let|var)\s+\w+\s+in\s+\w+/.test(line) &&
            !/hasOwnProperty|Object\.prototype\.hasOwnProperty/.test(line)) {
            push(issues, i, "Prototype Pollution: for...in loop without hasOwnProperty check may be exploitable with __proto__ keys. Add a guard.");
        }
        // ── 13. INSECURE RANDOM FOR SECURITY TOKENS ──────────────────────────
        // Math.random used to generate tokens/session IDs (broader catch than #10)
        if (/Math\.random/.test(line) &&
            /(?:sessionToken|session_token|otp|salt|csrf|nonce|uuid|generateId|genToken)/i.test(line)) {
            push(issues, i, "Insecure Randomness: Math.random() used for security token generation. Use crypto.randomBytes().");
        }
        // ── 14. REDOS ─────────────────────────────────────────────────────────
        // Heuristic: regex with nested quantifiers like (a+)+ or ([a-z]+)*
        if (/\/.*(?:\(.*\+\).*\*|\(.*\+\).*\+|\(.*\*\).*\+|\(\[.*\]\*\)\*|\(\[.*\]\+\)\*).*\//.test(line)) {
            push(issues, i, "ReDoS: Regex with nested quantifiers detected (e.g., (a+)+). This can cause catastrophic backtracking on crafted input.");
        }
        // Explicit vulnerable patterns as string/regex literals in .test() calls
        if (/\/\^\([\w\+\[\]\\-]+\+\)\+\$\//.test(line) || /\/\(\[[\w-]+\]\+\)\*\//.test(line)) {
            push(issues, i, "ReDoS: Potentially vulnerable regex pattern detected. Audit for catastrophic backtracking.");
        }
        // ── MISC: HTTP instead of HTTPS ───────────────────────────────────────
        if (/['"`]http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)/.test(line)) {
            push(issues, i, "Sensitive Data Exposure: HTTP used instead of HTTPS for non-local URL. Prefer encrypted connections.");
        }
        // ── MISC: Broken Authentication ───────────────────────────────────────
        if (/app\.(post|get)\s*\(\s*['"`][^'"`]*login[^'"`]*['"`]/.test(line) &&
            !/rateLimit|rateLimiter|throttle/.test(line)) {
            push(issues, i, "Broken Authentication: Login route without rate limiting detected. Apply express-rate-limit.");
        }
        // ── MISC: CSRF ────────────────────────────────────────────────────────
        if (/app\.(post|put|delete|patch)\s*\(/.test(line) &&
            !/csrf|csrfToken|csurf|xsrf/i.test(line)) {
            push(issues, i, "CSRF: Mutating route without CSRF protection detected. Use csurf or equivalent.");
        }
    }
    return issues;
}
//# sourceMappingURL=analyzer.js.map