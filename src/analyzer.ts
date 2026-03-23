export type IssueSeverity = 'critical' | 'warning' | 'info';

export interface Issue {
    line: number;
    message: string;
    severity: IssueSeverity;
}

// Deduplication helper
function push(issues: Issue[], line: number, message: string, severity: IssueSeverity = 'warning'): void {
    if (!issues.some(i => i.line === line && i.message === message)) {
        issues.push({ line, message, severity });
    }
}

export function analyzeCode(code: string): Issue[] {
    const issues: Issue[] = [];
    if (!code || code.trim().length === 0) { return issues; }

    const lines = code.split(/\r?\n/);

    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];

        // ── ALLOW EXPLICIT IGNORING ───────────────────────────────────────────
        if (line.includes('securestack-disable-line')) {
            continue;
        }

        // ── 1. SQL INJECTION ──────────────────────────────────────────────────
        if (/\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION)\b.*?(\+\s*\w|\$\{)/i.test(line)) {
            push(issues, i, "SQL Injection: User input concatenated into SQL query. Use parameterized queries.", 'critical');
        }

        // ── 2. XSS ────────────────────────────────────────────────────────────
        if (/\.innerHTML\s*=/.test(line) && !/\.innerHTML\s*=\s*['"` ][^'"` ]*['"` ]\s*;/.test(line)) {
            push(issues, i, "XSS: Dynamic value assigned to innerHTML. Use textContent or sanitize with DOMPurify.", 'critical');
        }
        if (/dangerouslySetInnerHTML/.test(line)) {
            push(issues, i, "XSS: dangerouslySetInnerHTML detected. Ensure value is sanitized.", 'critical');
        }
        if (/document\.write\s*\(/.test(line) && !/document\.write\s*\(\s*['"` ][^'"` ]*['"` ]\s*\)/.test(line)) {
            push(issues, i, "XSS: document.write with dynamic content can enable script injection.", 'critical');
        }

        // ── 3. HARDCODED SECRETS ──────────────────────────────────────────────
        if (/\b(?:apiKey|api_key|accessKeyId|token|secret(?:Key)?|password|passwd|dbPassword|awsAccessKey\w*)\s*[=:]\s*['"` ][^'"` ]{4,}['"` ]/i.test(line)) {
            push(issues, i, "Sensitive Data Exposure: Hardcoded secret detected. Use environment variables instead.", 'critical');
        }
        if (/['"` ](AKIA[0-9A-Z]{16}|ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})['"` ]/.test(line)) {
            push(issues, i, "Sensitive Data Exposure: API key or JWT token hardcoded. Move to environment variables.", 'critical');
        }

        // ── 4. EVAL / CODE INJECTION ──────────────────────────────────────────
        if (/\beval\s*\(/.test(line) && !/eval\s*\(\s*['"` ][^'"` ]*['"` ]\s*\)/.test(line)) {
            push(issues, i, "Code Injection: eval() with dynamic input is a critical code injection risk. Avoid eval().", 'critical');
        }
        if (/\beval\s*\(\s*['"` ]/.test(line)) {
            push(issues, i, "Code Injection: eval() usage detected. Even literal eval can be exploited. Remove eval().", 'critical');
        }
        if (/\b(?:setTimeout|setInterval)\s*\(\s*['"` ]/.test(line)) {
            push(issues, i, "Code Injection: setTimeout/setInterval with a string argument executes code like eval. Use a function reference.", 'warning');
        }

        // ── 5. COMMAND INJECTION ──────────────────────────────────────────────
        if (/\b(?:exec|execSync|system)\s*\(/.test(line) &&
            /(\+\s*\w|\$\{|req\.|params\.|query\.|body\.)/.test(line)) {
            push(issues, i, "Command Injection: Shell command built with dynamic input. Sanitize arguments or use safer APIs.", 'critical');
        }
        if (/\b(?:exec|execSync)\s*\(\s*['"` ][^'"` ]+['"` ]\s*\+/.test(line) ||
            /\b(?:exec|execSync)\s*\(\s*`[^`]*\$\{/.test(line)) {
            push(issues, i, "Command Injection: Shell command built with concatenated or interpolated string. Use execFile() with an args array.", 'critical');
        }

        // ── 6. PATH TRAVERSAL ─────────────────────────────────────────────────
        if (/\bfs\.(readFile|readFileSync|writeFile|writeFileSync|appendFile|createReadStream)\s*\(/.test(line) &&
            /(\+\s*\w|\$\{|req\.|params\.|query\.|body\.)/.test(line)) {
            push(issues, i, "Path Traversal: File path built from dynamic input. Use path.resolve() and validate against an allowed base directory.", 'critical');
        }
        if (/path\.join\s*\(/.test(line) && /(\+\s*\w|\$\{|req\.|params\.|query\.|body\.)/.test(line)) {
            push(issues, i, "Path Traversal: path.join with user-controlled input. Validate the resolved path is within the intended directory.", 'warning');
        }
        if (/['"` ][^'"` ]*\.\.[/\\]/.test(line)) {
            push(issues, i, "Path Traversal: Literal path traversal sequence '../' detected in string.", 'warning');
        }

        // ── 7. INSECURE DESERIALIZATION ───────────────────────────────────────
        if (/(?:serialize\.unserialize|unserialize)\s*\(/.test(line)) {
            push(issues, i, "Insecure Deserialization: node-serialize.unserialize can execute embedded functions (RCE). Avoid deserializing untrusted data.", 'critical');
        }
        if (/yaml\.load\s*\(/.test(line) && !/yaml\.safeLoad/.test(line)) {
            push(issues, i, "Insecure Deserialization: yaml.load() can execute arbitrary JS. Use yaml.safeLoad() or js-yaml's DEFAULT_SAFE_SCHEMA.", 'critical');
        }
        if (/JSON\.parse\s*\([^)]*\).*(?:eval|exec|unserialize)/.test(line)) {
            push(issues, i, "Insecure Deserialization: Parsed JSON immediately passed to eval/exec. This can lead to code execution.", 'critical');
        }

        // ── 8. SSRF ───────────────────────────────────────────────────────────
        if (/\b(?:fetch|axios\.(?:get|post|put|delete|request)|http\.get|http\.request|got|needle|superagent\.get)\s*\(/.test(line) &&
            !/\(\s*['"` ]https?:\/\/[^'"` ]+['"` ]\s*[,)]/.test(line)) {
            push(issues, i, "SSRF: HTTP request with a potentially user-controlled URL. Validate and whitelist allowed hosts.", 'critical');
        }
        if (/169\.254\.169\.254|metadata\.google\.internal|169\.254\.170\.2/.test(line)) {
            push(issues, i, "SSRF: Cloud instance metadata endpoint detected. Accessing this URL from user input can expose credentials.", 'critical');
        }

        // ── 9. OPEN REDIRECT ──────────────────────────────────────────────────
        if (/(?:window\.location(?:\.href)?|document\.location)\s*=/.test(line) &&
            !/=\s*['"` ]https?:\/\/[^'"` ]+['"` ]\s*;/.test(line)) {
            push(issues, i, "Open Redirect: window.location/document.location set to a dynamic value. Validate redirect targets against an allowlist.", 'warning');
        }
        if (/window\.location\.replace\s*\(/.test(line) && /(\+\s*\w|\$\{|\bvar\b|\bconst\b|\blet\b|\w+Url|\w+URL)/.test(line)) {
            push(issues, i, "Open Redirect: window.location.replace with dynamic URL. Validate redirect targets.", 'warning');
        }

        // ── 10. WEAK CRYPTOGRAPHY ─────────────────────────────────────────────
        if (/createHash\s*\(\s*['"` ](?:md5|sha1|sha-1)['"` ]\s*\)/i.test(line)) {
            push(issues, i, "Weak Cryptography: MD5/SHA1 are cryptographically broken for security use. Use SHA-256 or SHA-3.", 'warning');
        }
        if (/createCipher(?:iv)?\s*\(\s*['"` ](?:des|rc4|rc2|3des|bf|blowfish)[^'"` ]*['"` ]/i.test(line)) {
            push(issues, i, "Weak Cryptography: Broken cipher (DES/RC4/RC2) detected. Use AES-256-GCM.", 'warning');
        }
        if (/Math\.random\s*\(\s*\)/.test(line) &&
            /(?:token|otp|salt|key|secret|nonce|session|password|rand|id)/i.test(line)) {
            push(issues, i, "Insecure Randomness: Math.random() is not cryptographically secure. Use crypto.randomBytes() or crypto.getRandomValues().", 'warning');
        }

        // ── 11. SENSITIVE DATA IN URLS ────────────────────────────────────────
        if (/['"` ]https?:\/\/[^'"` ]*[?&](?:password|token|secret|apiKey|api_key|key)=/i.test(line)) {
            push(issues, i, "Sensitive Data Exposure: Credentials or tokens in URL query string. Use HTTP headers (Authorization) instead.", 'warning');
        }
        if (/(?:fetch|window\.location\.href|axios)\s*\([^)]*\+\s*(?:token|apiKey|secret|password)\b/.test(line)) {
            push(issues, i, "Sensitive Data Exposure: Secret or token appended to URL. Use Authorization headers instead of query parameters.", 'warning');
        }

        // ── 12. PROTOTYPE POLLUTION ───────────────────────────────────────────
        if (/\['__proto__'\]|\.__proto__\s*\[/.test(line)) {
            push(issues, i, "Prototype Pollution: __proto__ assignment detected. This can corrupt the prototype chain for all objects.", 'critical');
        }
        if (/for\s*\(\s*(?:const|let|var)\s+\w+\s+in\s+\w+/.test(line) &&
            !/hasOwnProperty|Object\.prototype\.hasOwnProperty/.test(line)) {
            push(issues, i, "Prototype Pollution: for...in loop without hasOwnProperty check may be exploitable with __proto__ keys. Add a guard.", 'info');
        }

        // ── 13. INSECURE RANDOM FOR SECURITY TOKENS ──────────────────────────
        if (/Math\.random/.test(line) &&
            /(?:sessionToken|session_token|otp|salt|csrf|nonce|uuid|generateId|genToken)/i.test(line)) {
            push(issues, i, "Insecure Randomness: Math.random() used for security token generation. Use crypto.randomBytes().", 'warning');
        }

        // ── 14. REDOS ─────────────────────────────────────────────────────────
        if (/\/.*(?:\(.*\+\).*\*|\(.*\+\).*\+|\(.*\*\).*\+|\(\[.*\]\*\)\*|\(\[.*\]\+\)\*).*\//.test(line)) {
            push(issues, i, "ReDoS: Regex with nested quantifiers detected (e.g., (a+)+). This can cause catastrophic backtracking on crafted input.", 'warning');
        }
        if (/\/\^\([\w\+\[\]\\-]+\+\)\+\$\//.test(line) || /\/\(\[[\w-]+\]\+\)\*\//.test(line)) {
            push(issues, i, "ReDoS: Potentially vulnerable regex pattern detected. Audit for catastrophic backtracking.", 'warning');
        }

        // ── MISC: HTTP instead of HTTPS ───────────────────────────────────────
        if (/['"` ]http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)/.test(line)) {
            push(issues, i, "Sensitive Data Exposure: HTTP used instead of HTTPS for non-local URL. Prefer encrypted connections.", 'info');
        }

        // ── MISC: Broken Authentication ───────────────────────────────────────
        if (/app\.(post|get)\s*\(\s*['"` ][^'"` ]*login[^'"` ]*['"` ]/.test(line) &&
            !/rateLimit|rateLimiter|throttle/.test(line)) {
            push(issues, i, "Broken Authentication: Login route without rate limiting detected. Apply express-rate-limit.", 'warning');
        }

        // ── MISC: CSRF ────────────────────────────────────────────────────────
        if (/app\.(post|put|delete|patch)\s*\(/.test(line) &&
            !/csrf|csrfToken|csurf|xsrf/i.test(line)) {
            push(issues, i, "CSRF: Mutating route without CSRF protection detected. Use csurf or equivalent.", 'info');
        }
    }

    return issues;
}
