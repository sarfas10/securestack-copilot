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
        if (/\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION)\b.*?(\+\s*\w|\$\{|\.\s*\$|\#\{|req\.|params\.|query\.|body\.|[a-z_][a-z0-9_]*\s*)/i.test(line)) {
            push(issues, i, "SQL Injection: User input concatenated into SQL query. Use parameterized queries.", 'critical');
        }

        // ── 2. XSS ────────────────────────────────────────────────────────────
        if (/\.innerHTML\s*=/.test(line) && !/\.innerHTML\s*=\s*['"` ][^'"` ]*['"` ]\s*;/.test(line)) {
            push(issues, i, "XSS: Dynamic value assigned to innerHTML. Use textContent or sanitize with DOMPurify.", 'critical');
        }
        if (/\.insertAdjacentHTML\s*\(/.test(line) && !/\.insertAdjacentHTML\s*\([^,]+,\s*['"` ][^'"` ]*['"` ]\s*\)/.test(line)) {
            push(issues, i, "XSS: Dynamic value passed to insertAdjacentHTML. Sanitize input before insertion.", 'critical');
        }
        if (/\.setAttribute\s*\(\s*['"` ]on\w+['"` ]/.test(line)) {
            push(issues, i, "XSS: Direct assignment of event handlers via setAttribute can enable script injection.", 'warning');
        }
        if (/dangerouslySetInnerHTML/.test(line)) {
            push(issues, i, "XSS: dangerouslySetInnerHTML detected. Ensure value is sanitized.", 'critical');
        }
        if (/document\.write\s*\(/.test(line) && !/document\.write\s*\(\s*['"` ][^'"` ]*['"` ]\s*\)/.test(line)) {
            push(issues, i, "XSS: document.write with dynamic content can enable script injection.", 'critical');
        }
        if (/(?:echo|print|response\.write|out\.print)\s*\(?.*?(\+\s*\w|\$\{|\.\s*\$|\#\{|req\.|params\.|query\.|body\.|[a-z_][a-z0-9_]*\s*)/i.test(line) && !/htmlspecialchars|strip_tags|escape/i.test(line)) {
            push(issues, i, "XSS: Dynamic value outputted to page without evident sanitization. Potential Cross-Site Scripting.", 'warning');
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
        if (/\b(?:exec|execSync|system|passthru|shell_exec|pcntl_exec)\s*\(/.test(line) &&
            /(\+\s*\w|\$\{|\.|\#\{|req\.|params\.|query\.|body\.)/.test(line)) {
            push(issues, i, "Command Injection: Shell command built with dynamic input. Sanitize arguments or use safer APIs.", 'critical');
        }
        if (/\b(?:spawn|spawnSync)\s*\(/.test(line) && /shell\s*:\s*true/.test(line)) {
            if (!/\b(?:spawn|spawnSync)\s*\(\s*['"` ][^'"` ]+['"` ]\s*,/.test(line)) {
                push(issues, i, "Command Injection: spawn/spawnSync with shell:true and dynamic input is risky. Pass arguments as an array instead.", 'critical');
            }
        }

        // ── 6. PATH TRAVERSAL ─────────────────────────────────────────────────
        if (/\b(?:fs\.(?:read|write|append)File|res\.(?:send|download)|open|File\.read|file_get_contents|fopen|include|require)\s*\(/.test(line) &&
            /(\+\s*\w|\$\{|\.\s*\$|\#\{|req\.|params\.|query\.|body\.)/.test(line)) {
            push(issues, i, "Path Traversal: File path built from dynamic input. Validate path against an allowed base directory.", 'critical');
        }
        if (/path\.join\s*\(/.test(line) && /(\+\s*\w|\$\{|\.|\#\{|req\.|params\.|query\.|body\.)/.test(line)) {
            push(issues, i, "Path Traversal: path.join with user-controlled input. Validate the resolved path.", 'warning');
        }
        if (/['"` ][^'"` ]*\.\.[/\\]/.test(line)) {
            push(issues, i, "Path Traversal: Literal path traversal sequence '../' detected in string.", 'warning');
        }

        // ── 7. INSECURE DESERIALIZATION ───────────────────────────────────────
        if (/(?:serialize\.unserialize|unserialize|pickle\.load|marshal\.load|BinaryFormatter\.Deserialize)\s*\(/.test(line)) {
            push(issues, i, "Insecure Deserialization: Unsafe deserialization detected. Avoid deserializing untrusted data.", 'critical');
        }
        if (/yaml\.(?:load|safeLoad)\s*\(/.test(line) && !/yaml\.safeLoad/.test(line)) {
            push(issues, i, "Insecure Deserialization: yaml.load() can execute arbitrary code. Use yaml.safeLoad().", 'critical');
        }

        // ── 8. SSRF ───────────────────────────────────────────────────────────
        if (/\b(?:fetch|axios\.\w+|http\.\w+|got|needle|superagent\.\w+|curl_exec|file_get_contents)\s*\(/.test(line) &&
            !/\(\s*['"` ]https?:\/\/[^'"` ]+['"` ]\s*[,)]/.test(line) &&
            /(\+\s*\w|\$\{|\.\s*\$|\#\{|req\.|params\.|query\.|body\.|[a-z_][a-z0-9_]*\s*)/.test(line)) {
            push(issues, i, "SSRF: HTTP request with potentially user-controlled URL. Validate allowed hosts.", 'critical');
        }
        if (/169\.254\.169\.254|metadata\.google\.internal|169\.254\.170\.2/.test(line)) {
            push(issues, i, "SSRF: Cloud metadata endpoint detected. Can expose credentials via SSRF.", 'critical');
        }

        // ── 9. OPEN REDIRECT ──────────────────────────────────────────────────
        if (/(?:window\.location(?:\.href)?|document\.location|header\(['"`]Location|res\.redirect)\s*(\s*=|:|\()/.test(line) &&
            !/https?:\/\/[^'"` ]+['"` ]\s*[;)]/.test(line) &&
            /(\+\s*\w|\$\{|\.|\#\{|req\.|params\.|query\.|body\.)/.test(line)) {
            push(issues, i, "Open Redirect: Redirect to dynamic value. Validate targets against an allowlist.", 'warning');
        }

        // ── 10. WEAK CRYPTOGRAPHY ─────────────────────────────────────────────
        if (/createHash\s*\(\s*['"` ](?:md5|sha1|sha-1)['"` ]\s*\)|md5\s*\(|sha1\s*\(|hash\s*\(\s*['"` ](?:md5|sha1)/i.test(line)) {
            push(issues, i, "Weak Cryptography: MD5/SHA1 are broken. Use SHA-256 or stronger.", 'warning');
        }
        if (/createCipher(?:iv)?\s*\(\s*['"` ](?:des|rc4|rc2|3des|bf|blowfish)[^'"` ]*['"` ]/i.test(line)) {
            push(issues, i, "Weak Cryptography: Broken cipher detected. Use AES-256-GCM.", 'warning');
        }
        if (/Math\.random\s*\(\s*\)/.test(line) &&
            /(?:token|otp|salt|key|secret|nonce|session|password|rand|id|uuid|gen)/i.test(line)) {
            push(issues, i, "Insecure Randomness: Math.random() is not secure for security-sensitive values. Use crypto.randomBytes().", 'warning');
        }

        // ── 11. SENSITIVE DATA IN URLS ────────────────────────────────────────
        if (/['"`]https?:\/\/[^'"`]*[?&](?:password|token|secret|apiKey|api_key|key|username|passwd|access_token|auth)=/i.test(line)) {
            push(issues, i, "Sensitive Data Exposure: Credentials or tokens in URL query string. Use HTTP headers.", 'warning');
        }

        // ── 12. PROTOTYPE POLLUTION ───────────────────────────────────────────
        if (/\['__proto__'\]|\.__proto__\s*\[/.test(line)) {
            push(issues, i, "Prototype Pollution: __proto__ assignment detected.", 'critical');
        }

        // ── 14. REDOS ─────────────────────────────────────────────────────────
        if (/\/.*(?:\(.*\+\).*\*|\(.*\+\).*\+|\(.*\*\).*\+|\(\[.*\]\*\)\*|\(\[.*\]\+\)\*).*\//.test(line)) {
            push(issues, i, "ReDoS: Regex with nested quantifiers can cause catastrophic backtracking.", 'warning');
        }

        // ── 21. XXE (XML EXTERNAL ENTITY) ─────────────────────────────────────
        if (/parseXmlString\s*\(.*noent\s*:\s*true/i.test(line) ||
            /simplexml_load_string/i.test(line) ||
            /XmlReader\.Create|XmlDocument\.Load/i.test(line) && !/DtdProcessing\.Prohibit/i.test(line)) {
            push(issues, i, "XXE: Insecure XML parser configuration. Disable external entity resolution.", 'critical');
        }

        // ── 22. BUFFER OVERFLOW (C/C++) ───────────────────────────────────────
        if (/\b(strcpy|strcat|gets|sprintf|vsprintf)\s*\(/.test(line)) {
            push(issues, i, "Buffer Overflow: Unsafe string function detected. Use bounded versions (e.g., strncpy).", 'critical');
        }

        // ── 23. INSECURE FILE UPLOAD ──────────────────────────────────────────
        if (/\bmove_uploaded_file\s*\(/.test(line) && !/in_array|preg_match|explode/i.test(line)) {
            push(issues, i, "Insecure File Upload: move_uploaded_file without file extension validation.", 'critical');
        }
        if (/multer\s*\(\s*\{.*\}\s*\)/.test(line) && !/fileFilter/i.test(line)) {
            push(issues, i, "Insecure File Upload: Multer configured without a fileFilter.", 'warning');
        }

        // ── 24. SSTI (SERVER SIDE TEMPLATE INJECTION) ─────────────────────────
        if (/\b(?:render_template_string|renderString|Template|render)\b.*?(\+\s*\w|\$\{|\.|\#\{|req\.|params\.|query\.|body\.|[a-z_][a-z0-9_]*\s*)/i.test(line)) {
            push(issues, i, "SSTI: Server-side template built from dynamic input. Use template files or sanitize input.", 'critical');
        }

        // ── 25. IDOR (INSECURE DIRECT OBJECT REFERENCE) ───────────────────────
        if (/\bwhere\s+\w*id\s*=\s*(\s*\$|\#\{|req\.|params\.|query\.|body\.)/i.test(line) && !/user_id|owner_id|account_id/i.test(line)) {
            push(issues, i, "IDOR: Direct use of user-supplied ID in query. Ensure authorization check is performed.", 'warning');
        }

        // ── 26. LDAP / XPATH INJECTION ────────────────────────────────────────
        if (/\b(Ldap|XPath|SelectNodes)\b.*?(\+\s*\w|\$\{|\.|\#\{)/i.test(line)) {
            push(issues, i, "Injection: LDAP/XPATH query built with dynamic input concatenation.", 'critical');
        }

        // ── MISC: HTTP instead of HTTPS ───────────────────────────────────────
        if (/['"` ]http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)/.test(line)) {
            push(issues, i, "Sensitive Data Exposure: HTTPS is preferred over HTTP for non-local connections.", 'info');
        }

        // ── MISC: Broken Authentication (Rate Limiting) ───────────────────────
        if (/app\.(post|get)\s*\(\s*['"` ][^'"` ]*login[^'"` ]*['"` ]/.test(line) && !/rateLimit|rateLimiter|throttle/.test(line)) {
            push(issues, i, "Broken Authentication: Login route without rate limiting. Apply protection against brute-force.", 'warning');
        }

        // ── MISC: CSRF ────────────────────────────────────────────────────────
        if (/app\.(post|put|delete|patch)\s*\(/.test(line) && !/csrf|csrfToken|csurf|xsrf/i.test(line)) {
            push(issues, i, "CSRF: Mutating route without obvious CSRF protection. Use csurf or equivalent middleware.", 'info');
        }

        // ── MISC: INSECURE COOKIES ────────────────────────────────────────────
        if (/res\.cookie\s*\(/.test(line) && (!/httpOnly\s*:\s*true/.test(line) || !/secure\s*:\s*true/.test(line))) {
            push(issues, i, "Insecure Cookie: Cookie missing httpOnly:true or secure:true flags.", 'warning');
        }

        // ── MISC: NOSQL INJECTION ─────────────────────────────────────────────
        if (/\.(find|findOne|update|delete|count)\s*\(\s*req\.(body|query|params)/.test(line)) {
            push(issues, i, "NoSQL Injection: Express request object passed directly into MongoDB query.", 'critical');
        }

        // ── 20. AUTHENTICATION BYPASS ─────────────────────────────────────────
        if (/(?:setLoginName|setAccessLevel|setAttribute|setUser|setRole)\s*\(\s*['"`](?:admin|root|superuser)['"`]\s*\)/i.test(line) ||
            /(?:getHeader|req\.headers\[['"`]|req\.header\()\s*['"`]X-.*?(?:Key|NoAuto|Role|User|Token|Secret|Admin)['"`]/i.test(line)) {
            push(issues, i, "Authentication Bypass: Potential identity spoofing via untrusted headers or hardcoded roles.", 'critical');
        }
    }

    return issues;
}
