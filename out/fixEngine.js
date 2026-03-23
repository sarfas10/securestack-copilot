"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.getInbuiltFix = getInbuiltFix;
function indent(line) {
    return line.match(/^(\s*)/)?.[1] ?? '';
}
const FIX_PATTERNS = [
    // ── 1. SQL Injection ─────────────────────────────────────────────────────
    {
        keywords: ['sql injection', 'parameterized'],
        apply: (line) => {
            if (/\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION)\b/i.test(line)) {
                const fixed = line
                    .replace(/(['"`])\s*\+\s*\w+/g, '?$1')
                    .replace(/\$\{[^}]+\}/g, '?');
                if (fixed !== line) {
                    return {
                        fix: fixed,
                        explanation: 'Replaced dynamic SQL concatenation with a parameterized placeholder (?). Bind user values via prepared statements.'
                    };
                }
            }
            return null;
        }
    },
    // ── 2. XSS ───────────────────────────────────────────────────────────────
    {
        keywords: ['xss', 'innerhtml', 'textcontent', 'domPurify', 'dangerouslysetinnerhtml'],
        apply: (line) => {
            if (/\.innerHTML\s*=/.test(line)) {
                return {
                    fix: line.replace(/\.innerHTML\s*=/, '.textContent ='),
                    explanation: 'Replaced .innerHTML with .textContent to prevent XSS.'
                };
            }
            if (/dangerouslySetInnerHTML/.test(line)) {
                return {
                    fix: line.replace(/dangerouslySetInnerHTML\s*=\s*\{\{\s*__html\s*:/, 'dangerouslySetInnerHTML={{ __html: /* TODO: DOMPurify.sanitize */ '),
                    explanation: 'Added a note to sanitize dangerouslySetInnerHTML output with DOMPurify.'
                };
            }
            if (/document\.write\s*\(/.test(line)) {
                const arg = line.match(/document\.write\s*\((.+)\)/)?.[1] ?? 'content';
                const ind = indent(line);
                return {
                    fix: `${ind}document.getElementById('output').textContent = ${arg};`,
                    explanation: 'Replaced document.write() with safe textContent assignment to prevent XSS.'
                };
            }
            return null;
        }
    },
    // ── 3. Hardcoded Secrets ─────────────────────────────────────────────────
    {
        keywords: ['hardcoded secret', 'environment variables', 'sensitive data exposure', 'jwt token hardcoded'],
        apply: (line) => {
            const match = line.match(/\b(apiKey|api_key|accessKeyId|token|secretKey?|password|passwd|dbPassword|awsAccessKey\w*)\s*[=:]\s*(['"`])([^'"`]{4,})\2/i);
            if (match) {
                const varName = match[1];
                const secretValue = match[3];
                const envKey = varName.replace(/([a-z])([A-Z])/g, '$1_$2').toUpperCase();
                const ind = indent(line);
                const decl = line.match(/\b(const|let|var)\b/)?.[0] ?? 'const';
                return {
                    fix: `${ind}${decl} ${varName} = process.env.${envKey};`,
                    explanation: `Replaced hardcoded value with process.env.${envKey}. Store credentials in .env.`,
                    envUpdate: { key: envKey, value: secretValue }
                };
            }
            const tokenMatch = line.match(/([a-zA-Z_0-9]+)\s*=\s*(['"`])(AKIA[0-9A-Z]{16}|ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\2/);
            if (tokenMatch) {
                const varName = tokenMatch[1];
                const secretValue = tokenMatch[3];
                const ind = indent(line);
                const decl = line.match(/\b(const|let|var)\b/)?.[0] ?? 'const';
                return {
                    fix: `${ind}${decl} ${varName} = process.env.SECRET_TOKEN;`,
                    explanation: `Moved hardcoded API/JWT token to environment variable.`,
                    envUpdate: { key: 'SECRET_TOKEN', value: secretValue }
                };
            }
            return null;
        }
    },
    // ── 4. Eval / Code Injection ─────────────────────────────────────────────
    {
        keywords: ["eval()", "code injection", "settimeout", "setinterval", "string argument", "literal eval"],
        apply: (line) => {
            if (/\beval\s*\(/.test(line)) {
                if (/eval\s*\(\s*(req\.|res\.|body\.|input|data|str|text|userInput|request)/i.test(line)) {
                    return {
                        fix: line.replace(/\beval\s*\(/, 'JSON.parse('),
                        explanation: 'Replaced eval() with JSON.parse() for safer deserialization.'
                    };
                }
                const fixed = line.replace(/\beval\s*\(/, '(/* eval removed — use JSON.parse or a safe alternative */ (');
                return {
                    fix: fixed.replace(/\)\s*;/, '));'),
                    explanation: 'Neutralized eval() execution.'
                };
            }
            const m = line.match(/\b(setTimeout|setInterval)\s*\(\s*(['"`])([\s\S]*?)\2\s*(?:,\s*(.+?))?\s*\)/);
            if (m) {
                const [, fn, , body, delay] = m;
                const ind = indent(line);
                const delayPart = delay ? `, ${delay.trim()}` : '';
                return {
                    fix: `${ind}${fn}(() => { ${body.trim()}; }${delayPart});`,
                    explanation: 'Replaced string argument with an arrow function to prevent implicit code injection via eval.'
                };
            }
            return null;
        }
    },
    // ── 5. Command Injection ─────────────────────────────────────────────────
    {
        keywords: ['command injection', 'shell command', 'execfile', 'spawn', 'execsync', 'safer apis'],
        apply: (line) => {
            if (/\b(exec|execSync)\s*\(/.test(line)) {
                const callMatch = line.match(/\b(exec|execSync)\s*\((.+)\)/);
                if (callMatch) {
                    const ind = indent(line);
                    const args = callMatch[2];
                    const concatMatch = args.match(/^(['"`])([^'"`]+)\1\s*\+\s*(.+)$/);
                    if (concatMatch) {
                        const cmd = concatMatch[2].trim().split(' ')[0];
                        const restCmd = concatMatch[2].trim().split(' ').slice(1).join(' ');
                        const userArg = concatMatch[3].trim();
                        const argsArray = restCmd ? `['${restCmd}', ${userArg}]` : `[${userArg}]`;
                        return {
                            fix: `${ind}execFile('${cmd}', ${argsArray}, (err, stdout) => { /* handle result */ });`,
                            explanation: 'Replaced exec() with execFile() to prevent shell injection.'
                        };
                    }
                    const templateMatch = args.match(/^`([^`$]+)\$\{(.+)\}`$/);
                    if (templateMatch) {
                        const cmd = templateMatch[1].trim().split(' ')[0];
                        const restCmd = templateMatch[1].trim().split(' ').slice(1).join(' ');
                        const userArg = templateMatch[2].trim();
                        const argsArray = restCmd ? `['${restCmd}', ${userArg}]` : `[${userArg}]`;
                        return {
                            fix: `${ind}execFile('${cmd}', ${argsArray}, (err, stdout) => { /* handle result */ });`,
                            explanation: 'Replaced exec() with execFile() to eliminate shell injection risk.'
                        };
                    }
                }
                const fixed = line.replace(/\bexecSync\b/, 'execFileSync').replace(/\bexec\b/, 'execFile');
                return {
                    fix: fixed,
                    explanation: 'Switched to execFile() which does not invoke a shell. Pass dynamic arguments as an array instead.'
                };
            }
            if (/\bspawn\s*\(/.test(line) && /"sh"|'sh'|"bash"|'bash'|"cmd"|'cmd'/.test(line)) {
                const ind = indent(line);
                return {
                    fix: `${ind}// TODO: Call the executable directly instead of passing args to a shell via spawn('sh', ...)\n${line.replace(/\bspawn\s*\(/, '/* vulnerable spawn */ spawn(')}`,
                    explanation: 'Using spawn with a shell (sh, bash, cmd) enables command injection. Call the executable directly.'
                };
            }
            return null;
        }
    },
    // ── 6. Path Traversal ────────────────────────────────────────────────────
    {
        keywords: ['path traversal', 'path.resolve', 'allowed base directory', 'path.join'],
        apply: (line, lineNum) => {
            const ind = indent(line);
            const B = `_base_L${lineNum}`;
            const S = `_safe_L${lineNum}`;
            const methodMatch = line.match(/\bfs\.(readFile|readFileSync|writeFile|writeFileSync|appendFile|createReadStream)\s*\((.+)\)/);
            if (methodMatch) {
                const method = methodMatch[1];
                const argsRaw = methodMatch[2];
                const firstArg = argsRaw.split(/,(?![^(]*\))/)[0].trim();
                const restArgs = argsRaw.split(/,(?![^(]*\))/).slice(1).join(',');
                const restPart = restArgs ? `, ${restArgs.trim()}` : '';
                return {
                    fix: [
                        `${ind}const ${B} = require('path').resolve(__dirname);`,
                        `${ind}const ${S} = require('path').resolve(${B}, ${firstArg});`,
                        `${ind}if (!${S}.startsWith(${B})) { throw new Error('Path traversal detected'); }`,
                        `${ind}fs.${method}(${S}${restPart})`
                    ].join('\n'),
                    explanation: 'Added path.resolve() validation to fs method to prevent path traversal outside intended base directory.'
                };
            }
            if (/path\.join\s*\(/.test(line)) {
                return {
                    fix: [
                        `${ind}const ${B} = require('path').resolve(__dirname);`,
                        `${ind}const ${S} = ${line.trim().replace(/^const\s+[a-zA-Z0-9_]+\s*=\s*/, '')}`,
                        `${ind}if (!require('path').resolve(${B}, ${S}).startsWith(${B})) { throw new Error('Path traversal detected'); }`,
                        line.replace(/path\.join\s*\(/, `${S} /* path traversal guarded */ = path.join(`)
                    ].join('\n'),
                    explanation: 'Added guard for path.join() to ensure the resulting path does not traverse out of the base directory.'
                };
            }
            if (/['"`][^'"`]*\.\.[/\\]/.test(line)) {
                return {
                    fix: line.replace(/(?:\.\.[\\/])+/g, ''),
                    explanation: 'Removed literal path traversal sequences (../) from string declaration.'
                };
            }
            return null;
        }
    },
    // ── 7. Insecure Deserialization ──────────────────────────────────────────
    {
        keywords: ['yaml.load', 'safeload', 'insecure deserialization', 'node-serialize', 'serialize.unserialize', 'parsed json immediately passed'],
        apply: (line) => {
            if (/yaml\.load\s*\(/.test(line) && !/yaml\.safeLoad/.test(line)) {
                return {
                    fix: line.replace(/yaml\.load\s*\(/, 'yaml.safeLoad('),
                    explanation: 'Replaced yaml.load() with yaml.safeLoad() to prevent arbitrary JS execution.'
                };
            }
            if (/(?:serialize\.unserialize|unserialize)\s*\(/.test(line)) {
                return {
                    fix: line.replace(/(?:serialize\.unserialize|unserialize)\s*\(/, 'JSON.parse(/* replace node-serialize with native JSON */ '),
                    explanation: 'Replaced dangerous node-serialize.unserialize() with JSON.parse(). Deserializing untrusted functions is an RCE risk.'
                };
            }
            if (/JSON\.parse\s*\([^)]*\).*(?:eval|exec|unserialize)/.test(line)) {
                return {
                    fix: line.replace(/eval|exec|unserialize/, '/* blocked direct execution of parsed JSON */'),
                    explanation: 'Identified JSON.parse() output passed directly to eval. Refactored to block execution.'
                };
            }
            return null;
        }
    },
    // ── 8. SSRF ─────────────────────────────────────────────────────────────
    {
        keywords: ['ssrf', 'user-controlled url', 'whitelist allowed hosts', 'cloud instance metadata endpoint'],
        apply: (line, lineNum) => {
            const ind = indent(line);
            if (/169\.254\.169\.254|metadata\.google\.internal/.test(line)) {
                return {
                    fix: `${ind}// CRITICAL: Cloud metadata SSRF risk intercepted. URL removed.\n${line.replace(/http:\/\/169\.254\.169\.254[^'"`]*|http:\/\/metadata\.google\.internal[^'"`]*/g, 'http://127.0.0.1/ssrf-blocked')}`,
                    explanation: 'Replaced cloud instance metadata IP with a loopback to prevent severe SSRF.'
                };
            }
            const A = `_allowed_L${lineNum}`;
            const P = `_parsed_L${lineNum}`;
            const fetchMatch = line.match(/\b(fetch|axios\.(?:get|post|put|delete|request)|http\.(?:get|request)|got)\s*\((.+)/);
            if (fetchMatch) {
                const urlExpr = fetchMatch[2].split(/,(?![^(]*\))/)[0].trim().replace(/[);]+$/, '');
                return {
                    fix: [
                        `${ind}const ${A} = ['api.example.com']; // update with your trusted hosts`,
                        `${ind}const ${P} = new URL(${urlExpr});`,
                        `${ind}if (!${A}.includes(${P}.hostname)) { throw new Error('SSRF: host not allowed'); }`,
                        line
                    ].join('\n'),
                    explanation: 'Added hostname allowlist validation before HTTP request to prevent SSRF.'
                };
            }
            return {
                fix: [
                    `${ind}// SSRF guard: validate the URL hostname before making this request`,
                    `${ind}// const ${P} = new URL(urlVariable);`,
                    `${ind}// const ${A} = ['api.example.com'];`,
                    `${ind}// if (!${A}.includes(${P}.hostname)) { throw new Error('SSRF: host not allowed'); }`,
                    line
                ].join('\n'),
                explanation: 'Added SSRF guard comment.'
            };
        }
    },
    // ── 9. Open Redirect ─────────────────────────────────────────────────────
    {
        keywords: ['open redirect', 'window.location', 'allowlist', 'dynamic url'],
        apply: (line, lineNum) => {
            const ind = indent(line);
            let rhsExpr = 'redirectUrl';
            let isReplace = false;
            const rhsMatch = line.match(/(?:window\.location(?:\.href)?|document\.location)\s*=\s*(.+)/);
            if (rhsMatch) {
                rhsExpr = rhsMatch[1].trim().replace(/;+\s*$/, '');
            }
            else {
                const replaceMatch = line.match(/window\.location\.replace\s*\((.+)\)/);
                if (replaceMatch) {
                    rhsExpr = replaceMatch[1].trim().replace(/;+\s*$/, '');
                    isReplace = true;
                }
            }
            if (rhsMatch || isReplace) {
                const A = `_allowed_L${lineNum}`;
                const R = `_redir_L${lineNum}`;
                const finalAction = isReplace ? `window.location.replace(${R}.href);` : `window.location.href = ${R}.href;`;
                return {
                    fix: [
                        `${ind}const ${A} = ['example.com']; // add your trusted domains`,
                        `${ind}const ${R} = new URL(${rhsExpr}, window.location.origin);`,
                        `${ind}if (!${A}.includes(${R}.hostname)) { throw new Error('Redirect not allowed'); }`,
                        `${ind}${finalAction}`
                    ].join('\n'),
                    explanation: 'Added domain allowlist validation before redirect to prevent Open Redirect.'
                };
            }
            return null;
        }
    },
    // ── 10. Weak / Broken Cryptography ───────────────────────────────────────
    {
        keywords: ['md5', 'sha1', 'weak cryptography', 'sha-256', 'broken cipher'],
        apply: (line) => {
            if (/createHash\s*\(\s*['"`](?:md5|sha1|sha-1)['"`]\s*\)/i.test(line)) {
                return {
                    fix: line.replace(/createHash\s*\(\s*['"`](?:md5|sha1|sha-1)['"`]\s*\)/i, "createHash('sha256')"),
                    explanation: 'Replaced weak MD5/SHA1 hash with SHA-256.'
                };
            }
            if (/createCipher(?:iv)?\s*\(\s*['"`](?:des|rc4|rc2|3des|bf|blowfish)[^'"`]*['"`]/i.test(line)) {
                return {
                    fix: line.replace(/createCipher(iv)?\s*\(\s*['"`][^'"`]+['"`]/i, "createCipher$1('aes-256-gcm'"),
                    explanation: 'Replaced broken cipher algorithm with strong aes-256-gcm.'
                };
            }
            return null;
        }
    },
    // ── 11. Sensitive Data Displayed/Logged (URLs) ───────────────────────────
    {
        keywords: ['credentials or tokens in url', 'secret or token appended'],
        apply: (line) => {
            if (/token=|password=|secret=|key=|apiKey=/i.test(line)) {
                const ind = indent(line);
                return {
                    fix: `${ind}// SECURITY: Do not append secret tokens/credentials in the URL query string.\n${ind}// Pass them via HTTP Headers (e.g. Authorization: Bearer <token>) instead.\n${line.replace(/([?&])(?:token|password|secret|key|apiKey)=[^'"\s`&]*/gi, '$1REDACTED_SECRET=***')}`,
                    explanation: 'Removed secret from URL string. Move credentials to HTTP headers.'
                };
            }
            return {
                fix: `${indent(line)}// SECURITY: Use Authorization headers instead of URL query parameters for secrets.\n${line}`,
                explanation: 'Replaced insecure URL token construction. Use headers.'
            };
        }
    },
    // ── 12. Prototype Pollution ──────────────────────────────────────────────
    {
        keywords: ['prototype pollution', '__proto__', 'hasownproperty'],
        apply: (line) => {
            if (/\['__proto__'\]|\.__proto__\s*\[/.test(line)) {
                const ind = indent(line);
                return {
                    fix: [
                        `${ind}const safeMap = Object.create(null); // null-prototype map avoids pollution`,
                        line.replace(/\['__proto__'\]|\.__proto__/g, '/* __proto__ removed */')
                    ].join('\n'),
                    explanation: 'Replaced __proto__ assignment with an Object.create(null) safe map.'
                };
            }
            const forInMatch = line.match(/for\s*\(\s*(const|let|var)\s+(\w+)\s+in\s+(\w+)/);
            if (forInMatch) {
                const [, decl, key, obj] = forInMatch;
                const ind = indent(line);
                return {
                    fix: `${ind}for (${decl} ${key} in ${obj}) {\n${ind}  if (!Object.prototype.hasOwnProperty.call(${obj}, ${key})) { continue; }`,
                    explanation: 'Added hasOwnProperty guard to for...in loop to prevent prototype pollution exploits.'
                };
            }
            return null;
        }
    },
    // ── 13. Insecure Randomness ──────────────────────────────────────────────
    {
        keywords: ['math.random', 'insecure randomness', 'crypto.randombytes'],
        apply: (line) => {
            if (/Math\.random\s*\(\s*\)/.test(line)) {
                return {
                    fix: line.replace(/Math\.random\s*\(\s*\)/, 'require("crypto").randomInt(0, 1_000_000) / 1_000_000'),
                    explanation: 'Replaced Math.random() with cryptographically secure crypto.randomInt().'
                };
            }
            return null;
        }
    },
    // ── 14. ReDoS (Regex Denial of Service) ──────────────────────────────────
    {
        keywords: ['redos', 'catastrophic backtracking', 'nested quantifiers', 'potentially vulnerable regex pattern'],
        apply: (line) => {
            // Strips the outer quantifier of nested identicals: (a+)+ -> (a+) and ([A-Z]+)* -> ([A-Z]+)
            const fixed = line.replace(/(\([^)]+[\+\*]\))[\+\*]/g, '$1');
            if (fixed !== line) {
                return {
                    fix: fixed,
                    explanation: 'Removed outer nested quantifier from regex to prevent ReDoS (Regex Denial of Service) catastrophic backtracking.'
                };
            }
            return null;
        }
    },
    // ── 15. HTTP rather than HTTPS ───────────────────────────────────────────
    {
        keywords: ['http used instead of https', 'encrypted connections'],
        apply: (line) => {
            if (/['"`]http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)/.test(line)) {
                return {
                    fix: line.replace(/(['"`])http:\/\//g, '$1https://'),
                    explanation: 'Enforced HTTPS for encrypted connections.'
                };
            }
            return null;
        }
    },
    // ── 16. CSRF ─────────────────────────────────────────────────────────────
    {
        keywords: ['csrf', 'csurf', 'mutating route'],
        apply: (line) => {
            const ind = indent(line);
            const routeMatch = line.match(/app\.(post|put|delete|patch)\s*\(\s*(['"`][^'"`]+['"`])\s*,\s*(.+)\)/);
            if (routeMatch) {
                const [, method, path, handler] = routeMatch;
                return {
                    fix: `${ind}app.${method}(${path}, require('csurf')({ cookie: true }), ${handler})`,
                    explanation: "Added inline csurf CSRF protection middleware."
                };
            }
            return {
                fix: `${ind}// Apply CSRF protection: app.use(require('csurf')({ cookie: true }))\n${line}`,
                explanation: "Add csurf CSRF middleware before this route."
            };
        }
    },
    // ── 17. Rate limiting ────────────────────────────────────────────────────
    {
        keywords: ['broken authentication', 'rate limit', 'login route'],
        apply: (line) => {
            const ind = indent(line);
            const routeMatch = line.match(/app\.(post|get)\s*\(\s*(['"`][^'"`]+['"`])\s*,\s*(.+)\)/);
            if (routeMatch) {
                const [, method, path, handler] = routeMatch;
                return {
                    fix: `${ind}app.${method}(${path}, require('express-rate-limit')({ windowMs: 15*60*1000, max: 10, message: 'Too many attempts' }), ${handler})`,
                    explanation: 'Added inline express-rate-limit middleware.'
                };
            }
            return {
                fix: `${ind}// Apply rate limiting: app.use(require('express-rate-limit')({ windowMs: 15*60*1000, max: 10 }))\n${line}`,
                explanation: 'Add express-rate-limit middleware to prevent brute-force attacks on this route.'
            };
        }
    }
];
function getInbuiltFix(lineText, issueMessage, lineNum = 0) {
    const msgLower = issueMessage.toLowerCase();
    for (const pattern of FIX_PATTERNS) {
        if (pattern.keywords.some(k => msgLower.includes(k.toLowerCase()))) {
            const result = pattern.apply(lineText, lineNum);
            if (result) {
                return result;
            }
        }
    }
    return null;
}
//# sourceMappingURL=fixEngine.js.map