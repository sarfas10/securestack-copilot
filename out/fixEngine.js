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
        keywords: ['xss', 'innerhtml', 'textcontent', 'domPurify', 'dangerouslysetinnerhtml', 'insertadjacenthtml', 'setattribute', 'outputted to page'],
        apply: (line) => {
            if (/\.innerHTML\s*=/.test(line)) {
                return {
                    fix: line.replace(/\.innerHTML\s*=/, '.textContent ='),
                    explanation: 'Replaced .innerHTML with .textContent to prevent XSS.'
                };
            }
            if (/\.insertAdjacentHTML\s*\(/.test(line)) {
                return {
                    fix: line.replace(/\.insertAdjacentHTML\s*\(/, '.insertAdjacentHTML(/* TODO: Sanitize input */ '),
                    explanation: 'Added a warning to sanitize input before using insertAdjacentHTML to prevent XSS.'
                };
            }
            if (/\.setAttribute\s*\(\s*['"`]on\w+['"`]/.test(line)) {
                return {
                    fix: line.replace(/\.setAttribute\s*\(\s*(['"`]on\w+['"`])\s*,\s*(.+)\s*\)/, '.addEventListener($1.substring(2), () => { $2 })'),
                    explanation: 'Replaced inline event handler with addEventListener for better security.'
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
            if (/(?:echo|print|response\.write|out\.print)/i.test(line)) {
                const ind = indent(line);
                const callMatch = line.match(/(?:echo|print|response\.write|out\.print)\s*\(?\s*(.+?)\s*\)?\s*;?$/i);
                if (callMatch) {
                    const arg = callMatch[1];
                    const method = line.match(/(echo|print|response\.write|out\.print)/i)?.[0] ?? 'echo';
                    return {
                        fix: `${ind}${method}(escapeHtml(${arg})); /* TODO: ensure escapeHtml is defined */`,
                        explanation: 'Wrapped output in escapeHtml() to prevent XSS. Ensure you have a sanitization helper defined in your project.'
                    };
                }
            }
            return null;
        }
    },
    // ── 11. Sensitive Data Displayed/Logged (URLs) ───────────────────────────
    {
        keywords: ['credentials or tokens in url', 'secret or token appended', 'url query string'],
        apply: (line, lineNum) => {
            const ind = indent(line);
            const sensitiveParams = 'token|password|secret|key|apiKey|api_key|username|passwd|access_token|auth';
            // Case 1: fetch("url?token=" + apiKey)
            const fetchConcatRe = new RegExp(`(fetch|axios\\.(?:get|post|put|delete|request))\\s*\\(\\s*(['\"\`].*?)[?&](?:${sensitiveParams})=['\"\`]?\\s*\\+\\s*([a-zA-Z0-9_.]+)`, 'i');
            const fetchConcatMatch = line.match(fetchConcatRe);
            if (fetchConcatMatch) {
                const [, method, baseUrl, varName] = fetchConcatMatch;
                return {
                    fix: `${ind}${method}(${baseUrl}", { headers: { "Authorization": \`Bearer \${${varName}}\` } });`,
                    explanation: 'Moved secret from URL query parameter to Authorization header.'
                };
            }
            // Case 2: fetch(`url?token=${apiKey}`)
            const fetchTemplateRe = new RegExp(`(fetch|axios\\.(?:get|post|put|delete|request))\\s*\\(\\s*\`([^\`]+?)[?&](?:${sensitiveParams})=\\s*\\$\\{(.+?)\\}\\s*\`\\s*\\)`, 'i');
            const fetchTemplateMatch = line.match(fetchTemplateRe);
            if (fetchTemplateMatch) {
                const [, method, baseUrl, varName] = fetchTemplateMatch;
                return {
                    fix: `${ind}${method}(\`${baseUrl}\`, { headers: { "Authorization": \`Bearer \${${varName}}\` } });`,
                    explanation: 'Moved secret from URL query parameter to Authorization header.'
                };
            }
            // Case 3: Literal token fetch("url?token=sk-123")
            const fetchLiteralRe = new RegExp(`(fetch|axios\\.(?:get|post|put|delete|request))\\s*\\(\\s*(['\"\`])(.*?)[?&](?:${sensitiveParams})=([^'\\"\\s\`&]+)\\2\\s*\\)`, 'i');
            const fetchLiteralMatch = line.match(fetchLiteralRe);
            if (fetchLiteralMatch) {
                const [, method, quote, baseUrl, secretValue] = fetchLiteralMatch;
                return {
                    fix: `${ind}${method}(${quote}${baseUrl}${quote}, { headers: { "Authorization": \`Bearer \${process.env.API_TOKEN}\` } });`,
                    explanation: 'Moved literal secret from URL to .env file and passed via Authorization header.',
                    envUpdate: { key: 'API_TOKEN', value: secretValue }
                };
            }
            // Case 4: window.location.href = "url?token=" + apiKey
            const winRe = new RegExp(`(window\\.location(?:\\.href)?|document\\.location)\\s*=\\s*(['\"\`].*?)[?&](?:${sensitiveParams})=['\"\`]?\\s*\\+\\s*([a-zA-Z0-9_.]+)`, 'i');
            const winMatch = line.match(winRe);
            if (winMatch) {
                const [, winProp, baseUrl] = winMatch;
                return {
                    fix: `${ind}${winProp} = ${baseUrl}"; // SECURITY: Exposing tokens in URLs is disabled`,
                    explanation: 'Removed sensitive token from redirect URL string to prevent token leakage in Referer headers or server logs.'
                };
            }
            // Case 5: URL string assignment with inline credentials
            const urlAssignRe = new RegExp(`(['\"\`])https?://[^'\"\`]*[?&](?:${sensitiveParams})=[^'\"\`&]*`, 'i');
            if (urlAssignRe.test(line)) {
                const sensitiveParamRe = new RegExp(`([?&])(?:${sensitiveParams})=[^'\"\`&]*`, 'gi');
                let fixed = line;
                const secrets = [];
                const paramCapture = new RegExp(`[?&](${sensitiveParams})=([^'\"\`&]*)`, 'gi');
                let paramMatch;
                while ((paramMatch = paramCapture.exec(line)) !== null) {
                    const paramName = paramMatch[1].replace(/([a-z])([A-Z])/g, '$1_$2').toUpperCase();
                    if (paramMatch[2]) {
                        secrets.push({ key: paramName, value: paramMatch[2] });
                    }
                }
                fixed = fixed.replace(sensitiveParamRe, (match, prefix) => '');
                fixed = fixed.replace(/\?&/g, '?');
                fixed = fixed.replace(/&&+/g, '&');
                fixed = fixed.replace(/\?(['"`])/g, '$1');
                fixed = fixed.replace(/&(['"`])/g, '$1');
                if (fixed !== line) {
                    const envInfo = secrets.map(s => `${s.key}=${s.value}`).join(', ');
                    return {
                        fix: `${fixed}\n${ind}// SECURITY: Removed sensitive query params (${secrets.map(s => s.key).join(', ')}). Pass credentials via headers or environment variables.`,
                        explanation: `Stripped sensitive parameters from URL to prevent credential leakage. Move values to .env: ${envInfo}`,
                        envUpdate: secrets.length > 0 ? { key: secrets[0].key, value: secrets[0].value } : undefined
                    };
                }
            }
            // Fallback: strip entire sensitive query parameters from the line
            const fallbackRe = new RegExp(`[?&](?:${sensitiveParams})=[^'\\"\\s\`&]*`, 'gi');
            if (fallbackRe.test(line)) {
                const secrets = [];
                const paramCapture = new RegExp(`[?&](${sensitiveParams})=([^'\\"\\s\`&]*)`, 'gi');
                let paramMatch;
                while ((paramMatch = paramCapture.exec(line)) !== null) {
                    const paramName = paramMatch[1].replace(/([a-z])([A-Z])/g, '$1_$2').toUpperCase();
                    if (paramMatch[2]) {
                        secrets.push({ key: paramName, value: paramMatch[2] });
                    }
                }
                let fixed = line.replace(fallbackRe, '');
                fixed = fixed.replace(/\?(['"`])/g, '$1');
                fixed = fixed.replace(/&(['"`])/g, '$1');
                fixed = fixed.replace(/\?&/g, '?');
                fixed = fixed.replace(/&&+/g, '&');
                if (fixed !== line) {
                    return {
                        fix: `${fixed}\n${ind}// SECURITY: Removed sensitive query params. Pass credentials via headers or environment variables.`,
                        explanation: 'Stripped sensitive parameters from URL to prevent credential leakage in Referer headers, browser history, or server logs.',
                        envUpdate: secrets.length > 0 ? { key: secrets[0].key, value: secrets[0].value } : undefined
                    };
                }
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
            if (/\b(?:spawn|spawnSync)\s*\(/.test(line) && /shell\s*:\s*true/.test(line)) {
                const ind = indent(line);
                return {
                    fix: line.replace(/shell\s*:\s*true/, 'shell: false /* security: disabled shell to prevent injection */'),
                    explanation: 'Disabled shell:true in spawn/spawnSync to prevent command injection. Pass arguments as an array instead.'
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
                        `${ind}fs.${method}(${S}${restPart}) /* securestack-disable-line */`
                    ].join('\n'),
                    explanation: 'Added path.resolve() validation to fs method to prevent path traversal outside intended base directory.'
                };
            }
            if (/res\.(?:sendFile|download)\s*\(/.test(line)) {
                const match = line.match(/res\.(?:sendFile|download)\s*\((.+)\)/);
                if (match) {
                    const pathArg = match[1].split(',')[0].trim();
                    const ind = indent(line);
                    const B = `_base_L${lineNum}`;
                    const S = `_safe_L${lineNum}`;
                    return {
                        fix: [
                            `${ind}const ${B} = require('path').resolve(__dirname, 'public'); // set your allowed base dir`,
                            `${ind}const ${S} = require('path').resolve(${B}, ${pathArg});`,
                            `${ind}if (!${S}.startsWith(${B})) { throw new Error('Path traversal detected'); }`,
                            line.replace(pathArg, S) + ' /* securestack-disable-line */'
                        ].join('\n'),
                        explanation: 'Added path validation to res.sendFile/download to prevent path traversal.'
                    };
                }
            }
            if (/path\.join\s*\(/.test(line)) {
                return {
                    fix: [
                        `${ind}const ${B} = require('path').resolve(__dirname);`,
                        `${ind}const ${S} = ${line.trim().replace(/^const\s+[a-zA-Z0-9_]+\s*=\s*/, '')}`,
                        `${ind}if (!require('path').resolve(${B}, ${S}).startsWith(${B})) { throw new Error('Path traversal detected'); }`,
                        line.replace(/path\.join\s*\(/, `${S} /* path traversal guarded */ = path.join(`) + ' /* securestack-disable-line */'
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
                        `${line} /* securestack-disable-line */`
                    ].join('\n'),
                    explanation: 'Added hostname allowlist validation before HTTP request to prevent SSRF.'
                };
            }
            return {
                fix: [
                    `${ind}const ${P} = new URL(${line.trim().match(/['"`](.*?)['"`]/)?.[1] || 'url_variable'});`,
                    `${ind}const ${A} = ['api.example.com']; // update with your trusted hosts`,
                    `${ind}if (!${A}.includes(${P}.hostname)) { throw new Error('SSRF: host not allowed'); }`,
                    `${line} /* securestack-disable-line */`
                ].join('\n'),
                explanation: 'Implemented SSRF hostname allowlist validation.'
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
                        `${ind}${finalAction} /* securestack-disable-line */`
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
            if (!/Math\.random\s*\(\s*\)/.test(line)) {
                return null;
            }
            const ind = indent(line);
            const decl = line.match(/\b(const|let|var)\b/)?.[0] ?? 'const';
            const varMatch = line.match(/\b(?:const|let|var)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=/);
            const varName = varMatch?.[1] ?? '_rand';
            // Pattern: Math.random().toString(36)  → hex token via randomBytes
            if (/Math\.random\s*\(\s*\)\s*\.toString\s*\(\s*36\s*\)/.test(line)) {
                return {
                    fix: `${ind}${decl} ${varName} = require("crypto").randomBytes(16).toString("hex");`,
                    explanation: 'Replaced Math.random().toString(36) with crypto.randomBytes(16).toString("hex") for a cryptographically secure random token.'
                };
            }
            // Pattern: Math.floor(Math.random() * N)  → crypto.randomInt(0, N)
            const floorMatch = line.match(/Math\.floor\s*\(\s*Math\.random\s*\(\s*\)\s*\*\s*(\d+)\s*\)/);
            if (floorMatch) {
                const upperBound = floorMatch[1];
                return {
                    fix: `${ind}${decl} ${varName} = require("crypto").randomInt(0, ${upperBound});`,
                    explanation: `Replaced Math.floor(Math.random() * ${upperBound}) with crypto.randomInt(0, ${upperBound}) for a cryptographically secure integer.`
                };
            }
            // Pattern: Math.random().toString(16) or generic Math.random() hex usage
            if (/Math\.random\s*\(\s*\)\s*\.toString\s*\(\s*16\s*\)/.test(line)) {
                return {
                    fix: `${ind}${decl} ${varName} = require("crypto").randomBytes(16).toString("hex");`,
                    explanation: 'Replaced Math.random().toString(16) with crypto.randomBytes(16).toString("hex") for a cryptographically secure random hex string.'
                };
            }
            // Fallback: generic Math.random() replacement
            return {
                fix: line.replace(/Math\.random\s*\(\s*\)/, 'require("crypto").randomBytes(4).readUInt32BE(0) / 4294967296'),
                explanation: 'Replaced Math.random() with crypto.randomBytes() for cryptographically secure randomness. (4294967296 = 2^32)'
            };
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
    },
    // ── 18. Insecure Cookies ────────────────────────────────────────────────
    {
        keywords: ['insecure cookie', 'missing httponly', 'secure flag'],
        apply: (line) => {
            const ind = indent(line);
            if (/res\.cookie\s*\(/.test(line)) {
                let fixed = line;
                if (!/httpOnly\s*:\s*true/.test(line)) {
                    fixed = fixed.replace(/res\.cookie\s*\(([^,]+),\s*([^,]+),\s*\{/, 'res.cookie($1, $2, { httpOnly: true, ');
                    if (fixed === line) { // missing options object entirely
                        fixed = fixed.replace(/res\.cookie\s*\(([^,]+),\s*([^)]+)\)/, 'res.cookie($1, $2, { httpOnly: true, secure: true, sameSite: "strict" })');
                    }
                }
                if (!/secure\s*:\s*true/.test(fixed) && fixed.includes('{')) {
                    fixed = fixed.replace('{', '{ secure: true, ');
                }
                if (fixed !== line) {
                    return {
                        fix: fixed,
                        explanation: 'Added httpOnly and secure flags to cookie to prevent XSS theft and ensure encrypted transmission.'
                    };
                }
            }
            return null;
        }
    },
    // ── 19. NoSQL Injection ──────────────────────────────────────────────────
    {
        keywords: ['nosql injection', 'mongodb query', 'request object passed directly'],
        apply: (line) => {
            const ind = indent(line);
            const match = line.match(/\.(find|findOne|update|delete|count|aggregate)\s*\(\s*(req\.(body|query|params)[^)]*)\)/);
            if (match) {
                const input = match[2];
                return {
                    fix: line.replace(input, `/* sanitize NoSQL */ (typeof ${input} === 'string' ? { _id: ${input} } : ${input})`),
                    explanation: 'Neutralized potential NoSQL injection by ensuring request input is handled safely.'
                };
            }
            return null;
        }
    },
    // ── 20. Authentication Bypass ────────────────────────────────────────────
    {
        keywords: ['authentication bypass', 'identity spoofing', 'untrusted headers', 'hardcoded admin roles'],
        apply: (line) => {
            const ind = indent(line);
            if (/(?:setLoginName|setAccessLevel|setAttribute|setUser|setRole)\s*\(\s*['"`](?:admin|root|superuser)['"`]\s*\)/i.test(line)) {
                const method = line.match(/(setLoginName|setAccessLevel|setAttribute|setUser|setRole)/i)?.[0] ?? 'setRole';
                return {
                    fix: `${ind}if (req.session && req.session.isAdmin) {\n${ind}    ${method}('admin');\n${ind}} else {\n${ind}    throw new Error('Unauthorized role assignment attempt');\n${ind}}`,
                    explanation: 'Replaced hardcoded privileged role assignment with a session-based check. Ensure req.session.isAdmin is verified server-side.'
                };
            }
            if (/(?:getHeader|req\.headers\[['"`]|req\.header\()\s*['"`]X-.*?(?:Key|NoAuto|Role|User|Token|Secret|Admin)['"`]/i.test(line)) {
                return {
                    fix: `${ind}const userContext = await authProvider.verify(req.headers); // Use a trusted auth provider\n${ind}if (!userContext || !userContext.isValid) { throw new Error('Invalid authentication context'); }`,
                    explanation: 'Replaced direct header access with a call to an authentication provider to prevent identity spoofing via untrusted headers.'
                };
            }
            return null;
        }
    },
    // ── 21. XXE (XML External Entity) ────────────────────────────────────────
    {
        keywords: ['xxe', 'insecure xml parser', 'external entity'],
        apply: (line) => {
            if (/noent\s*:\s*true/i.test(line)) {
                return {
                    fix: line.replace(/noent\s*:\s*true/i, 'noent: false /* security: disabled external entities */'),
                    explanation: 'Disabled external entity resolution (noent: false) to prevent XXE attacks.'
                };
            }
            if (/XmlReader\.Create|XmlDocument\.Load/i.test(line)) {
                const ind = indent(line);
                return {
                    fix: `${ind}XmlReaderSettings settings = new XmlReaderSettings();\n${ind}settings.DtdProcessing = DtdProcessing.Prohibit;\n${line.replace(/XmlReader\.Create\s*\(/i, 'XmlReader.Create(input, settings /* ')}`,
                    explanation: 'Enforced DtdProcessing.Prohibit on XML reader to prevent XXE.'
                };
            }
            return null;
        }
    },
    // ── 22. Buffer Overflow (C/C++) ──────────────────────────────────────────
    {
        keywords: ['buffer overflow', 'unsafe string function', 'strcpy', 'strcat'],
        apply: (line) => {
            const ind = indent(line);
            if (/\bstrcpy\s*\((.*?), (.*?)\)/.test(line)) {
                const match = line.match(/\bstrcpy\s*\((.*?), (.*?)\)/);
                if (match) {
                    return {
                        fix: `${ind}strncpy(${match[1]}, ${match[2]}, sizeof(${match[1]}) - 1);\n${ind}${match[1]}[sizeof(${match[1]}) - 1] = '\\0';`,
                        explanation: 'Replaced strcpy with strncpy and ensured null-termination to prevent buffer overflow.'
                    };
                }
            }
            if (/\bgets\s*\(/.test(line)) {
                return {
                    fix: line.replace(/\bgets\s*\((.*?)\)/, 'fgets($1, sizeof($1), stdin)'),
                    explanation: 'Replaced unsafe gets() with fgets().'
                };
            }
            return null;
        }
    },
    // ── 24. SSTI (Server Side Template Injection) ────────────────────────────
    {
        keywords: ['ssti', 'server-side template', 'dynamic input'],
        apply: (line) => {
            const ind = indent(line);
            if (/\b(?:render_template_string|renderString)\s*\(/.test(line)) {
                const callMatch = line.match(/\b(render_template_string|renderString)\s*\((.+)\)/);
                if (callMatch) {
                    const args = callMatch[2].split(',');
                    const templateData = args.length > 1 ? args.slice(1).join(',').trim() : '{}';
                    return {
                        fix: `${ind}render_template('template_file.html', ${templateData}); /* use static file and pass data */`,
                        explanation: 'Replaced string-based template rendering (SSTI risk) with file-based rendering and safe data passing.'
                    };
                }
            }
            return null;
        }
    },
    // ── 25. IDOR (Insecure Direct Object Reference) ──────────────────────────
    {
        keywords: ['idor', 'direct use of user-supplied id'],
        apply: (line) => {
            const ind = indent(line);
            if (/\bwhere\s+\w*id\s*=\s*/i.test(line)) {
                return {
                    fix: `${ind}// Verify ownership before query\n${ind}if (await db.checkAccess(req.user.id, resourceId)) {\n${ind}    ${line.trim()}\n${ind}}`,
                    explanation: 'Added an authorization check block to prevent Insecure Direct Object Reference (IDOR).'
                };
            }
            return null;
        }
    },
    // ── 26. LDAP / XPATH Injection ───────────────────────────────────────────
    {
        keywords: ['ldap/xpath injection', 'concatenation'],
        apply: (line) => {
            const ind = indent(line);
            if (/\b(Ldap|XPath|SelectNodes)\b/i.test(line)) {
                const varMatch = line.match(/\+\s*([a-zA-Z_$][a-zA-Z0-9_$]*)/) || line.match(/,\s*['"`].*?\$\{(.+?)\}/);
                const userVar = varMatch?.[1] ?? 'userInput';
                const fixedLine = line.replace(new RegExp(`\\b${userVar}\\b`, 'g'), 'sanitizedInput');
                return {
                    fix: `${ind}const sanitizedInput = sanitizeInquiry(${userVar}); // TODO: implement sanitizeInquiry\n${fixedLine}`,
                    explanation: 'Added input sanitization for LDAP/XPATH queries to prevent injection attacks.'
                };
            }
            return null;
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