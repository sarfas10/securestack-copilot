// 1. SQL Injection
const userId = 42;
const query1 = "SELECT * FROM users WHERE id = " + userId;
const query2 = `SELECT * FROM users WHERE id = ${userId}`;

// 2. XSS (Cross-Site Scripting)
const userInput = "<script>alert('xss')</script>";
document.body.innerHTML = userInput;
document.getElementById("app").innerHTML = "<div>" + userInput + "</div>";

// 3. Hardcoded Secrets
const apiKey = "12345-SECRET-API-KEY";
const userToken = 'eyJhbGciOiJIUzI1NiIsInR5c...';
let dbPassword = "supersecretpassword";
const secretKey = "mysecretkey";
const awsAccessKeyId = "AKIAIOSFODNN7EXAMPLE";

// 4. Insecure eval Usage
const userCode = "console.log('hello')";
eval(userCode);
const result = eval("2 + 2");
setTimeout("alert('insecure')", 1000);
document.getElementById('output').innerHTML = "<script>" + userCode + "</script>";

// 5. Command Injection
const { exec, execSync } = require("child_process");
const filename = "report.txt";
exec("cat " + filename, (err, stdout) => { });
execSync("ls -la " + filename);
const spawn = require("child_process").spawn;
spawn("sh", ["-c", "rm -rf " + filename]);

// 6. Path Traversal
const fs = require("fs");
const requestedFile = "../../etc/passwd";
fs.readFile("/var/www/" + requestedFile, "utf8", (err, data) => { });
fs.readFileSync("./uploads/" + requestedFile);
const path = require("path");
const filePath = path.join("/uploads", requestedFile);

// 7. Insecure Deserialization
const serialize = require("node-serialize");
const untrustedData = '{"rce":"_$$ND_FUNC$$_function(){require(\'child_process\').exec(\'id\')}()"}';
serialize.unserialize(untrustedData);

const yaml = require("js-yaml");
yaml.load("!!js/eval 'process.exit(1)'");

// 8. Server-Side Request Forgery (SSRF)
const http = require("http");
const targetUrl = "http://169.254.169.254/latest/meta-data/";
http.get(targetUrl, (res) => { });

const axios = require("axios");
const userSuppliedUrl = "http://internal-service/admin";
axios.get(userSuppliedUrl);

// 9. Open Redirect
const redirectUrl = "https://evil.com";
window.location.href = redirectUrl;
window.location.replace("http://" + redirectUrl);

// 10. Weak / Broken Cryptography
const crypto = require("crypto");
const md5Hash = crypto.createHash('md5').update("password").digest("hex");
const sha1Hash = crypto.createHash('sha1').update("sensitive").digest("hex");
const cipher = crypto.createCipher('des', "weakkey");
const rc4Cipher = crypto.createCipher('rc4', "weakkey");

// 11. Sensitive Data Exposed in URLs
const loginUrl = "https://example.com/login?username=admin&password=secret";
fetch("https://api.example.com/data?token=" + apiKey);

// 12. Prototype Pollution
function merge(target, source) {
  for (const key in source) {
    target[key] = source[key];
  }
}
const malicious = JSON.parse('{"__proto__":{"admin":true}}');
merge({}, malicious);

const obj = {};
obj["__proto__"]["isAdmin"] = true;

// 13. Insecure Random Number Generation
const sessionToken = Math.random().toString(36).substring(2);
const otp = Math.floor(Math.random() * 1000000);
const salt = Math.random().toString(16);

// 14. RegEx Denial of Service (ReDoS)
const userSearchInput = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaab";
const vulnerableRegex = /^(a+)+$/;
vulnerableRegex.test(userSearchInput);

const anotherRedos = /([a-zA-Z]+)+$/.test(userSearchInput);