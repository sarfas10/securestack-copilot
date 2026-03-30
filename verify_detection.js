"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const analyzer_1 = require("./src/analyzer");
const fs = require("fs");
const path = require("path");
const testFiles = [
    'VulFiles/Buffer Overflow/strcpy.c',
    'VulFiles/XXE/xxe.js',
    'VulFiles/IDOR/example1.php',
    'VulFiles/Server Side Template Injection/Twig.php'
];
async function runTest() {
    for (const relativePath of testFiles) {
        const fullPath = path.resolve(process.cwd(), relativePath);
        if (!fs.existsSync(fullPath)) {
            console.log(`File not found: ${relativePath}`);
            continue;
        }
        const content = fs.readFileSync(fullPath, 'utf-8');
        console.log(`--- Analyzing ${relativePath} ---`);
        const results = (0, analyzer_1.analyzeCode)(content);
        results.forEach(res => {
            console.log(`[Line ${res.line}] ${res.message} (Severity: ${res.severity})`);
        });
        console.log('\n');
    }
}
runTest();
//# sourceMappingURL=verify_detection.js.map