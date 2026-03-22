"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.updateDiagnostics = updateDiagnostics;
const vscode = require("vscode");
function updateDiagnostics(document, collection, issues) {
    // Clear previous diagnostics
    collection.set(document.uri, []);
    if (document.lineCount === 0) {
        return;
    }
    const diagnostics = [];
    for (const issue of issues) {
        if (issue.line < 0 || issue.line >= document.lineCount) {
            continue;
        }
        const line = document.lineAt(issue.line);
        const range = new vscode.Range(issue.line, line.firstNonWhitespaceCharacterIndex, issue.line, line.text.length);
        const diagnostic = new vscode.Diagnostic(range, issue.message, vscode.DiagnosticSeverity.Warning);
        diagnostic.source = '🛡️ AI Security Copilot';
        diagnostics.push(diagnostic);
    }
    collection.set(document.uri, diagnostics);
}
//# sourceMappingURL=diagnostics.js.map