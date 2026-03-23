"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.updateDiagnostics = updateDiagnostics;
const vscode = require("vscode");
function updateDiagnostics(document, collection, issues) {
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
        // Map our severity → VS Code DiagnosticSeverity
        const vsSeverity = issue.severity === 'critical' ? vscode.DiagnosticSeverity.Error :
            issue.severity === 'info' ? vscode.DiagnosticSeverity.Information :
                vscode.DiagnosticSeverity.Warning;
        const diagnostic = new vscode.Diagnostic(range, issue.message, vsSeverity);
        diagnostic.source = '🛡️ AI Security Copilot';
        // Store our custom severity string in `code` so the hover provider can read it
        diagnostic.code = issue.severity;
        diagnostics.push(diagnostic);
    }
    collection.set(document.uri, diagnostics);
}
//# sourceMappingURL=diagnostics.js.map