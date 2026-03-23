import * as vscode from 'vscode';
import { Issue } from './analyzer';

export function updateDiagnostics(
    document: vscode.TextDocument,
    collection: vscode.DiagnosticCollection,
    issues: Issue[]
) {
    collection.set(document.uri, []);
    if (document.lineCount === 0) { return; }

    const diagnostics: vscode.Diagnostic[] = [];

    for (const issue of issues) {
        if (issue.line < 0 || issue.line >= document.lineCount) { continue; }

        const line = document.lineAt(issue.line);
        const range = new vscode.Range(
            issue.line,
            line.firstNonWhitespaceCharacterIndex,
            issue.line,
            line.text.length
        );

        // Map our severity → VS Code DiagnosticSeverity
        const vsSeverity =
            issue.severity === 'critical'  ? vscode.DiagnosticSeverity.Error :
            issue.severity === 'info'      ? vscode.DiagnosticSeverity.Information :
                                             vscode.DiagnosticSeverity.Warning;

        const diagnostic = new vscode.Diagnostic(range, issue.message, vsSeverity);
        diagnostic.source = '🛡️ AI Security Copilot';
        // Store our custom severity string in `code` so the hover provider can read it
        diagnostic.code = issue.severity;

        diagnostics.push(diagnostic);
    }

    collection.set(document.uri, diagnostics);
}
