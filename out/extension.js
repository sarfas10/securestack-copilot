"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.activate = activate;
exports.deactivate = deactivate;
const vscode = require("vscode");
const analyzer_1 = require("./analyzer");
const diagnostics_1 = require("./diagnostics");
function activate(context) {
    console.log('AI Security Copilot extension is now active.');
    const diagnosticCollection = vscode.languages.createDiagnosticCollection('aiSecurityCopilot');
    context.subscriptions.push(diagnosticCollection);
    // Create an inline decoration type for visual badges
    const securityDecorationType = vscode.window.createTextEditorDecorationType({
        after: {
            contentText: ' 🛡️',
            color: '#ffaa00',
            margin: '0 0 0 20px',
            textDecoration: 'none; font-weight: bold; font-size: 11px; background-color: rgba(255, 170, 0, 0.1); padding: 2px 6px; border-radius: 4px; border: 1px solid rgba(255, 170, 0, 0.3);'
        }
    });
    const analyzeDocument = (document) => {
        if (document.uri.scheme !== 'file') {
            return;
        }
        const code = document.getText();
        const issues = (0, analyzer_1.analyzeCode)(code);
        (0, diagnostics_1.updateDiagnostics)(document, diagnosticCollection, issues);
        // Apply visual inline decorations to all visible editors of this document
        const editors = vscode.window.visibleTextEditors.filter(editor => editor.document.uri.toString() === document.uri.toString());
        const decorations = issues.map(issue => {
            const line = document.lineAt(issue.line);
            return {
                range: new vscode.Range(issue.line, line.text.length, issue.line, line.text.length)
            };
        });
        for (const editor of editors) {
            editor.setDecorations(securityDecorationType, decorations);
        }
    };
    // Analyze currently active document on startup
    if (vscode.window.activeTextEditor) {
        analyzeDocument(vscode.window.activeTextEditor.document);
    }
    // Analyze when a file is opened
    context.subscriptions.push(vscode.workspace.onDidOpenTextDocument(document => {
        analyzeDocument(document);
    }));
    // Analyze when active editor changes
    context.subscriptions.push(vscode.window.onDidChangeActiveTextEditor(editor => {
        if (editor) {
            analyzeDocument(editor.document);
        }
    }));
    // Analyze on file save
    context.subscriptions.push(vscode.workspace.onDidSaveTextDocument(document => {
        analyzeDocument(document);
    }));
    // Clear diagnostics when file is closed
    context.subscriptions.push(vscode.workspace.onDidCloseTextDocument(document => {
        diagnosticCollection.delete(document.uri);
    }));
}
function deactivate() {
    console.log('AI Security Copilot extension deactivated.');
}
//# sourceMappingURL=extension.js.map