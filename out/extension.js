"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.activate = activate;
exports.deactivate = deactivate;
const vscode = require("vscode");
const analyzer_1 = require("./analyzer");
const diagnostics_1 = require("./diagnostics");
const codeActions_1 = require("./codeActions");
// Severity colour palette (ruler only — underlines come from diagnostics)
const SEV_COLOR = {
    critical: '#ff4d4d',
    warning: '#ffaa00',
    info: '#4da6ff'
};
// Severity ordering (higher = worse)
const SEV_ORDER = { critical: 3, warning: 2, info: 1 };
function makeDecorationType(sev) {
    return vscode.window.createTextEditorDecorationType({
        overviewRulerColor: SEV_COLOR[sev],
        overviewRulerLane: vscode.OverviewRulerLane.Right
    });
}
function activate(context) {
    console.log('🛡️ SecureStack Copilot is now active.');
    // ── Diagnostics collection ───────────────────────────────────────────────
    const diagnosticCollection = vscode.languages.createDiagnosticCollection('aiSecurityCopilot');
    context.subscriptions.push(diagnosticCollection);
    // ── Severity-coloured inline decorations ─────────────────────────────────
    const decorationTypes = {
        critical: makeDecorationType('critical'),
        warning: makeDecorationType('warning'),
        info: makeDecorationType('info')
    };
    for (const dt of Object.values(decorationTypes)) {
        context.subscriptions.push(dt);
    }
    // ── Quick Fix code action provider ───────────────────────────────────────
    context.subscriptions.push(vscode.languages.registerCodeActionsProvider({ scheme: 'file' }, new codeActions_1.SecurityCodeActionProvider(), { providedCodeActionKinds: codeActions_1.SecurityCodeActionProvider.providedCodeActionKinds }));
    // ── Command: fix single issue (from Quick Fix lightbulb) ─────────────────
    context.subscriptions.push(vscode.commands.registerCommand('aiSecurityCopilot.fixIssue', async (document, diagnostic) => {
        await (0, codeActions_1.applySecurityFix)(document, diagnostic);
    }));
    // ── Command: fix at position (invoked from hover markdown command URI) ────
    context.subscriptions.push(vscode.commands.registerCommand('aiSecurityCopilot.fixAtPosition', async (uriString, lineNum) => {
        await (0, codeActions_1.applyFixAtPosition)(uriString, lineNum, diagnosticCollection);
    }));
    // ── Command: fix all issues in the active file ───────────────────────────
    context.subscriptions.push(vscode.commands.registerCommand('aiSecurityCopilot.fixAllInFile', async () => {
        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            vscode.window.showWarningMessage('SecureStack: No active editor.');
            return;
        }
        await (0, codeActions_1.applyAllFixes)(editor.document, diagnosticCollection);
    }));
    // ── Analyse document and apply decorations ───────────────────────────────
    const analyzeDocument = (document) => {
        if (document.uri.scheme !== 'file') {
            return;
        }
        if (document.fileName.endsWith('.env')) {
            return;
        }
        const issues = (0, analyzer_1.analyzeCode)(document.getText());
        (0, diagnostics_1.updateDiagnostics)(document, diagnosticCollection, issues);
        const editors = vscode.window.visibleTextEditors.filter(e => e.document.uri.toString() === document.uri.toString());
        // One decoration per line — pick worst severity for that line
        const lineSeverity = new Map();
        for (const issue of issues) {
            if (issue.line < 0 || issue.line >= document.lineCount) {
                continue;
            }
            const existing = lineSeverity.get(issue.line);
            if (!existing || SEV_ORDER[issue.severity] > SEV_ORDER[existing]) {
                lineSeverity.set(issue.line, issue.severity);
            }
        }
        const buckets = {
            critical: [], warning: [], info: []
        };
        for (const [lineNum, sev] of lineSeverity) {
            const lineLength = document.lineAt(lineNum).text.length;
            buckets[sev].push({
                range: new vscode.Range(lineNum, lineLength, lineNum, lineLength)
            });
        }
        for (const editor of editors) {
            for (const sev of Object.keys(buckets)) {
                editor.setDecorations(decorationTypes[sev], buckets[sev]);
            }
        }
    };
    // Run on startup for the active document
    if (vscode.window.activeTextEditor) {
        analyzeDocument(vscode.window.activeTextEditor.document);
    }
    context.subscriptions.push(vscode.workspace.onDidOpenTextDocument(doc => analyzeDocument(doc)));
    context.subscriptions.push(vscode.window.onDidChangeActiveTextEditor(e => { if (e) {
        analyzeDocument(e.document);
    } }));
    context.subscriptions.push(vscode.workspace.onDidSaveTextDocument(doc => analyzeDocument(doc)));
    context.subscriptions.push(vscode.workspace.onDidCloseTextDocument(doc => diagnosticCollection.delete(doc.uri)));
}
function deactivate() {
    console.log('🛡️ SecureStack Copilot deactivated.');
}
//# sourceMappingURL=extension.js.map