import * as vscode from 'vscode';
import { analyzeCode, IssueSeverity } from './analyzer';
import { updateDiagnostics } from './diagnostics';
import {
    SecurityCodeActionProvider,
    applySecurityFix,
    applyFixAtPosition,
    applyAllFixes
} from './codeActions';

// Severity colour palette (ruler only — underlines come from diagnostics)
const SEV_COLOR: Record<IssueSeverity, string> = {
    critical: '#ff4d4d',
    warning:  '#ffaa00',
    info:     '#4da6ff'
};

// Severity ordering (higher = worse)
const SEV_ORDER: Record<IssueSeverity, number> = { critical: 3, warning: 2, info: 1 };

function makeDecorationType(sev: IssueSeverity): vscode.TextEditorDecorationType {
    return vscode.window.createTextEditorDecorationType({
        overviewRulerColor: SEV_COLOR[sev],
        overviewRulerLane: vscode.OverviewRulerLane.Right
    });
}

export function activate(context: vscode.ExtensionContext) {
    console.log('🛡️ SecureStack Copilot is now active.');

    // ── Diagnostics collection ───────────────────────────────────────────────
    const diagnosticCollection = vscode.languages.createDiagnosticCollection('aiSecurityCopilot');
    context.subscriptions.push(diagnosticCollection);

    // ── Severity-coloured inline decorations ─────────────────────────────────
    const decorationTypes: Record<IssueSeverity, vscode.TextEditorDecorationType> = {
        critical: makeDecorationType('critical'),
        warning:  makeDecorationType('warning'),
        info:     makeDecorationType('info')
    };
    for (const dt of Object.values(decorationTypes)) {
        context.subscriptions.push(dt);
    }

    // ── Quick Fix code action provider ───────────────────────────────────────
    context.subscriptions.push(
        vscode.languages.registerCodeActionsProvider(
            { scheme: 'file' },
            new SecurityCodeActionProvider(),
            { providedCodeActionKinds: SecurityCodeActionProvider.providedCodeActionKinds }
        )
    );

    // ── Command: fix single issue (from Quick Fix lightbulb) ─────────────────
    context.subscriptions.push(
        vscode.commands.registerCommand(
            'aiSecurityCopilot.fixIssue',
            async (document: vscode.TextDocument, diagnostic: vscode.Diagnostic) => {
                await applySecurityFix(document, diagnostic);
            }
        )
    );

    // ── Command: fix at position (invoked from hover markdown command URI) ────
    context.subscriptions.push(
        vscode.commands.registerCommand(
            'aiSecurityCopilot.fixAtPosition',
            async (uriString: string, lineNum: number) => {
                await applyFixAtPosition(uriString, lineNum, diagnosticCollection);
            }
        )
    );

    // ── Command: fix all issues in the active file ───────────────────────────
    context.subscriptions.push(
        vscode.commands.registerCommand(
            'aiSecurityCopilot.fixAllInFile',
            async () => {
                const editor = vscode.window.activeTextEditor;
                if (!editor) {
                    vscode.window.showWarningMessage('SecureStack: No active editor.');
                    return;
                }
                await applyAllFixes(editor.document, diagnosticCollection);
            }
        )
    );

    // ── Analyse document and apply decorations ───────────────────────────────
    const analyzeDocument = (document: vscode.TextDocument) => {
        if (document.uri.scheme !== 'file') { return; }
        if (document.fileName.endsWith('.env')) { return; }

        const issues = analyzeCode(document.getText());
        updateDiagnostics(document, diagnosticCollection, issues);

        const editors = vscode.window.visibleTextEditors.filter(
            e => e.document.uri.toString() === document.uri.toString()
        );

        // One decoration per line — pick worst severity for that line
        const lineSeverity = new Map<number, IssueSeverity>();
        for (const issue of issues) {
            if (issue.line < 0 || issue.line >= document.lineCount) { continue; }
            const existing = lineSeverity.get(issue.line);
            if (!existing || SEV_ORDER[issue.severity] > SEV_ORDER[existing]) {
                lineSeverity.set(issue.line, issue.severity);
            }
        }

        const buckets: Record<IssueSeverity, vscode.DecorationOptions[]> = {
            critical: [], warning: [], info: []
        };
        for (const [lineNum, sev] of lineSeverity) {
            const lineLength = document.lineAt(lineNum).text.length;
            buckets[sev].push({
                range: new vscode.Range(lineNum, lineLength, lineNum, lineLength)
            });
        }

        for (const editor of editors) {
            for (const sev of Object.keys(buckets) as IssueSeverity[]) {
                editor.setDecorations(decorationTypes[sev], buckets[sev]);
            }
        }
    };

    // Run on startup for the active document
    if (vscode.window.activeTextEditor) {
        analyzeDocument(vscode.window.activeTextEditor.document);
    }

    context.subscriptions.push(
        vscode.workspace.onDidOpenTextDocument(doc => analyzeDocument(doc))
    );
    context.subscriptions.push(
        vscode.window.onDidChangeActiveTextEditor(e => { if (e) { analyzeDocument(e.document); } })
    );
    context.subscriptions.push(
        vscode.workspace.onDidSaveTextDocument(doc => analyzeDocument(doc))
    );
    context.subscriptions.push(
        vscode.workspace.onDidCloseTextDocument(doc => diagnosticCollection.delete(doc.uri))
    );
}

export function deactivate() {
    console.log('🛡️ SecureStack Copilot deactivated.');
}
