import * as vscode from 'vscode';
import { getInbuiltFix } from './fixEngine';

// ── Quick Fix code action provider ──────────────────────────────────────────

export class SecurityCodeActionProvider implements vscode.CodeActionProvider {
    public static readonly providedCodeActionKinds = [
        vscode.CodeActionKind.QuickFix
    ];

    public provideCodeActions(
        document: vscode.TextDocument,
        _range: vscode.Range | vscode.Selection,
        context: vscode.CodeActionContext,
        _token: vscode.CancellationToken
    ): vscode.ProviderResult<(vscode.CodeAction | vscode.Command)[]> {
        const diagnostics = context.diagnostics.filter(
            d => d.source === '🛡️ AI Security Copilot'
        );
        if (diagnostics.length === 0) { return []; }

        return diagnostics.map(diagnostic => {
            const action = new vscode.CodeAction(
                '✨ Fix with SecureStack',
                vscode.CodeActionKind.QuickFix
            );
            action.diagnostics = [diagnostic];
            action.isPreferred = true;
            action.command = {
                command: 'aiSecurityCopilot.fixIssue',
                title: '✨ Fix with SecureStack',
                arguments: [document, diagnostic]
            };
            return action;
        });
    }
}


// ── Apply fix for a single diagnostic ───────────────────────────────────────

export async function applySecurityFix(
    document: vscode.TextDocument,
    diagnostic: vscode.Diagnostic
): Promise<boolean> {
    const lineNum = diagnostic.range.start.line;
    const lineText = document.lineAt(lineNum).text;
    const issueMsg = diagnostic.message;

    // 1. Try inbuilt fix engine first
    let result = getInbuiltFix(lineText, issueMsg, lineNum);

    // 2. Fall back to backend API if no inbuilt fix found
    if (!result) {
        result = await fetchApiFix(document.getText(), issueMsg, lineNum);
    }

    if (!result) {
        vscode.window.showErrorMessage(
            `SecureStack: No fix available for "${issueMsg.substring(0, 60)}..."`
        );
        return false;
    }

    if (result.envUpdate) {
        const action = await vscode.window.showInformationMessage(
            `SecureStack found a hardcoded secret. Extract it to a .env file automatically?`,
            'Yes', 'No'
        );
        if (action !== 'Yes') {
            return false; // Cancel fix if not permitted
        }
        await appendToEnv(document.uri, [result.envUpdate]);
    }

    const edit = new vscode.WorkspaceEdit();
    edit.replace(document.uri, document.lineAt(lineNum).range, result.fix);

    const success = await vscode.workspace.applyEdit(edit);
    if (success) {
        vscode.window.showInformationMessage(`✅ Fix applied: ${result.explanation}`);
    } else {
        vscode.window.showErrorMessage('SecureStack: Failed to apply the edit.');
    }
    return success;
}

// ── Apply fix by URI + line number (used by hover command link) ──────────────

export async function applyFixAtPosition(
    uriString: string,
    lineNum: number,
    dc: vscode.DiagnosticCollection
): Promise<void> {
    let uri: vscode.Uri;
    try { uri = vscode.Uri.parse(uriString, true); } catch { return; }

    let document: vscode.TextDocument;
    try { document = await vscode.workspace.openTextDocument(uri); } catch { return; }

    const all = dc.get(uri);
    if (!all) { return; }

    const diag = [...all].find(
        d => d.source === '🛡️ AI Security Copilot' && d.range.start.line === lineNum
    );
    if (!diag) { return; }

    await applySecurityFix(document, diag);
}

// ── Apply all fixes in a file ────────────────────────────────────────────────

export async function applyAllFixes(
    document: vscode.TextDocument,
    diagnosticsCollection: vscode.DiagnosticCollection
) {
    const diagnostics = diagnosticsCollection.get(document.uri);
    const secDiags = [...(diagnostics ?? [])].filter(
        d => d.source === '🛡️ AI Security Copilot'
    );

    if (secDiags.length === 0) {
        vscode.window.showInformationMessage('✅ No SecureStack issues found in this file.');
        return;
    }

    await vscode.window.withProgress(
        {
            location: vscode.ProgressLocation.Notification,
            title: `🛡️ SecureStack: Fixing ${secDiags.length} issue(s)…`,
            cancellable: false
        },
        async () => {
            // Process highest line first so replacements don't shift earlier line numbers
            const sorted = [...secDiags].sort((a, b) => b.range.start.line - a.range.start.line);

            // Snapshot the document ONCE before any edits touch it
            const current =
                vscode.workspace.textDocuments.find(
                    d => d.uri.toString() === document.uri.toString()
                ) ?? document;

            // Collect ALL replacements into ONE WorkspaceEdit.
            // A single applyEdit() = a single undo step, so Ctrl+Z reverts everything at once.
            const batchEdit = new vscode.WorkspaceEdit();
            const seenLines = new Set<number>();
            const envUpdates: { key: string; value: string; }[] = [];
            let fixed = 0;

            for (const diag of sorted) {
                const lineNum = diag.range.start.line;
                if (lineNum >= current.lineCount) { continue; }
                if (seenLines.has(lineNum)) { continue; }

                const lineText = current.lineAt(lineNum).text;
                let result = getInbuiltFix(lineText, diag.message, lineNum);
                if (!result) {
                    result = (await fetchApiFix(current.getText(), diag.message, lineNum)) as any;
                }

                if (result) {
                    batchEdit.replace(current.uri, current.lineAt(lineNum).range, result.fix);
                    if (result.envUpdate) {
                        envUpdates.push(result.envUpdate);
                    }
                    seenLines.add(lineNum);
                    fixed++;
                }
            }

            if (envUpdates.length > 0) {
                const action = await vscode.window.showInformationMessage(
                    `SecureStack found ${envUpdates.length} hardcoded secret(s). Extract them to a .env file automatically?`,
                    'Yes', 'No'
                );
                if (action !== 'Yes') {
                    return; // Cancel the entire batch if user says no
                }
                await appendToEnv(document.uri, envUpdates);
            }

            if (fixed > 0) {
                const success = await vscode.workspace.applyEdit(batchEdit);
                if (!success) {
                    vscode.window.showErrorMessage('SecureStack: Failed to apply batch edit.');
                    return;
                }
            }

            vscode.window.showInformationMessage(
                `✅ SecureStack: ${fixed}/${secDiags.length} issue(s) fixed.`
            );
        }
    );
}

// ── Environment Helpers ──────────────────────────────────────────────────────

async function appendToEnv(documentUri: vscode.Uri, updates: { key: string; value: string; }[]) {
    const workspaceFolder = vscode.workspace.getWorkspaceFolder(documentUri);
    if (!workspaceFolder) { return; }

    const envPath = vscode.Uri.joinPath(workspaceFolder.uri, '.env');
    let envContent = '';
    try {
        const data = await vscode.workspace.fs.readFile(envPath);
        envContent = Buffer.from(data).toString('utf-8');
    } catch {
        // File doesn't exist yet
    }

    let newContent = envContent;
    if (newContent.length > 0 && !newContent.endsWith('\n')) {
        newContent += '\n';
    }

    const unique = new Map<string, string>();
    for (const u of updates) { unique.set(u.key, u.value); }

    let addedCount = 0;
    for (const [key, value] of unique) {
        if (!newContent.includes(`${key}=`)) {
            newContent += `${key}="${value}"\n`;
            addedCount++;
        }
    }

    if (addedCount > 0) {
        await vscode.workspace.fs.writeFile(envPath, Buffer.from(newContent, 'utf-8'));
        vscode.window.showInformationMessage(`✅ Secrets securely extracted to .env file`);
    }
}

// ── Backend API fallback ─────────────────────────────────────────────────────

async function fetchApiFix(
    code: string,
    issueMessage: string,
    line: number
): Promise<{ fix: string; explanation: string } | null> {
    try {
        const response = await fetch('http://localhost:3000/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ code, issue: issueMessage, line }),
            signal: AbortSignal.timeout(10_000)
        });
        if (!response.ok) { return null; }
        const data = await response.json() as { fix?: string; explanation?: string };
        if (data.fix) {
            return {
                fix: data.fix,
                explanation: data.explanation ?? 'Fix applied via SecureStack AI.'
            };
        }
    } catch {
        // Backend unavailable — silently return null
    }
    return null;
}
