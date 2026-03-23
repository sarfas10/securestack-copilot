import * as vscode from 'vscode';
import { getInbuiltFix } from './fixEngine';
import { exec } from 'child_process';

// ── Notification Sound Helper ────────────────────────────────────────────────

function playNotificationSound() {
    try {
        if (process.platform === 'win32') {
            exec('powershell -c "[System.Media.SystemSounds]::Asterisk.Play()"');
        } else if (process.platform === 'darwin') {
            exec('afplay /System/Library/Sounds/Ping.aiff');
        } else {
            exec('paplay /usr/share/sounds/freedesktop/stereo/message.oga');
        }
    } catch {
        // Suppress failures if audio isn't available
    }
}

// ── Inline Preview Decorators ───────────────────────────────────────────────

const redBackground = vscode.window.createTextEditorDecorationType({
    backgroundColor: 'rgba(255, 0, 0, 0.2)',
    isWholeLine: true
});

const greenBackground = vscode.window.createTextEditorDecorationType({
    backgroundColor: 'rgba(0, 255, 0, 0.2)',
    isWholeLine: true
});

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

    let result = getInbuiltFix(lineText, issueMsg, lineNum);
    if (!result) {
        result = await fetchApiFix(document.getText(), issueMsg, lineNum);
    }

    if (!result) {
        vscode.window.showErrorMessage(
            `SecureStack: No fix available for "${issueMsg.substring(0, 60)}..."`
        );
        return false;
    }

    const edit = new vscode.WorkspaceEdit();
    let fixText = result.fix;
    if (!fixText.endsWith('\n')) {
        fixText += '\n';
    }
    const fixLinesCount = fixText.split(/\r?\n/).length - 1;

    edit.insert(document.uri, new vscode.Position(lineNum + 1, 0), fixText);
    await vscode.workspace.applyEdit(edit);

    const changes = [{
        originalLineNum: lineNum,
        insertedLineNum: lineNum + 1,
        fixLinesCount
    }];

    const editor = vscode.window.activeTextEditor;
    if (editor && editor.document === document) {
        editor.setDecorations(redBackground, [document.lineAt(lineNum).range]);
        
        if (fixLinesCount > 0) {
            const startPos = new vscode.Position(lineNum + 1, 0);
            const endPos = new vscode.Position(lineNum + fixLinesCount - 1, Number.MAX_VALUE);
            editor.setDecorations(greenBackground, [new vscode.Range(startPos, endPos)]);
        }
    }

    playNotificationSound();
    const action = await vscode.window.showInformationMessage(
        'Apply this AI fix?', { modal: false }, 'Accept', 'Reject'
    );

    // Clear decorations regardless of choice
    if (editor && editor.document === document) {
        editor.setDecorations(redBackground, []);
        editor.setDecorations(greenBackground, []);
    }

    if (action === 'Accept') {
        const acceptEdit = new vscode.WorkspaceEdit();
        for (const change of changes) {
            acceptEdit.delete(document.uri, document.lineAt(change.originalLineNum).rangeIncludingLineBreak);
        }
        await vscode.workspace.applyEdit(acceptEdit);
        
        if (result.envUpdate) {
            const existingKeys = await getExistingEnvKeys(document.uri);
            if (!existingKeys.has(result.envUpdate.key)) {
                const envAction = await vscode.window.showInformationMessage(
                    `SecureStack found a hardcoded secret. Extract it to a .env file automatically?`,
                    'Yes', 'No'
                );
                if (envAction === 'Yes') {
                    await appendToEnv(document.uri, [result.envUpdate]);
                }
            }
        }
        return true;
    } else {
        const rejectEdit = new vscode.WorkspaceEdit();
        for (const change of changes) {
            const start = new vscode.Position(change.insertedLineNum, 0);
            const end = new vscode.Position(change.insertedLineNum + change.fixLinesCount, 0);
            rejectEdit.delete(document.uri, new vscode.Range(start, end));
        }
        await vscode.workspace.applyEdit(rejectEdit);
        return false;
    }
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
            const sorted = [...secDiags].sort((a, b) => b.range.start.line - a.range.start.line);

            const current =
                vscode.workspace.textDocuments.find(
                    d => d.uri.toString() === document.uri.toString()
                ) ?? document;

            const batchEdit = new vscode.WorkspaceEdit();
            const seenLines = new Set<number>();
            const changes = [];
            const envUpdates = [];
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
                    let fixText = result.fix;
                    if (!fixText.endsWith('\n')) {
                        fixText += '\n';
                    }
                    const fixLinesCount = fixText.split(/\r?\n/).length - 1;

                    batchEdit.insert(current.uri, new vscode.Position(lineNum + 1, 0), fixText);
                    changes.push({
                        originalLineNum: lineNum,
                        insertedLineNum: lineNum + 1,
                        fixLinesCount
                    });
                    if (result.envUpdate) {
                        envUpdates.push(result.envUpdate);
                    }
                    seenLines.add(lineNum);
                    fixed++;
                }
            }

            if (fixed > 0) {
                await vscode.workspace.applyEdit(batchEdit);
                changes.reverse();

                const editor = vscode.window.activeTextEditor;
                if (editor && editor.document === current) {
                    const redRanges = changes.map(c => current.lineAt(c.originalLineNum).range);
                    const greenRanges = changes.map(c => {
                        if (c.fixLinesCount > 0) {
                            const start = new vscode.Position(c.insertedLineNum, 0);
                            const end = new vscode.Position(c.insertedLineNum + c.fixLinesCount - 1, Number.MAX_VALUE);
                            return new vscode.Range(start, end);
                        }
                        return null;
                    }).filter((r): r is vscode.Range => r !== null);

                    editor.setDecorations(redBackground, redRanges);
                    editor.setDecorations(greenBackground, greenRanges);
                }

                playNotificationSound();
                const action = await vscode.window.showInformationMessage(
                    `Apply ${fixed} AI fix(es)?`, { modal: false }, 'Accept All', 'Reject All'
                );

                if (editor && editor.document === current) {
                    editor.setDecorations(redBackground, []);
                    editor.setDecorations(greenBackground, []);
                }

                if (action === 'Accept All') {
                    const acceptEdit = new vscode.WorkspaceEdit();
                    const sortedDesc = [...changes].sort((a, b) => b.originalLineNum - a.originalLineNum);
                    for (const change of sortedDesc) {
                        acceptEdit.delete(document.uri, document.lineAt(change.originalLineNum).rangeIncludingLineBreak);
                    }
                    await vscode.workspace.applyEdit(acceptEdit);

                    if (envUpdates.length > 0) {
                        const existingKeys = await getExistingEnvKeys(document.uri);
                        const newUpdates = envUpdates.filter(u => !existingKeys.has(u.key));

                        if (newUpdates.length > 0) {
                            const envAction = await vscode.window.showInformationMessage(
                                `SecureStack found ${newUpdates.length} hardcoded secret(s). Extract them to a .env file automatically?`,
                                'Yes', 'No'
                            );
                            if (envAction === 'Yes') {
                                await appendToEnv(document.uri, newUpdates);
                            }
                        }
                    }
                } else {
                    const rejectEdit = new vscode.WorkspaceEdit();
                    const sortedDesc = [...changes].sort((a, b) => b.insertedLineNum - a.insertedLineNum);
                    for (const change of sortedDesc) {
                        const start = new vscode.Position(change.insertedLineNum, 0);
                        const end = new vscode.Position(change.insertedLineNum + change.fixLinesCount, 0);
                        rejectEdit.delete(document.uri, new vscode.Range(start, end));
                    }
                    await vscode.workspace.applyEdit(rejectEdit);
                }
            }
        }
    );
}

// ── Environment Helpers ──────────────────────────────────────────────────────

async function getExistingEnvKeys(documentUri: vscode.Uri): Promise<Set<string>> {
    const keys = new Set<string>();
    const workspaceFolder = vscode.workspace.getWorkspaceFolder(documentUri);
    if (!workspaceFolder) { return keys; }

    const envPath = vscode.Uri.joinPath(workspaceFolder.uri, '.env');
    try {
        const data = await vscode.workspace.fs.readFile(envPath);
        const content = Buffer.from(data).toString('utf-8');
        for (const line of content.split(/\r?\n/)) {
            const trimmed = line.trim();
            if (trimmed && !trimmed.startsWith('#')) {
                const eqIdx = trimmed.indexOf('=');
                if (eqIdx > 0) {
                    keys.add(trimmed.substring(0, eqIdx).trim());
                }
            }
        }
    } catch {
        // File doesn't exist yet
    }
    return keys;
}

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
