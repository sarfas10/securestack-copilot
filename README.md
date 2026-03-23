# SecureStack Copilot

SecureStack Copilot is an intelligent, AI-powered VS Code extension designed to detect security vulnerabilities in your codebase and provide actionable, automated fixes directly within your editor.

![SecureStack Copilot Demo](https://via.placeholder.com/800x400.png?text=SecureStack+Copilot+Demo) <!-- Replace with actual demo GIF or image -->

## 🌟 Features

- **Real-time Security Scanning**: Automatically analyzes your code as you type to identify potential vulnerabilities.
- **AI-Powered Fixes**: Suggests context-aware fixes for detected vulnerabilities.
- **Inline Diffs**: Preview suggested fixes directly in your code with intuitive red/green diffs before applying them.
- **Common Vulnerability Detection**: Specialized in finding issues like:
  - SQL Injections
  - Hardcoded Secrets and API Keys
  - Cross-Site Scripting (XSS)
  - Insecure Deserialization
  - And more...
- **Secret Extraction**: Automatically detects hardcoded secrets and securely extracts them into `.env` files, replacing the references in your code.
- **One-Click Fixes**: Fix all issues in a file with a single command (`aiSecurityCopilot.fixAllInFile`).

## 🚀 Installation

1. Open VS Code.
2. Go to the Extensions view (`Ctrl+Shift+X` or `Cmd+Shift+X`).
3. Search for **SecureStack Copilot**.
4. Click **Install**.
5. Restart VS Code (if necessary).

*Alternatively, you can compile and install from source:*

```bash
git clone https://github.com/sarfas10/securestack-copilot.git
cd securestack-copilot
npm install
npm run compile
code .
```
Press `F5` in VS Code to run the extension in a new Extension Development Host window.

## 🛠️ Usage

Once installed, SecureStack Copilot works automatically in the background.

- **Vulnerability Alerts**: When a vulnerability is detected, a badge or squiggly line will appear under the affected code.
- **Applying a Fix**: 
  - Hover over the highlighted code.
  - Click on the **Quick Fix** (lightbulb icon) or use `Ctrl+.` (`Cmd+.` on macOS).
  - Select the suggested fix to apply it.
- **Fix All**: Open the command palette (`Ctrl+Shift+P` / `Cmd+Shift+P`) and type `SecureStack: Fix All Issues in File`.

## 🤝 Contributing

We welcome contributions from the community! If you're interested in improving SecureStack Copilot, please read our [Contributing Guidelines](CONTRIBUTING.md) to get started. By participating, you are expected to uphold our [Code of Conduct](CODE_OF_CONDUCT.md).

## 🛡️ Security

If you discover a security vulnerability within SecureStack Copilot itself, please review our [Security Policy](SECURITY.md) for detailed reporting instructions.

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
