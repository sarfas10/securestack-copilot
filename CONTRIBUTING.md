# Contributing to SecureStack Copilot

First off, thank you for considering contributing to SecureStack Copilot! It's people like you that make open source such a great community to learn, inspire, and create.

## Where do I go from here?

If you've noticed a bug or have a feature request, make one! It's generally best if you get confirmation of your bug or approval for your feature request this way before starting to code.

## Setting up your development environment

1. **Fork the repository** to your own GitHub account.
2. **Clone the repository** to your local machine:
   ```bash
   git clone https://github.com/YOUR_USERNAME/securestack-copilot.git
   ```
3. **Install dependencies**:
   ```bash
   cd securestack-copilot
   npm install
   ```
4. **Open in VS Code**:
   ```bash
   code .
   ```
5. **Run the extension**: Press `F5` to open a new window with your extension loaded.

## Making Changes

1. Create a new branch for your feature or bug fix:
   ```bash
   git checkout -b feature/your-feature-name
   ```
2. Make your code changes.
3. Keep your commits small, focused, and well-described.
4. Make sure the code compiles by running `npm run compile`.
5. Run tests locally if applicable.

## Submitting a Pull Request (PR)

1. Push your branch to your fork on GitHub.
2. Open a Pull Request against the `main` branch of the upstream repository.
3. Fill out the PR template completely. Ensure you describe the problem you're fixing and the approach you took.
4. Link the PR to any related issues.
5. Wait for a maintainer to review your code. We may request changes before merging.

## Coding Rules

- Follow the existing code style and formatting (we use TypeScript).
- Write meaningful variable names and useful comments.
- Ensure that any new AI detection logic is thoroughly tested to prevent false positives.

Thank you for contributing!
