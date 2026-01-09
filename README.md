# Marauder - Offline Password Manager

## Scope

Marauder is an offline-first password manager with a Python backend and browser extension. The system is designed to operate entirely locally, providing secure password storage and management without requiring internet connectivity or cloud services.

### Core Features (Planned)

- Local password storage with encryption
- Browser extension for password management
- Secure key derivation and encryption
- Password generation and strength analysis
- Secure credential retrieval and autofill

## Non-Goals

The following features are explicitly **not** part of this project's scope:

- **Cloud synchronization**: No cloud-based storage or sync capabilities
- **Online features**: No network communication or remote services
- **Third-party integrations**: No integration with external password managers or services (initially)
- **Multi-device sync**: No automatic synchronization across devices
- **Web-based interface**: No web application or online dashboard

## Security Assumptions

This project operates under the following security assumptions:

1. **Local-only storage**: All data is stored locally on the user's device
2. **No network communication**: The application does not send data over the network
3. **User-controlled encryption keys**: Users generate and manage their own encryption keys
4. **Offline operation**: The system is designed to function without internet connectivity
5. **No telemetry**: No usage data or telemetry is collected or transmitted

## Development Setup

### Prerequisites

- Python 3.11 or higher
- pip (Python package manager)
- git

### Installation

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd Marauder
   ```

2. Create a virtual environment:
   ```bash
   python -m venv .venv
   ```

3. Activate the virtual environment:
   - On Windows:
     ```bash
     .venv\Scripts\activate
     ```
   - On Unix/macOS:
     ```bash
     source .venv/bin/activate
     ```

4. Install the project in editable mode with development dependencies:
   ```bash
   pip install -e ".[dev]"
   ```

5. Install pre-commit hooks:
   ```bash
   pre-commit install
   ```

### Running Tests

Run the test suite:
```bash
pytest
```

### Code Quality Checks

Run linting:
```bash
ruff check .
```

Check code formatting:
```bash
ruff format --check .
```

Run security analysis:
```bash
bandit -r src/
```

## Exit Criteria

Milestone 0 is considered complete when all of the following criteria are met:

- [x] Project installs cleanly: `pip install -e .` succeeds without errors
- [x] Linting passes: `ruff check` returns no errors
- [x] Formatting passes: `ruff format --check` returns no changes needed
- [x] Bandit passes: `bandit -r src/` returns no high/critical severity issues
- [x] Empty test suite runs: `pytest` executes successfully with 0 tests

## CI/CD Integration

This project is structured to be CI-ready. A typical CI pipeline should:

1. Install Python 3.11+
2. Install dependencies: `pip install -e ".[dev]"`
3. Run code quality checks:
   - `ruff check .`
   - `ruff format --check .`
   - `bandit -r src/`
4. Run tests: `pytest`

The project structure is platform-agnostic and can be adapted to GitHub Actions, GitLab CI, Jenkins, or any other CI/CD platform.

## License

MIT License

