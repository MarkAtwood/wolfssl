# Contributing to wolfSSL

## Contributor Agreement

External contributors must sign a contributor agreement before pull requests can be merged. When you open your first PR, a wolfSSL team member will ask you to email support@wolfssl.com referencing the PR. The agreement is tracked via wolfSSL's Zendesk ticketing system. Once signed, your PR will be approved for CI testing.

## Fork Workflow

Do not push branches to this repository. Fork to your personal GitHub account and open pull requests from your fork.

## Source Code Rules

CI enforces all of these on every PR. Violations block merge.

### Formatting

- **No trailing whitespace.** Files must end with a newline.
- **No hard tabs** in C, header, or YAML files. Makefiles are exempt.
- **ASCII only.** No non-ASCII bytes in source files. All code, comments, and string literals must be pure ASCII. Specific exclusions exist for test data files.
- **No CR characters** (`\r`). Use Unix line endings.

### C Style

- **C comments only.** Use `/* */`, not `//`, in all `.c` and `.h` files. The only exceptions are `// NOLINT` and `// cppcheck` suppression comments.
- **No flush-left function calls** (a sign of debug residue).
- **No macros with arguments but empty bodies** in `wolfssl/`, `wolfcrypt/src/`, or `src/`.

### Headers

- **Every public header must compile standalone** when preceded only by `#include <wolfssl/options.h>`. CI compiles each header individually to verify this.

### Spelling and Linting

- **codespell** runs on all files in the repository (not just changed files). Fix any flagged typos before submitting.
- **shellcheck** runs on all shell scripts with `--severity=warning`. Fix warnings before submitting.

### AI Attribution

- **No AI attribution in commits.** CI rejects commits containing `Co-authored-by:` or `Signed-off-by:` trailers that reference:
  - `noreply@anthropic.com`
  - `noreply@openai.com`
  - `+Copilot@users.noreply.github.com`
  - Any `[bot]@users.noreply.github.com` address
- Commits authored by bot email addresses are also rejected.
- **Do not add these trailers.** Your PR will fail CI if they are present.

## PR Requirements

Use the PR template (`.github/PULL_REQUEST_TEMPLATE.md`). Every PR must include:

- **Description** of the scope of the fix or feature
- **Tracking reference** — `Fixes zd#NNNN` for Zendesk tickets (wolfSSL uses Zendesk, not GitHub Issues, for bug tracking)
- **Test description** — how the change was tested
- **Checklist:**
  - Added or updated tests for the change
  - Updated doxygen comments for any changed public APIs
  - Updated README or documentation if applicable

All CI checks must pass before merge.

## Testing Before Submitting

At minimum, run:

```bash
./configure && make check
```

For broader coverage, test against the CI smoke configurations (see `AI/build-linux.md` for the list). The most important configurations to test locally:

```bash
# Default
./configure && make check

# All features
./configure --enable-all && make check

# OpenSSL compat
./configure --enable-opensslextra && make check

# Crypto only
./configure --enable-cryptonly && make check
```

Use `--cflags=-Werror` to match CI strictness.

## Security Reports

Do not open GitHub issues for security vulnerabilities. Report them to support@wolfssl.com using the template in `SECURITY-REPORT-TEMPLATE.md`.
