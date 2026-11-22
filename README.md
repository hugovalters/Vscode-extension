# VS Code Extension

See known CVEs in your project's dependencies right in VS Code's Problems
panel — on the exact line of the lockfile where each vulnerable package is
declared. Open source, auditable, privacy-first — powered by the ValtersIT
CVE API.

> Part of the ValtersIT platform — CVE & Threat-IP data you can query or run yourself.
> Explore both API and scanners: https://www.valtersit.com/platform/
> Scanner plans & pricing: https://www.valtersit.com/cve/pricing/#scanners

## What it does

**ValtersIT: Scan Workspace Dependencies** (command palette, or the
`$(shield) ValtersIT` status-bar item) finds every dependency file in the
workspace, reads the pinned versions locally, submits them to the ValtersIT
API and shows each matched CVE as a diagnostic:

- **Error** for CVSS ≥ 7.0, **Warning** for 4.0–6.9, **Information** below
  that;
- message `CVE-XXXX-XXXXX in <package> <version> (CVSS 9.1) — fixed in
  <version>`;
- the CVE id is a link to the full ValtersIT write-up.

| File | Ecosystem |
|---|---|
| `package-lock.json`, `npm-shrinkwrap.json` (v1, v2, v3) | npm |
| `requirements*.txt` (`name==version` lines) | PyPI |
| `Gemfile.lock` | RubyGems |
| `composer.lock` | Composer / Packagist |
| `packages.lock.json`, `*.csproj` / `*.fsproj` / `*.vbproj`, `packages.config` | NuGet |

`node_modules`, `vendor`, virtualenvs, `bin`, `obj` and build output are
never searched (configurable).

## Your data stays yours

- **What we receive:** package name and version only (e.g. `lodash
  4.17.15`), plus an opaque system identifier — a SHA-256 of VS Code's own
  anonymous machine id, signed per request so it cannot be replayed.
- **What we never receive:** your source code, file paths, workspace or
  repository name, IP address, hostname, or the contents of any file.
  Dependency files are parsed locally inside the extension; only `name` +
  `version` (+ that opaque identifier) leave VS Code.
- **Where your API key lives:** VS Code's SecretStorage (the operating
  system keychain) — never in `settings.json` or the workspace.
- **No runtime dependencies:** the extension uses only Node's built-in
  `https` and `crypto` modules — no npm packages are bundled.
- **Audit it yourself.** Three TypeScript files in `src/`, ~650 lines.

## Install

The extension is built from source:

```bash
git clone https://gitlab.com/valtersit/vscode-extension
cd vscode-extension
npm install            # dev tools only: typescript, @types/vscode, @types/node
npm run compile
npx @vscode/vsce package
code --install-extension valtersit-cve-scanner-1.0.0.vsix
```

Requires VS Code 1.85 or newer (also works in VSCodium and other VS Code
based editors that support `.vsix` install).

## First use

1. **ValtersIT: Set API Key** — paste your `vit_v1_…` key. Get one at
   [valtersit.com/cve/pricing](https://www.valtersit.com/cve/pricing/#scanners).
2. **ValtersIT: Scan Workspace Dependencies** — the first time, a dialog
   shows the authorised-use notice (below) and asks you to confirm.
3. Open the **Problems** panel (`Ctrl+Shift+M` / `Cmd+Shift+M`).

Details of every run — files found, packages per file, matches — are in the
**ValtersIT** output channel.

## Settings

| Setting | Default | Meaning |
|---|---|---|
| `valtersit.scanOnSave` | `false` | Re-scan automatically when a dependency file is saved |
| `valtersit.includeDevDependencies` | `false` | Also scan `devDependencies` / `packages-dev` |
| `valtersit.minimumCvss` | `0` | Hide findings below this CVSS score |
| `valtersit.exclude` | `**/{node_modules,vendor,.venv,venv,bin,obj,dist,build}/**` | Paths never searched |
| `valtersit.apiBase` | `https://api.valtersit.com/api/v1` | API endpoint (must be `https://`) |

## Commands

| Command | |
|---|---|
| ValtersIT: Scan Workspace Dependencies | Scan now |
| ValtersIT: Set API Key / Remove API Key | Manage the key in SecretStorage |
| ValtersIT: Confirm Authorised Use | Show the notice again and re-confirm |
| ValtersIT: Clear Findings | Remove all ValtersIT diagnostics |

## Sample

```
package-lock.json  ●  CVE-2020-8203 in lodash 4.17.15 (CVSS 7.4) — fixed in 4.17.19   ValtersIT(CVE-2020-8203)  [Ln 214]
requirements.txt   ▲  CVE-2026-10412 in django 4.2.7 (CVSS 5.3) — fixed in 4.2.17     ValtersIT(CVE-2026-10412) [Ln 3]
```

Status bar: `$(shield) ValtersIT: 2`.

## Authorised use only

Scan only code you own, or for which you have explicit written
authorisation to assess. Before the first scan the extension shows this
and requires you to confirm:

```
ValtersIT Scanner — Authorised Use Confirmation

Run this tool ONLY against systems you own, or for which you have explicit
written authorisation to assess.

This scan sends only component name + version, plus an opaque system
identifier (a one-way hash of local machine signals such as machine-id and
disk UUID, so repeat scans are recognised as the same system), to the
ValtersIT API — no IP address, hostname, MAC address, or file contents.
See the Privacy Policy: https://www.valtersit.com/privacy

                                                  [ YES — I am authorised ]
```

Licensed under Apache-2.0 (see `LICENSE` and `NOTICE`); provided without
warranty of any kind. "ValtersIT" and the ValtersIT logo are trademarks of
Valters Capital, SIA and are not licensed for use. Visual Studio Code is a
trademark of Microsoft Corporation; this project is not affiliated with or
endorsed by it.

## Questions or a bug?

Please **don't** open GitHub/GitLab issues — I don't monitor them.
Reach me through the contact form instead: https://www.valtersit.com/contacts/

Maintained by Hugo Valters
