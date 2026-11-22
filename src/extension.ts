// Copyright 2026 Valters Capital, SIA
// Licensed under the Apache License, Version 2.0.
// ValtersIT is a trademark of Valters Capital, SIA — see NOTICE.
// Maintained by Hugo Valters

/**
 * ValtersIT CVE Scanner for VS Code.
 *
 * Finds dependency lockfiles/manifests in the workspace, reads the pinned
 * package versions from them locally, submits name + version to the
 * ValtersIT API, and shows matched CVEs as diagnostics on the line where
 * each package is declared. Nothing else from the workspace is read or sent.
 */

import * as path from "path";
import * as vscode from "vscode";
import {
  ATTESTATION_VERSION,
  AUTHORISATION_NOTICE,
  CLIENT_VERSION,
  MAX_SCAN_COMPONENTS,
  ScanComponent,
  explainStatus,
  resultsOf,
  submitScan,
} from "./api";
import { DEPENDENCY_GLOB, findLine, parserFor } from "./parsers";

const SECRET_KEY = "valtersit.apiKey";
const CONSENT_KEY = "valtersit.consent";

let diagnostics: vscode.DiagnosticCollection;
let output: vscode.OutputChannel;
let status: vscode.StatusBarItem;
let scanning = false;

export function activate(context: vscode.ExtensionContext): void {
  diagnostics = vscode.languages.createDiagnosticCollection("valtersit");
  output = vscode.window.createOutputChannel("ValtersIT");
  status = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 0);
  status.command = "valtersit.scanWorkspace";
  status.text = "$(shield) ValtersIT";
  status.tooltip = "Scan workspace dependencies for known CVEs";
  status.show();

  context.subscriptions.push(
    diagnostics,
    output,
    status,
    vscode.commands.registerCommand("valtersit.scanWorkspace", () => scanWorkspace(context)),
    vscode.commands.registerCommand("valtersit.setApiKey", () => setApiKey(context)),
    vscode.commands.registerCommand("valtersit.clearApiKey", async () => {
      await context.secrets.delete(SECRET_KEY);
      vscode.window.showInformationMessage("ValtersIT API key removed.");
    }),
    vscode.commands.registerCommand("valtersit.confirmAuthorisedUse", () => confirmAuthorisedUse(context, true)),
    vscode.commands.registerCommand("valtersit.clearDiagnostics", () => diagnostics.clear()),
    vscode.workspace.onDidSaveTextDocument((doc) => {
      const cfg = vscode.workspace.getConfiguration("valtersit");
      if (cfg.get<boolean>("scanOnSave") && parserFor(path.basename(doc.fileName))) {
        void scanWorkspace(context, true);
      }
    }),
  );
}

export function deactivate(): void {
  // Disposables registered in activate() are cleaned up by VS Code.
}

async function setApiKey(context: vscode.ExtensionContext): Promise<string | undefined> {
  const key = await vscode.window.showInputBox({
    title: "ValtersIT API key",
    prompt: "Stored in VS Code's secret storage on this machine - never in settings or the workspace.",
    password: true,
    ignoreFocusOut: true,
    placeHolder: "vit_v1_...",
    validateInput: (v) => (v.trim().length >= 8 ? undefined : "That does not look like an API key."),
  });
  if (key) {
    await context.secrets.store(SECRET_KEY, key.trim());
    vscode.window.showInformationMessage("ValtersIT API key saved.");
    return key.trim();
  }
  return undefined;
}

async function confirmAuthorisedUse(context: vscode.ExtensionContext, force = false): Promise<boolean> {
  const stored = context.globalState.get<{ attestation_version?: string }>(CONSENT_KEY);
  if (!force && stored?.attestation_version === ATTESTATION_VERSION) {
    return true;
  }
  const choice = await vscode.window.showWarningMessage(
    "ValtersIT Scanner — Authorised Use Confirmation",
    { modal: true, detail: AUTHORISATION_NOTICE },
    "YES — I am authorised",
  );
  if (choice !== "YES — I am authorised") {
    vscode.window.showInformationMessage("Confirmation not received - nothing was scanned.");
    return false;
  }
  await context.globalState.update(CONSENT_KEY, {
    confirmed: true,
    confirmed_at: new Date().toISOString(),
    attestation_version: ATTESTATION_VERSION,
    source: "vscode-extension",
    client_version: CLIENT_VERSION,
  });
  return true;
}

interface Origin {
  uri: vscode.Uri;
  fileName: string;
  text: string;
}

async function scanWorkspace(context: vscode.ExtensionContext, quiet = false): Promise<void> {
  if (scanning) {
    return;
  }
  if (!vscode.workspace.workspaceFolders?.length) {
    vscode.window.showWarningMessage("ValtersIT: open a folder or workspace first.");
    return;
  }
  if (!(await confirmAuthorisedUse(context))) {
    return;
  }
  let apiKey = await context.secrets.get(SECRET_KEY);
  if (!apiKey) {
    if (quiet) {
      return;
    }
    apiKey = await setApiKey(context);
    if (!apiKey) {
      return;
    }
  }

  const cfg = vscode.workspace.getConfiguration("valtersit");
  const includeDev = cfg.get<boolean>("includeDevDependencies", false);
  const minCvss = cfg.get<number>("minimumCvss", 0);
  const apiBase = cfg.get<string>("apiBase", "https://api.valtersit.com/api/v1");
  const exclude = cfg.get<string>("exclude") || undefined;

  scanning = true;
  status.text = "$(sync~spin) ValtersIT";
  try {
    await vscode.window.withProgress(
      { location: vscode.ProgressLocation.Window, title: "ValtersIT: scanning dependencies" },
      async () => {
        const files = await vscode.workspace.findFiles(DEPENDENCY_GLOB, exclude, 500);
        const components: ScanComponent[] = [];
        const origins = new Map<string, Origin[]>();
        const seen = new Set<string>();
        output.appendLine(`[${new Date().toISOString()}] Scanning ${files.length} dependency file(s)`);

        for (const uri of files) {
          const fileName = path.basename(uri.fsPath);
          const parse = parserFor(fileName);
          if (!parse) {
            continue;
          }
          let text: string;
          try {
            text = Buffer.from(await vscode.workspace.fs.readFile(uri)).toString("utf8");
          } catch {
            continue;
          }
          let found;
          try {
            found = parse(text, includeDev);
          } catch (err) {
            output.appendLine(`  ! could not parse ${vscode.workspace.asRelativePath(uri)}: ${String(err)}`);
            continue;
          }
          output.appendLine(`  ${vscode.workspace.asRelativePath(uri)}: ${found.length} pinned package(s)`);
          for (const c of found) {
            const key = `${c.product}@${c.version}`;
            const list = origins.get(key) ?? [];
            list.push({ uri, fileName, text });
            origins.set(key, list);
            const dedupe = `${c.vendor}|${key}`;
            if (!seen.has(dedupe)) {
              seen.add(dedupe);
              components.push({ ...c, slug: c.product });
            }
          }
        }

        diagnostics.clear();
        if (!components.length) {
          if (!quiet) {
            vscode.window.showInformationMessage("ValtersIT: no pinned dependencies found in this workspace.");
          }
          status.text = "$(shield) ValtersIT";
          return;
        }

        const { ok, truncated, response } = await submitScan(apiBase, apiKey as string, vscode.env.machineId, components);
        if (truncated) {
          output.appendLine(`  ! ${components.length} components found; the API accepts ${MAX_SCAN_COMPONENTS} per scan - the first ${MAX_SCAN_COMPONENTS} were sent.`);
        }
        if (!ok) {
          const msg = explainStatus(response);
          output.appendLine("  ! " + msg);
          vscode.window.showErrorMessage("ValtersIT: " + msg);
          status.text = "$(shield) ValtersIT";
          return;
        }

        const results = resultsOf(response.body).filter((r) => typeof r.cvss !== "number" || r.cvss >= minCvss);
        const byFile = new Map<string, vscode.Diagnostic[]>();
        for (const r of results) {
          const product = String(r.slug ?? r.product ?? "");
          const version = String(r.version ?? "");
          const cvss = typeof r.cvss === "number" ? r.cvss : undefined;
          const where = origins.get(`${product}@${version}`) ?? [];
          for (const o of where) {
            const line = findLine(o.text, o.fileName, product);
            const range = new vscode.Range(line, 0, line, Number.MAX_SAFE_INTEGER);
            const sev = cvss === undefined ? vscode.DiagnosticSeverity.Information
              : cvss >= 7 ? vscode.DiagnosticSeverity.Error
              : cvss >= 4 ? vscode.DiagnosticSeverity.Warning
              : vscode.DiagnosticSeverity.Information;
            const d = new vscode.Diagnostic(
              range,
              `${r.cve_id ?? "CVE"} in ${product} ${version}` +
                (cvss !== undefined ? ` (CVSS ${cvss.toFixed(1)})` : "") +
                (r.patched_in ? ` — fixed in ${r.patched_in}` : ""),
              sev,
            );
            d.source = "ValtersIT";
            if (r.cve_id) {
              d.code = { value: String(r.cve_id), target: vscode.Uri.parse(`https://www.valtersit.com/cve/${r.cve_id}/`) };
            }
            const k = o.uri.toString();
            byFile.set(k, [...(byFile.get(k) ?? []), d]);
          }
        }
        for (const [k, list] of byFile) {
          diagnostics.set(vscode.Uri.parse(k), list);
        }

        output.appendLine(`  Scan submitted: ${components.length} component(s), ${results.length} CVE match(es).`);
        status.text = results.length ? `$(shield) ValtersIT: ${results.length}` : "$(shield) ValtersIT: 0";
        if (!quiet) {
          const msg = results.length
            ? `ValtersIT: ${results.length} known CVE(s) in ${components.length} dependencies - see the Problems panel.`
            : `ValtersIT: no known CVEs in ${components.length} dependencies.`;
          vscode.window.showInformationMessage(msg);
        }
      },
    );
  } catch (err) {
    output.appendLine("  ! scan failed: " + String(err));
    vscode.window.showErrorMessage("ValtersIT: scan failed - see the ValtersIT output channel.");
  } finally {
    scanning = false;
    if (status.text.includes("sync~spin")) {
      status.text = "$(shield) ValtersIT";
    }
  }
}
