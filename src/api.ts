// Copyright 2026 Valters Capital, SIA
// Licensed under the Apache License, Version 2.0.
// ValtersIT is a trademark of Valters Capital, SIA — see NOTICE.
// Maintained by Hugo Valters

/**
 * Minimal ValtersIT API client for the extension - Node built-ins only.
 * Mirrors the behaviour of the scanners' valtersit_client.py: the
 * account-level consent call before every scan, the 1000-component cap, and
 * the HMAC-signed opaque system identifier.
 */

import { createHash, createHmac } from "crypto";
import { request } from "https";
import { URL } from "url";

export const CLIENT_VERSION = "1.0.0";
export const ATTESTATION_VERSION = "v2";
export const MAX_SCAN_COMPONENTS = 1000;

export const AUTHORISATION_NOTICE =
  "Run this tool ONLY against systems you own, or for which you have explicit written authorisation to assess.\n\n" +
  "This scan sends only component name + version, plus an opaque system identifier (a one-way hash of local " +
  "machine signals such as machine-id and disk UUID, so repeat scans are recognised as the same system), to the " +
  "ValtersIT API — no IP address, hostname, MAC address, or file contents. See the Privacy Policy: " +
  "https://www.valtersit.com/privacy";

export interface ScanComponent {
  vendor: string;
  product: string;
  version: string;
  slug: string;
}

export interface ScanResult {
  slug?: string;
  product?: string;
  version?: string;
  cve_id?: string;
  cvss?: number;
  patched_in?: string;
  [key: string]: unknown;
}

export interface ApiResponse {
  status: number | undefined;
  body: unknown;
}

/**
 * Opaque, HMAC-signed system identifier in the same format the scanners use:
 * <stable_32hex>.<unix_ts>.<hmac_sha256_20hex>. The stable part is a SHA-256
 * of VS Code's own anonymous machine id - not reversible to anything.
 */
export function fingerprint(machineId: string, apiKey: string, now: number = Date.now()): string {
  const stable = createHash("sha256").update("vscode:" + machineId).digest("hex").slice(0, 32);
  const ts = Math.floor(now / 1000);
  const sig = createHmac("sha256", apiKey).update(`${stable}:${ts}`).digest("hex").slice(0, 20);
  return `${stable}.${ts}.${sig}`;
}

function call(apiBase: string, apiKey: string, method: string, path: string, body?: unknown): Promise<ApiResponse> {
  const url = new URL(apiBase.replace(/\/+$/, "") + "/" + path.replace(/^\/+/, ""));
  if (url.protocol !== "https:") {
    return Promise.resolve({ status: undefined, body: { detail: "valtersit.apiBase must be an https:// URL" } });
  }
  const payload = body === undefined ? undefined : Buffer.from(JSON.stringify(body));
  return new Promise((resolve) => {
    const req = request(
      url,
      {
        method,
        timeout: 30000,
        headers: {
          Authorization: "Bearer " + apiKey,
          "User-Agent": `valtersit-vscode/${CLIENT_VERSION} (+https://www.valtersit.com)`,
          Accept: "application/json",
          ...(payload ? { "Content-Type": "application/json", "Content-Length": payload.length } : {}),
        },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => {
          const text = Buffer.concat(chunks).toString("utf8");
          let parsed: unknown = {};
          try {
            parsed = text ? JSON.parse(text) : {};
          } catch {
            parsed = { detail: text.slice(0, 500) };
          }
          resolve({ status: res.statusCode, body: parsed });
        });
      },
    );
    req.on("timeout", () => req.destroy(new Error("request timed out")));
    req.on("error", (err) => resolve({ status: undefined, body: { detail: err.message } }));
    if (payload) {
      req.write(payload);
    }
    req.end();
  });
}

async function callWithRetry(apiBase: string, apiKey: string, method: string, path: string, body?: unknown): Promise<ApiResponse> {
  for (let attempt = 0; ; attempt++) {
    const res = await call(apiBase, apiKey, method, path, body);
    if (res.status !== 429 || attempt >= 3) {
      return res;
    }
    await new Promise((r) => setTimeout(r, 2 ** (attempt + 1) * 1000));
  }
}

export function explainStatus(res: ApiResponse): string {
  const b = res.body as { detail?: unknown; error?: unknown } | undefined;
  let detail = b && (b.detail ?? b.error);
  if (detail && typeof detail !== "string") {
    detail = JSON.stringify(detail);
  }
  switch (res.status) {
    case undefined:
      return `Could not reach the ValtersIT API (${detail || "network error"}).`;
    case 401:
      return `Not authenticated — check your API key (ValtersIT: Set API Key). (${detail || ""})`;
    case 403:
      return `Forbidden — your plan does not include this endpoint. (${detail || ""})`;
    case 422:
      return `Request rejected by the API — validation error. (${detail || ""})`;
    case 429:
      return `Rate limited by the API, even after retrying. (${detail || ""})`;
    default:
      return `Unexpected API response: HTTP ${res.status} (${detail || ""})`;
  }
}

/** POST /scan/consent (account-level, idempotent) then POST /scan. */
export async function submitScan(
  apiBase: string,
  apiKey: string,
  machineId: string,
  components: ScanComponent[],
): Promise<{ ok: boolean; truncated: boolean; response: ApiResponse }> {
  const truncated = components.length > MAX_SCAN_COMPONENTS;
  const inventory = truncated ? components.slice(0, MAX_SCAN_COMPONENTS) : components;
  const consent = await callWithRetry(apiBase, apiKey, "POST", "/scan/consent");
  if (consent.status !== 200 && consent.status !== 204) {
    return { ok: false, truncated, response: consent };
  }
  const res = await callWithRetry(apiBase, apiKey, "POST", "/scan", {
    fingerprint: fingerprint(machineId, apiKey),
    components: inventory,
  });
  const ok = res.status !== undefined && res.status >= 200 && res.status < 300;
  return { ok, truncated, response: res };
}

export function resultsOf(body: unknown): ScanResult[] {
  const results = (body as { results?: unknown })?.results;
  return Array.isArray(results) ? results.filter((r): r is ScanResult => !!r && typeof r === "object") : [];
}
