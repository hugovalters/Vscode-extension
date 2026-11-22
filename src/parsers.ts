// Copyright 2026 Valters Capital, SIA
// Licensed under the Apache License, Version 2.0.
// ValtersIT is a trademark of Valters Capital, SIA — see NOTICE.
// Maintained by Hugo Valters

/**
 * Dependency-file parsers. Pure functions (no VS Code API) so they can be
 * unit-tested with plain Node. Each returns the pinned packages it finds;
 * ranges, floating versions and unpinned entries are skipped, never guessed.
 */

export interface Component {
  vendor: string;
  product: string;
  version: string;
}

export type Parser = (text: string, includeDev: boolean) => Component[];

const REQ_LINE = /^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*===?\s*([^\s;#,]+)/;

export function parseRequirements(text: string): Component[] {
  const out: Component[] = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.split(" #")[0].trim();
    if (!line || line.startsWith("#") || line.startsWith("-")) {
      continue;
    }
    const m = REQ_LINE.exec(line);
    if (m) {
      out.push({ vendor: "PyPI", product: m[1].replace(/[-_.]+/g, "-").toLowerCase(), version: m[2] });
    }
  }
  return out;
}

interface LockEntry {
  version?: string;
  name?: string;
  dev?: boolean;
  link?: boolean;
  dependencies?: Record<string, LockEntry>;
}

export function parsePackageLock(text: string, includeDev: boolean): Component[] {
  const lock = JSON.parse(text) as { packages?: Record<string, LockEntry>; dependencies?: Record<string, LockEntry> };
  const out: Component[] = [];
  if (lock.packages && typeof lock.packages === "object") {
    for (const [path, meta] of Object.entries(lock.packages)) {
      if (!path || !meta || meta.link || !path.includes("node_modules/") || !meta.version) {
        continue;
      }
      if (meta.dev && !includeDev) {
        continue;
      }
      const name = meta.name || path.slice(path.lastIndexOf("node_modules/") + "node_modules/".length);
      out.push({ vendor: "npm", product: name, version: meta.version });
    }
    return out;
  }
  const walk = (deps: Record<string, LockEntry> | undefined): void => {
    for (const [name, meta] of Object.entries(deps || {})) {
      const v = meta.version || "";
      if (v && !(meta.dev && !includeDev) && !/^(file:|link:|git|http)/.test(v)) {
        out.push({ vendor: "npm", product: name, version: v });
      }
      walk(meta.dependencies);
    }
  };
  walk(lock.dependencies);
  return out;
}

export function parseGemfileLock(text: string): Component[] {
  const out: Component[] = [];
  let section = "";
  let inSpecs = false;
  for (const line of text.split(/\r?\n/)) {
    if (line && !line.startsWith(" ")) {
      section = line.trim();
      inSpecs = false;
      continue;
    }
    if (line.trim() === "specs:") {
      inSpecs = true;
      continue;
    }
    if (inSpecs && ["GEM", "GIT", "PATH"].includes(section)) {
      const m = /^ {4}([A-Za-z0-9][A-Za-z0-9._-]*) \(([^)]+)\)\s*$/.exec(line);
      if (m) {
        out.push({ vendor: "RubyGems", product: m[1], version: m[2].split("-")[0] });
      }
    }
  }
  return out;
}

export function parseComposerLock(text: string, includeDev: boolean): Component[] {
  const data = JSON.parse(text) as { packages?: { name?: string; version?: string }[]; "packages-dev"?: { name?: string; version?: string }[] };
  const pkgs = [...(data.packages || []), ...(includeDev ? data["packages-dev"] || [] : [])];
  return pkgs
    .filter((p) => p.name && p.version)
    .map((p) => ({ vendor: "Packagist", product: p.name as string, version: (p.version as string).replace(/^v(?=\d)/, "") }));
}

export function parseNugetLock(text: string): Component[] {
  const data = JSON.parse(text.replace(/^﻿/, "")) as {
    dependencies?: Record<string, Record<string, { type?: string; resolved?: string }>>;
  };
  const out: Component[] = [];
  for (const deps of Object.values(data.dependencies || {})) {
    for (const [name, meta] of Object.entries(deps || {})) {
      if (meta && meta.type !== "Project" && meta.resolved) {
        out.push({ vendor: "NuGet", product: name, version: meta.resolved });
      }
    }
  }
  return out;
}

export function parseProjectFile(text: string): Component[] {
  const out: Component[] = [];
  // <PackageReference Include="X" Version="1.2.3" /> or <PackageReference Include="X"><Version>1.2.3</Version>...
  const re = /<PackageReference\b([^>]*?)(?:\/>|>([\s\S]*?)<\/PackageReference>)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    const attrs = m[1];
    const name = /\b(?:Include|Update)\s*=\s*"([^"]+)"/.exec(attrs)?.[1];
    let version = /\bVersion\s*=\s*"([^"]+)"/.exec(attrs)?.[1];
    if (!version && m[2]) {
      version = /<Version>\s*([^<]+?)\s*<\/Version>/.exec(m[2])?.[1];
    }
    const exact = version ? /^\[?\s*([0-9][0-9A-Za-z.+-]*)\s*\]?$/.exec(version) : null;
    if (name && exact && !version!.includes(",") && !version!.includes("*")) {
      out.push({ vendor: "NuGet", product: name, version: exact[1] });
    }
  }
  return out;
}

export function parsePackagesConfig(text: string): Component[] {
  const out: Component[] = [];
  const re = /<package\b([^>]*)\/?>/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    const id = /\bid\s*=\s*"([^"]+)"/.exec(m[1])?.[1];
    const version = /\bversion\s*=\s*"([^"]+)"/.exec(m[1])?.[1];
    if (id && version) {
      out.push({ vendor: "NuGet", product: id, version });
    }
  }
  return out;
}

/** The parser for a file name, or undefined if the file is not a supported dependency file. */
export function parserFor(fileName: string): Parser | undefined {
  if (/^requirements[^/\\]*\.txt$/.test(fileName)) {
    return (t) => parseRequirements(t);
  }
  if (fileName === "package-lock.json" || fileName === "npm-shrinkwrap.json") {
    return parsePackageLock;
  }
  if (fileName === "Gemfile.lock") {
    return (t) => parseGemfileLock(t);
  }
  if (fileName === "composer.lock") {
    return parseComposerLock;
  }
  if (fileName === "packages.lock.json") {
    return (t) => parseNugetLock(t);
  }
  if (/\.(cs|fs|vb)proj$/.test(fileName)) {
    return (t) => parseProjectFile(t);
  }
  if (fileName === "packages.config") {
    return (t) => parsePackagesConfig(t);
  }
  return undefined;
}

export const DEPENDENCY_GLOB =
  "**/{requirements*.txt,package-lock.json,npm-shrinkwrap.json,Gemfile.lock,composer.lock,packages.lock.json,*.csproj,*.fsproj,*.vbproj,packages.config}";

/** Zero-based line where a package is declared in a dependency file, for placing diagnostics. */
export function findLine(text: string, fileName: string, product: string): number {
  const lines = text.split(/\r?\n/);
  const esc = product.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const patterns: RegExp[] = [];
  if (fileName === "package-lock.json" || fileName === "npm-shrinkwrap.json") {
    patterns.push(new RegExp(`"node_modules/${esc}"\\s*:`), new RegExp(`"${esc}"\\s*:`));
  } else if (fileName === "composer.lock") {
    patterns.push(new RegExp(`"name"\\s*:\\s*"${esc}"`, "i"));
  } else if (fileName === "Gemfile.lock") {
    patterns.push(new RegExp(`^ {4}${esc} \\(`));
  } else if (fileName.startsWith("requirements")) {
    // PyPI names are compared normalised: "django-rest" must find "Django_Rest==2.0".
    const loose = product
      .split(/[-_.]+/)
      .map((part) => part.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"))
      .join("[-_.]+");
    patterns.push(new RegExp(`^\\s*${loose}\\s*(\\[|=)`, "i"));
  } else {
    patterns.push(new RegExp(`"${esc}"`, "i"));
  }
  for (const p of patterns) {
    const i = lines.findIndex((l) => p.test(l));
    if (i >= 0) {
      return i;
    }
  }
  return 0;
}
