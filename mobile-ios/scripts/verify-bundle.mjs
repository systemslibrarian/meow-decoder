#!/usr/bin/env node
// verify-bundle.mjs — every <script src>, <link href>, <img src>, <source src>,
// and dynamic import("...") in dist/index.html must resolve to a real file
// inside dist/. Catches the case where build-web.sh forgot to copy a JS or
// asset, which would only show as a broken QR or blank page on the device.

import { readFileSync, existsSync, statSync } from "node:fs";
import { resolve, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const dist = resolve(here, "..", "dist");
const indexPath = join(dist, "index.html");

if (!existsSync(indexPath)) {
    console.error(`verify-bundle: ${indexPath} missing — run build:native first`);
    process.exit(1);
}

const html = readFileSync(indexPath, "utf8");

const refs = [];
const patterns = [
    /<script\s[^>]*src=["']([^"']+)["']/gi,
    /<link\s[^>]*href=["']([^"']+)["']/gi,
    /<img\s[^>]*src=["']([^"']+)["']/gi,
    /<source\s[^>]*src=["']([^"']+)["']/gi,
    /\bimport\(\s*["']([^"']+)["']\s*\)/g,
];
for (const re of patterns) {
    let m;
    while ((m = re.exec(html)) !== null) refs.push(m[1]);
}

const isLocal = (p) =>
    !p.startsWith("http://") &&
    !p.startsWith("https://") &&
    !p.startsWith("data:") &&
    !p.startsWith("//") &&
    !p.startsWith("#") &&
    !p.startsWith("javascript:") &&
    !p.startsWith("blob:") &&
    // Skip JS template-literal placeholders that appear inside string
    // expressions like `<img src='${url}'>` — those are runtime values,
    // not static asset references.
    !p.includes("${");

const missing = [];
const checked = new Set();
for (const raw of refs) {
    if (!isLocal(raw)) continue;
    const clean = raw.split(/[?#]/)[0];
    if (checked.has(clean)) continue;
    checked.add(clean);
    const fp = clean.startsWith("/") ? join(dist, clean) : join(dist, clean);
    if (!existsSync(fp) || !statSync(fp).isFile()) missing.push(clean);
}

if (missing.length) {
    console.error(`verify-bundle: ${missing.length} unresolved reference(s) in dist/index.html:`);
    for (const m of missing) console.error(`  - ${m}`);
    process.exit(1);
}

console.log(`verify-bundle: ${checked.size} local references all resolve`);
