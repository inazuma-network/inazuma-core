/** Shared helpers for the Inazuma testnet-readiness harness. */
import { readFileSync, existsSync } from "node:fs";
export const WORK = process.env.WORK ?? "/tmp/devnet";
// Point the same harness at a real multi-region net:
//   NODE_URLS=http://a:9933,http://b:9933 node harness/load.mjs
const REMOTE = (process.env.NODE_URLS ?? "").split(",").map((s) => s.trim()).filter(Boolean);
export const N = Number(process.env.NODES ?? (REMOTE.length || 4));
export const rpcUrl = (i) => REMOTE[(i - 1) % REMOTE.length] ?? `http://127.0.0.1:${19330 + i}`;
export const nodes = () => Array.from({ length: N }, (_, k) => k + 1);

export const key = (i) => readFileSync(`${WORK}/n${i}.key`, "utf8").trim();
export const addr = (i) => readFileSync(`${WORK}/n${i}.addr`, "utf8").trim();
export const pid = (i) =>
  existsSync(`${WORK}/n${i}.pid`) ? Number(readFileSync(`${WORK}/n${i}.pid`, "utf8").trim()) : 0;

export const ADMIN_KEY = process.env.HARNESS_ADMIN_KEY ?? "harness-admin-key-0123456789";

export async function rpc(i, method, params = {}, timeout = 15000) {
  const res = await fetch(rpcUrl(i), {
    method: "POST",
    headers: { "content-type": "application/json", "x-api-key": ADMIN_KEY },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
    signal: AbortSignal.timeout(timeout),
  });
  const j = await res.json();
  if (j.error) throw new Error(`${method}: ${j.error.message ?? JSON.stringify(j.error)}`);
  return j.result;
}
export const raw = (i, body, headers = {}) =>
  fetch(rpcUrl(i), {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body,
    signal: AbortSignal.timeout(10000),
  });

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
export async function waitFor(fn, ms = 60000, every = 500) {
  const until = Date.now() + ms;
  for (;;) {
    try {
      if (await fn()) return true;
    } catch {}
    if (Date.now() > until) return false;
    await sleep(every);
  }
}
export async function height(i) {
  return (await rpc(i, "inaz_chainInfo")).height;
}

/* ---------- result collection ---------- */
export const results = [];
export async function check(section, name, fn) {
  const t0 = Date.now();
  try {
    const detail = await fn();
    results.push({ section, name, pass: true, detail: detail ?? "", ms: Date.now() - t0 });
    console.log(`  PASS  ${name}${detail ? ` — ${detail}` : ""}`);
    return true;
  } catch (e) {
    results.push({ section, name, pass: false, detail: String(e.message ?? e), ms: Date.now() - t0 });
    console.log(`  FAIL  ${name} — ${e.message ?? e}`);
    return false;
  }
}
export function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}
export function summary(label) {
  const pass = results.filter((r) => r.pass).length;
  console.log(`\n== ${label}: ${pass}/${results.length} passed ==`);
  for (const r of results.filter((x) => !x.pass)) console.log(`   ! ${r.section} / ${r.name}: ${r.detail}`);
  return { pass, total: results.length, results };
}
