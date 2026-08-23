/**
 * Fork / anomaly detection bot.
 *
 * Continuously compares chain identity across every node it is given, pages the
 * on-call sinks (Discord / Telegram / generic webhook — see harness/alert.mjs)
 * and exits non-zero the moment two nodes disagree below finality — the one
 * invariant a public testnet must never break. Safe to run as a systemd service:
 *   NODE_URLS=https://a:9933,https://b:9933 \
 *   DISCORD_WEBHOOK_URL=... node harness/forkwatch.mjs
 */
import { page, alertSinks } from "./alert.mjs";

const URLS = (process.env.NODE_URLS ?? "http://127.0.0.1:19331,http://127.0.0.1:19332,http://127.0.0.1:19333,http://127.0.0.1:19334")
  .split(",").map((s) => s.trim()).filter(Boolean);
const EVERY_MS = Number(process.env.INTERVAL_MS ?? 5000);
const STALL_MS = Number(process.env.STALL_MS ?? 60000);
const ONCE = process.argv.includes("--once");


const call = async (url, method, params = {}) => {
  const r = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
    signal: AbortSignal.timeout(8000),
  });
  const j = await r.json();
  if (j.error) throw new Error(j.error.message ?? "rpc error");
  return j.result;
};
const blockAt = (url, height) => call(url, "inaz_getBlock", { height });

const alerts = [];
const COOLDOWN_MS = Number(process.env.ALERT_COOLDOWN_MS ?? 300_000);
const lastPaged = new Map();
const CRITICAL = new Set(["FINALIZED-FORK", "state-root-divergence", "chain-stall", "all-nodes-down"]);

const alert = (kind, detail) => {
  const line = `[ALERT] ${new Date().toISOString()} ${kind} — ${detail}`;
  console.error(line);
  alerts.push({ kind, detail, at: Date.now() });
  // Page immediately, deduped per kind so a persistent fault doesn't spam.
  const last = lastPaged.get(kind) ?? 0;
  if (Date.now() - last >= COOLDOWN_MS) {
    lastPaged.set(kind, Date.now());
    void page(kind, `${detail}\nnodes: ${URLS.join(", ")}`, CRITICAL.has(kind) ? "critical" : "warning");
  }
};


let lastProgress = Date.now();
let lastMaxHeight = -1;

async function tick() {
  const infos = await Promise.allSettled(URLS.map((u) => call(u, "inaz_chainInfo")));
  const live = infos.map((r, i) => ({ url: URLS[i], info: r.status === "fulfilled" ? r.value : null }));
  const up = live.filter((n) => n.info);
  if (up.length === 0) return alert("all-nodes-down", "no node answered inaz_chainInfo");
  for (const n of live.filter((x) => !x.info)) alert("node-unreachable", n.url);

  const maxH = Math.max(...up.map((n) => Number(n.info.height)));
  if (maxH > lastMaxHeight) { lastMaxHeight = maxH; lastProgress = Date.now(); }
  else if (Date.now() - lastProgress > STALL_MS) alert("chain-stall", `no new block for ${((Date.now() - lastProgress) / 1000) | 0}s at height ${maxH}`);

  // Safety: compare the block hash all nodes have at the lowest common
  // finalized height. Disagreement there is a finalized fork, the worst case.
  const finalized = Math.min(...up.map((n) => Number(n.info.finalizedHeight ?? 0)));
  if (finalized > 0) {
    const blocks = await Promise.allSettled(up.map((n) => blockAt(n.url, finalized)));
    const hashes = new Map();
    blocks.forEach((b, i) => {
      if (b.status !== "fulfilled" || !b.value) return;
      const h = b.value.hash ?? b.value.blockHash;
      if (!hashes.has(h)) hashes.set(h, []);
      hashes.get(h).push(up[i].url);
    });
    if (hashes.size > 1) {
      alert("FINALIZED-FORK", `height ${finalized}: ${[...hashes.entries()].map(([h, u]) => `${String(h).slice(0, 12)}=${u.length}`).join(" vs ")}`);
      return "fatal";
    }
  }

  // Liveness/consistency: state roots at the lowest common tip.
  const common = Math.min(...up.map((n) => Number(n.info.height)));
  const roots = new Set();
  for (const n of up) {
    const b = await blockAt(n.url, common).catch(() => null);
    if (b) roots.add(b.stateRoot ?? b.state_root ?? "?");
  }
  if (roots.size > 1) alert("state-root-divergence", `height ${common}: ${roots.size} distinct roots`);

  const lag = maxH - Math.min(...up.map((n) => Number(n.info.height)));
  if (lag > 200) alert("node-lagging", `spread of ${lag} blocks across ${up.length} nodes`);
  console.log(`ok  h=${maxH} finalized=${finalized} nodes=${up.length}/${URLS.length} spread=${lag} mempool=${up[0].info.mempool}`);
  return null;
}

const sinks = alertSinks();
console.log(
  `[forkwatch] watching ${URLS.length} nodes every ${EVERY_MS}ms — paging: ${sinks.length ? sinks.join("+") : "NONE (log only)"}`,
);
for (;;) {
  const fatal = await tick().catch((e) => { alert("watcher-error", e.message); return null; });
  if (fatal === "fatal") { await new Promise((r) => setTimeout(r, 1500)); process.exit(2); }
  if (ONCE) break;

  await new Promise((r) => setTimeout(r, EVERY_MS));
}
process.exit(alerts.some((a) => a.kind === "FINALIZED-FORK") ? 2 : 0);
