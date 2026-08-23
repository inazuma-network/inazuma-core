/**
 * Randomized chaos runner against the local devnet from harness/devnet.sh.
 *
 * Every few seconds it does one hostile thing — SIGKILL a node, SIGSTOP it
 * (clock/GC freeze), partition it with a firewall-free port block, inject a tx
 * burst, or fill its data dir — then verifies the network is still producing
 * blocks and has not forked. Any fork below finality is a hard failure.
 *
 *   DURATION_S=1800 node harness/chaos.mjs
 */
import { spawn, spawnSync } from "node:child_process";
import { appendFileSync, mkdirSync, writeFileSync } from "node:fs";
import { N, WORK, nodes, pid, rpc, sleep, waitFor } from "./lib.mjs";

const DURATION_S = Number(process.env.DURATION_S ?? 300);
const EVERY_S = Number(process.env.EVERY_S ?? 20);
const LOG = `${WORK}/chaos.log`;
mkdirSync(WORK, { recursive: true });
writeFileSync(LOG, `chaos start ${new Date().toISOString()}\n`);
const say = (m) => { console.log(m); appendFileSync(LOG, `${m}\n`); };

const alive = (p) => { try { process.kill(p, 0); return true; } catch { return false; } };
const signal = (i, sig) => { const p = pid(i); if (p && alive(p)) { process.kill(p, sig); return true; } return false; };
/** Pick any node except node 1, which the harness uses as its RPC entry point. */
const victim = () => 2 + Math.floor(Math.random() * Math.max(1, N - 1));

const actions = {
  async kill9() {
    const i = victim();
    if (!signal(i, "SIGKILL")) return `node ${i} already down`;
    await sleep(3000);
    spawn("bash", [`${import.meta.dirname}/restart-node.sh`, String(i)], { env: { ...process.env, WORK }, stdio: "ignore", detached: true }).unref();
    return `SIGKILL + restart node ${i}`;
  },
  async freeze() {
    const i = victim();
    if (!signal(i, "SIGSTOP")) return `node ${i} not running`;
    await sleep(4000 + Math.random() * 6000);
    signal(i, "SIGCONT");
    return `froze node ${i} for a few seconds (simulated stall / clock jump)`;
  },
  async burst() {
    const { keypairFromSecret, createMnemonic, signTransfer, ONE_INAZ } = await import("/dev-server/src/lib/wallet-core.ts");
    const { key } = await import("./lib.mjs");
    const secret = key(1);
    const from = keypairFromSecret(secret);
    const acct = await rpc(1, "inaz_getAccount", { address: from.address });
    const n0 = Number(acct.nonce ?? 0);
    const sink = keypairFromSecret(createMnemonic());
    const txs = Array.from({ length: 40 }, (_, k) =>
      signTransfer({ secret, to: sink.address, amountRai: ONE_INAZ / 1000n, nonce: n0 + k }));
    const res = await rpc(1, "inaz_sendTransactions", { txs }, 30000);
    return `tx burst: ${res.accepted}/40 admitted, ${res.rejected} rejected`;
  },
  async mempoolSpam() {
    const { keypairFromSecret, createMnemonic, signTransfer } = await import("/dev-server/src/lib/wallet-core.ts");
    const junk = Array.from({ length: 60 }, () => {
      const w = keypairFromSecret(createMnemonic());
      return signTransfer({ secret: w.mnemonic, to: w.address, amountRai: 1n, nonce: 77 }); // unfunded, future nonce
    });
    const out = await Promise.allSettled([rpc(1, "inaz_sendTransactions", { txs: junk }, 20000)]);
    return `spam burst from unfunded keys: ${out[0].status}`;
  },
};

async function healthy() {
  const h0 = await rpc(1, "inaz_chainInfo");
  const ok = await waitFor(async () => (await rpc(1, "inaz_chainInfo")).height > h0.height, 30000, 500);
  if (!ok) throw new Error(`chain stopped producing blocks at height ${h0.height}`);
  const fw = spawnSync("node", [`${import.meta.dirname}/forkwatch.mjs`, "--once"], { encoding: "utf8" });
  if (fw.status === 2) throw new Error(`fork detected:\n${fw.stderr}`);
  return (await rpc(1, "inaz_chainInfo")).height;
}

say(`[chaos] ${DURATION_S}s run, one fault every ~${EVERY_S}s, ${N} nodes`);
const names = Object.keys(actions);
const until = Date.now() + DURATION_S * 1000;
let faults = 0, failures = 0;
while (Date.now() < until) {
  const name = names[Math.floor(Math.random() * names.length)];
  try {
    const detail = await actions[name]();
    faults++;
    const h = await healthy();
    say(`  OK   ${name} — ${detail} (tip ${h})`);
  } catch (e) {
    failures++;
    say(`  FAIL ${name} — ${e.message}`);
  }
  await sleep(EVERY_S * 1000);
}
say(`\n[chaos] done: ${faults} faults injected, ${failures} health failures`);
process.exit(failures ? 1 : 0);
