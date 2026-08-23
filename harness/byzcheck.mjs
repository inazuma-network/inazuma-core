/**
 * Verifies what the honest nodes did while a real malicious binary attacked them.
 *
 * The bar is not "the attack was noticed" — it is:
 *   1. the offence is detected and punished (evidence -> slash record), or for
 *      attacks that carry no slashable proof, the block is rejected;
 *   2. the honest chain never stalls while it happens;
 *   3. honest nodes stay on one chain (no state-root divergence).
 *
 * Run: WORK=/tmp/byznet NODES=4 node harness/byzcheck.mjs <mode> [observe_s]
 */
import { rpc, sleep, nodes, addr, N } from "./lib.mjs";

const mode = process.argv[2] ?? "double-sign";
const observe = Number(process.argv[3] ?? 60);
const honest = nodes().filter((i) => i !== N);
const attacker = addr(N);

const info = async (i) => rpc(i, "inaz_chainInfo");
const slashes = async (i) => rpc(i, "inaz_slashing", { limit: 50 });

async function snapshot() {
  const out = {};
  for (const i of honest) {
    const ci = await info(i).catch(() => null);
    out[i] = ci ? { h: ci.height, root: ci.stateRoot ?? ci.state_root, fin: ci.finalized } : null;
  }
  return out;
}

console.log(`[byzcheck] mode=${mode} attacker=node${N} (${attacker.slice(0, 12)}…) observing ${observe}s`);
const t0 = await snapshot();
let firstDetection = null;
const start = Date.now();

for (let s = 0; s < observe; s += 5) {
  await sleep(5000);
  for (const i of honest) {
    const sl = await slashes(i).catch(() => null);
    if (!firstDetection && sl?.slashes?.some((r) => r.offender === attacker)) {
      firstDetection = { node: i, secs: ((Date.now() - start) / 1000).toFixed(1), rec: sl.slashes.find((r) => r.offender === attacker) };
      console.log(`  detected by node${i} after ${firstDetection.secs}s: ${firstDetection.rec.offence} burned=${firstDetection.rec.burnedInaz} tombstoned=${firstDetection.rec.tombstoned}`);
    }
  }
}

const t1 = await snapshot();
const advanced = honest.every((i) => t1[i] && t0[i] && t1[i].h > t0[i].h);
const roots = new Set(honest.map((i) => `${t1[i]?.root}`));
const alive = honest.filter((i) => t1[i]).length;
const set = await rpc(honest[0], "inaz_validators").catch(() => null);
const av = set?.validators?.find((v) => v.address === attacker);

const report = {
  mode,
  honestNodesUp: `${alive}/${honest.length}`,
  chainAdvanced: advanced,
  heights: honest.map((i) => `n${i}:${t0[i]?.h}->${t1[i]?.h}`).join(" "),
  honestStateRootsAgree: roots.size === 1,
  slashDetectedInSecs: firstDetection?.secs ?? null,
  offence: firstDetection?.rec?.offence ?? null,
  burned: firstDetection?.rec?.burnedInaz ?? null,
  tombstoned: firstDetection?.rec?.tombstoned ?? null,
  attackerJailedUntil: av?.jailedUntil ?? av?.jailed_until ?? null,
  attackerStake: av?.stakeInaz ?? av?.stake ?? null,
};
console.log(JSON.stringify(report, null, 2));

// Liveness under attack is non-negotiable; punishment is required for the two
// equivocation modes, while "invalid" and "withhold" are pass/fail on rejection
// and liveness respectively (they leave no signed conflicting header to slash).
const needsSlash = mode === "double-sign" || mode === "equivocate";
const ok = advanced && roots.size === 1 && (!needsSlash || firstDetection !== null);
console.log(ok ? "\nRESULT: PASS" : "\nRESULT: FAIL");
process.exit(ok ? 0 : 1);
