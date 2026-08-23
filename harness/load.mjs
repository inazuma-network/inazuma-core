/**
 * 1,000+ real wallet load test against the local devnet.
 * Every wallet is a genuine ed25519 + ML-DSA-65 Inazuma key signed with the
 * SAME library the web wallet ships (src/lib/wallet-core.ts), so this exercises
 * wallet, SDK, mempool, block production, fees and state accounting together.
 */
import { keypairFromSecret, createMnemonic, signTransfer, ONE_INAZ, MIN_FEE } from "/dev-server/src/lib/wallet-core.ts";
import { addr, assert, check, height, key, rpc, sleep, summary, waitFor } from "./lib.mjs";

const WALLETS = Number(process.env.WALLETS ?? 1000);
const treasurySecret = key(1);
const treasury = keypairFromSecret(treasurySecret);

const chunk = (a, n) => Array.from({ length: Math.ceil(a.length / n) }, (_, i) => a.slice(i * n, i * n + n));
// The node admits at most ACCOUNT_TX_RATE (50) tx/s per sender, so batches are
// paced. Hitting the limit is correct node behaviour, not a harness failure.
const submit = async (txs, perSender = 1) => {
  const out = [];
  const size = 50;
  for (const part of chunk(txs, size)) {
    out.push(await rpc(1, "inaz_sendTransactions", { txs: part }, 60000));
    if (perSender > 1) await sleep(1100);
  }
  return out.flat();
};

console.log(`\n### Load test: ${WALLETS} wallets`);

// --- 1. generate wallets (real keys, real PQ half) ---
let wallets = [];
await check("load", `generates ${WALLETS} independent wallets`, () => {
  wallets = Array.from({ length: WALLETS }, () => keypairFromSecret(createMnemonic()));
  const uniq = new Set(wallets.map((w) => w.address));
  assert(uniq.size === WALLETS, `address collision: ${uniq.size}/${WALLETS}`);
  assert(wallets.every((w) => !w.legacy), "a wallet lacks the post-quantum half");
  return `${uniq.size} unique base58 addresses`;
});

// --- 2. fund them all from the treasury ---
const FUND = 5n * ONE_INAZ;
let startNonce = 0;
await check("load", "funds every wallet from the treasury", async () => {
  const acct = await rpc(1, "inaz_getAccount", { address: treasury.address });
  startNonce = Number(acct.nonce ?? 0);
  const txs = wallets.map((w, i) =>
    signTransfer({ secret: treasurySecret, to: w.address, amountRai: FUND, nonce: startNonce + i }),
  );
  const t0 = Date.now();
  const accepted = await submit(txs, txs.length); // all from one sender
  const ok = await waitFor(async () => {
    const a = await rpc(1, "inaz_getAccount", { address: wallets.at(-1).address });
    return BigInt(a.balance ?? "0") >= FUND;
  }, 180000);
  assert(ok, "funding never settled for the last wallet");
  return `${accepted.length} txs accepted, settled in ${((Date.now() - t0) / 1000).toFixed(1)}s`;
});

await check("load", "every funded wallet is queryable with the exact balance", async () => {
  let bad = 0;
  for (const part of chunk(wallets, 200)) {
    const accs = await Promise.all(part.map((w) => rpc(1, "inaz_getAccount", { address: w.address })));
    bad += accs.filter((a) => BigInt(a.balance ?? "0") !== FUND).length;
  }
  assert(bad === 0, `${bad} wallets have a wrong balance`);
  return `${wallets.length}/${wallets.length} exact`;
});

// --- 3. sustained load: every wallet spends, measured TPS ---
await check("load", "sustained load from all wallets settles exactly", async () => {
  const sink = keypairFromSecret(createMnemonic());
  const amount = ONE_INAZ;
  const txs = wallets.map((w) =>
    signTransfer({ secret: w.mnemonic, to: sink.address, amountRai: amount, nonce: 0 }),
  );
  const h0 = await height(1);
  const t0 = Date.now();
  await submit(txs);
  const ok = await waitFor(async () => {
    const a = await rpc(1, "inaz_getAccount", { address: sink.address });
    return BigInt(a.balance ?? "0") === amount * BigInt(wallets.length);
  }, 240000);
  const secs = (Date.now() - t0) / 1000;
  assert(ok, "sink balance never reached the expected total");
  const h1 = await height(1);
  return `${wallets.length} txs in ${secs.toFixed(1)}s (~${(wallets.length / secs).toFixed(0)} tx/s incl. settlement) over ${h1 - h0} blocks`;
});

// --- 4. conservation of value across the whole run ---
await check("load", "no INAZ created or destroyed beyond fees and rewards", async () => {
  const info = await rpc(1, "inaz_chainInfo");
  assert(BigInt(info.height) > 0n, "chain stalled");
  const balances = [];
  for (const part of chunk(wallets, 200)) {
    const accs = await Promise.all(part.map((w) => rpc(1, "inaz_getAccount", { address: w.address })));
    balances.push(...accs.map((a) => BigInt(a.balance ?? "0")));
  }
  const expected = FUND - ONE_INAZ - MIN_FEE;
  const wrong = balances.filter((b) => b !== expected).length;
  assert(wrong === 0, `${wrong} wallets off the expected remainder ${expected}`);
  return `all wallets hold exactly ${expected} rai after 1 spend + fee`;
});

// --- 5. mempool flood: cheap spam must not stall block production ---
await check("load", "mempool survives a spam burst and keeps producing blocks", async () => {
  const spam = wallets.slice(0, 300).map((w) =>
    signTransfer({ secret: w.mnemonic, to: treasury.address, amountRai: 1n, nonce: 99 }), // future nonces
  );
  const h0 = await height(1);
  await Promise.allSettled(chunk(spam, 100).map((p) => rpc(1, "inaz_sendTransactions", { txs: p }, 30000)));
  await sleep(4000);
  const h1 = await height(1);
  assert(h1 > h0, "block production stopped during the flood");
  const info = await rpc(1, "inaz_chainInfo");
  assert(!info.halted, "node halted under load");
  return `+${h1 - h0} blocks during flood, mempool=${info.mempool}`;
});

// --- 6. double spend from the same wallet ---
await check("load", "double spend with a reused nonce is rejected", async () => {
  const w = wallets[0];
  const a = await rpc(1, "inaz_getAccount", { address: w.address });
  const n = Number(a.nonce ?? 0);
  const t1 = signTransfer({ secret: w.mnemonic, to: treasury.address, amountRai: ONE_INAZ / 2n, nonce: n });
  const t2 = signTransfer({ secret: w.mnemonic, to: addr(2), amountRai: ONE_INAZ / 2n, nonce: n });
  await rpc(1, "inaz_sendTransaction", { tx: t1 });
  let second = "accepted";
  try {
    await rpc(1, "inaz_sendTransaction", { tx: t2 });
  } catch (e) {
    second = e.message;
  }
  await waitFor(async () => Number((await rpc(1, "inaz_getAccount", { address: w.address })).nonce) === n + 1, 30000);
  const after = await rpc(1, "inaz_getAccount", { address: w.address });
  assert(Number(after.nonce) === n + 1, `nonce advanced twice: ${after.nonce}`);
  return `only one spend applied (second: ${second.slice(0, 60)})`;
});

summary(`load ${WALLETS} wallets`);
process.exit(0);
