# Mainnet gate: the 7 blocking gaps

One section per gap: the deliverable, the exact command that produces it, and the
condition that makes it DONE. Nothing here is satisfied by code review.

---

## 1. Cross-node safety/fork checker + alert

**Deliverable** `harness/forkwatch.mjs` + `harness/alert.mjs`.
Polls `inaz_chainInfo` on every node every 5s, compares the block hash at the
lowest common **finalized** height and the state root at the common tip, and
pages Discord / Telegram / any webhook the moment two nodes disagree. Exits `2`
on a finalized fork so a supervisor records the failure.

```bash
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/... \
NODE_URLS=http://a:9933,http://b:9933,http://c:9933 \
node harness/forkwatch.mjs
```
Alerts paged: `FINALIZED-FORK`, `state-root-divergence`, `chain-stall`,
`all-nodes-down` (critical); `node-unreachable`, `node-lagging` (warning).
Deduped per kind (`ALERT_COOLDOWN_MS`, default 5m).

**Done when** the drill passes:
```bash
ALERT_SLA_S=60 harness/fork-drill.sh 4
```
It splits a fresh devnet into two halves that build divergent tips, then fails
unless an alert fires inside the SLA. Prints the measured detection time.

## 2. cargo audit in CI

**Deliverable** `audit` job in both pipelines: `inazuma-core/.github/workflows/ci.yml`
and the repo-level `.github/workflows/ci.yml`, `cargo audit --deny warnings`.

**Done when** it runs on every push and PR next to fmt/clippy/test — it does; a
new advisory against a transitive crate turns the build red.

## 3. Byzantine behaviour, real binaries, real network

**Deliverable** a separately built malicious node (`--features byzantine`,
`src/byzantine.rs`) driven by `INAZ_BYZANTINE=double-sign|equivocate|invalid|withhold`.

- local rehearsal: `harness/byzantine.sh double-sign 4`
- live multi-machine: `HONEST="u@a u@b u@c" ADVERSARY=u@d harness/byzantine-remote.sh double-sign`

The remote runner builds the binary, swaps it on the adversary host via systemd,
watches the honest nodes, then restores the honest binary.

**Done when** for each of the four modes on the live multi-region net:
the adversary is jailed/slashed (`inaz_validators`) **and** every honest node's
height strictly increases across the window. The script exits non-zero otherwise.

## 4. Disk-full and OOM

**Deliverable** `harness/resource-limits.sh disk|oom|both` (root).
Disk: data dir on a 24M tmpfs, then filled to 100% with `dd`. OOM: node inside a
cgroup v2 `memory.max` (default 64M) with swap disabled.

**Done when** for both cases the node stops with a clear error and, after the
constraint is lifted, a restart reopens the DB and reports a height **>=** the
last height seen before the failure. The script asserts this (`verify_recovery`)
instead of assuming it.

## 5. Prometheus metrics + alerts

**Deliverable** `/metrics` on the node (`src/metrics.rs`), `ops/prometheus.yml`,
`ops/alerts.yml`, and now `ops/alertmanager.yml` which actually pages.
Exposed at minimum: `inazuma_block_height`, `inazuma_peer_count`,
`inazuma_mempool_txs`, `inazuma_finality_lag_blocks`, `inazuma_halted`,
`inazuma_state_root_info`.

**Done when** killing a node pages `NodeDown` within 1m and stalling the chain
pages `ChainStalled` within 2m, with no dashboard involved. Verify by
`systemctl stop inazuma` on one host and waiting for the message.

## 6. Wire-protocol fuzzing

**Deliverable** `fuzz/` (cargo-fuzz) with three targets against the exact bytes an
unauthenticated peer controls:
- `p2p_wire` — frame bodies and legacy newline JSON (`transport::decode_json`, `decode_line`)
- `p2p_frame` — 4-byte length prefix, asserts no oversized/zero length is accepted
- `tx_decode` — arbitrary JSON -> `Transaction` -> canonical signing bytes

Built with `debug-assertions` and `overflow-checks` on, so an integer overflow is
a crash, not a silent wrap.

```bash
cargo +nightly fuzz run p2p_wire -- -max_total_time=21600 -rss_limit_mb=4096
```
CI: 2 minutes per target on every PR (`fuzz-smoke`), plus `fuzz-soak.yml` nightly
6h per target with a cached, accumulating corpus.

**Done when** the soak has run days-scale with zero crashes/hangs, or every
artifact in `fuzz/artifacts/` is fixed and re-fuzzed clean.

## 7. Known issues + runbooks

**Deliverable** `docs/known-issues.md` (public, honest) and `docs/runbooks.md`
with cold-readable procedures for chain stall, fork detected, RPC overload, disk
full, mempool flood.

**Done when** each operator can execute a runbook without asking anyone. Test it:
one person plays the incident (stop a node / split the net), another follows the
runbook cold with no help.

---

# After the gaps: full reset + real-chain testing

## 1. Wipe to true genesis
```bash
HOSTS="u@fra u@nyc u@sgp u@lon u@tor" harness/testnet-reset.sh
```
Fresh keys, fresh genesis, empty data dirs — nothing inherited. Verifies every
host is producing and peered, then prints the `NODE_URLS` for the watchers.
Each operator does one host following only `inazuma-validator/docs/quickstart.md`;
anywhere someone has to ask a question is a doc bug, fixed before continuing.

## 2. Multi-region, real network
4-5 hosts across 3+ regions, real public IPs, no docker-compose on one box. NAT,
discovery, gossip and latency are only proven here.

## 3. Live chaos + adversarial
```bash
node harness/chaos.mjs --kill --freeze          # SIGKILL / SIGSTOP mid-round
harness/byzantine-remote.sh double-sign         # then equivocate, invalid, withhold
harness/resource-limits.sh both                 # on one real node, mid-run
```
Partition with firewall rules between regions for 10-15 minutes, then unblock and
confirm the chain heals to one tip.

## 4. Sustained real load, external client
```bash
NODE_URLS=http://a:9933,http://b:9933,http://c:9933 WALLETS=1000 node harness/load.mjs
```
and the existing 72h soak engine (one cron tick per minute against the same net,
`/api/public/soak/tick`) left running uninterrupted for the full window.
Plus deliberate double-spends, replays and malformed txs from an external client
(`harness/byzcheck.mjs`), never from in-process test code. The 72h run must end
with a written pass/fail report, not a burst number.

## 5. Watchers on the whole run
forkwatch + Prometheus/Alertmanager stay up for the entire cycle. If they page
correctly during real chaos they are validated; if they miss anything, that is a
second bug found.

## 6. Only then
Invite the 10-20 outside operators, with monitoring and runbooks already proven
against real conditions.
