# Known issues (public testnet)

Published deliberately so testers don't file duplicates. Updated as items close.

## Networking
- **Inbound-only NAT setups**: nodes that cannot dial out and have no port
  forward will not accept inbound peers. Workaround: forward the P2P port, or run
  with `--peers` against public nodes (outbound-only works fine).
- **Peer churn at scale** is untested above a few dozen peers. Report degraded
  block propagation if you see it.
- **Sybil / eclipse hardening** relies on `--peer-ids` pinning today; there is no
  automatic peer-table diversity policy yet.

## Node operation
- **Disk-full and OOM behaviour** is now exercised by `harness/resource-limits.sh`
  (tmpfs filled to 100%, cgroup memory cap): the node stops and the DB reopens
  with state intact. Still give the data dir headroom — a full disk stops the node.
- **Snapshot sync** is in production use, but byte-for-byte equality with a
  genesis sync is not yet asserted by an automated test.
- **DB bit-rot detection** relies on the storage engine's checksums; there is no
  standalone `verify-db` command yet.

## Consensus
- **Long-range attack simulation** (old keys rewriting from genesis) has not been
  run. Weak-subjectivity checkpoints exist but treat deep reorg claims with
  suspicion and report them.
- Reorgs deeper than 5,000 blocks are rejected outright by design.

## Tooling
- Fee estimation is percentile-based on local mempool contents; it can lag during
  sudden bursts.
- WASM contract gas metering boundaries are not fuzzed yet; unexpected
  out-of-gas behaviour is worth a report.

## Monitoring gaps
- Fork detection and paging are live (`harness/forkwatch.mjs`, Alertmanager), and
  drill-verified under 60s. Multi-region gossip at 50-100 nodes is still unproven;
  expect the first real data from the public testnet.

## Reporting
Bugs: GitHub issues on `inazuma-network/inazuma-core` (node) or
`inazuma-network/inazuma-validator` (operator tooling).
Security: private advisories only — see `SECURITY.md`.
