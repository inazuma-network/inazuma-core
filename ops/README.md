# Observability

Every node serves Prometheus metrics at `GET http://<rpc-host>:<rpc-port>/metrics`
(no API key, no peer addresses or node keys — same redaction rule as
`inaz_netInfo` for anonymous callers).

- `prometheus.yml` — scrape config
- `alerts.yml` — chain stall, finality lag, node down, no peers, mempool backlog,
  operator halt, state-root divergence
- `grafana-dashboard.json` — import into Grafana for a network-wide view

Fork detection runs independently of Prometheus:

```bash
NODE_URLS=https://rpc.inazuma.network,https://rpc2... node harness/forkwatch.mjs
```

It exits 2 on a finalized fork, and alerts on stalls, divergent state roots,
lagging nodes and unreachable nodes.

Chaos runs (SIGKILL, freeze, tx bursts, mempool spam, health + fork check after
every fault) against a local devnet:

```bash
harness/devnet.sh 4 && DURATION_S=1800 node harness/chaos.mjs
```
