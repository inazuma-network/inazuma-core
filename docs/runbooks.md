# On-call runbooks

Five scary scenarios, written while calm.

## 1. Chain stall (no new blocks)
1. `curl -s <rpc>/metrics | grep inazuma_block_height` on every node — is it one
   node or all of them?
2. `node harness/forkwatch.mjs --once` for a network-wide view.
3. One node stuck: restart it (`systemctl restart inazuma`); its data dir
   recovers via the journal.
4. All nodes stuck: check `inazuma_halted` — if 1, an operator halted the chain;
   resume with `inaz_resume` (admin key).
5. Still stuck: check whether quorum stake is online (`inaz_validators`). Below
   quorum, bring validators back before anything else.

## 2. Fork detected
1. Confirm with forkwatch (`FINALIZED-FORK` alert, exit code 2).
2. Halt affected nodes immediately: `inaz_halt` with a reason.
3. Capture both branches: `inaz_getBlock` at the divergent height on each side,
   plus logs, before touching data dirs.
4. Pick the branch with the greater finalized weight; wipe and resync the
   minority nodes from a snapshot.
5. Post-mortem before resuming; never resume both branches.

## 3. RPC overload
1. `inaz_rpcLimits` (admin) to see the current tiers.
2. Anonymous flood: tighten the anon rate, or put the public endpoint behind a
   CDN/reverse proxy with per-IP limits.
3. One account flooding the mempool: the per-account 50 tx/s limit already caps
   it; confirm mempool size is draining.

## 4. Disk full on a validator
1. `df -h` — free space now: rotate/compress logs first, they are the usual cause.
2. Prune history: `inaz_prune` (admin) keeps recent blocks only.
3. If the node already died mid-write, restart it — journal replay restores a
   consistent tip. Do not hand-edit the data dir.

## 5. Mempool flood
1. Watch `inazuma_mempool_txs` and `rate(inazuma_txs_total[5m])`.
2. Block production continues by design (fee-ordered mempool, 20k cap,
   64 pending per sender); paying transactions still land.
3. If spam is coming from a handful of peers, ban them via the peer book and
   pin `--peer-ids`.

## Key backups
Validator keys live in `/etc/inazuma/validator.env` (mode 600). Back up the
`inazkey1` string offline; it is the only recovery path. One key, one machine —
running the same key twice is a slashable double-sign.

## Paging setup (do this before you need it)
`harness/forkwatch.mjs` and Alertmanager both page the same on-call sinks:

```
DISCORD_WEBHOOK_URL=...        # or
TELEGRAM_BOT_TOKEN=... TELEGRAM_CHAT_ID=...
ALERT_WEBHOOK_URL=...          # any HTTP endpoint
```
Alertmanager reads the same URLs from `/etc/alertmanager/discord_webhook_slack_url`
and `/etc/alertmanager/generic_webhook_url` (see `ops/alertmanager.yml`).
Verify quarterly with `ALERT_SLA_S=60 harness/fork-drill.sh 4` — it fails if no
alert lands in time.

## 6. Node under resource pressure (disk full / OOM kill)
1. `df -h` and `journalctl -u inazuma -n 50` — look for `no space left` or an
   `oom-kill` line from the kernel.
2. Free space or raise the memory cap, then `systemctl start inazuma`. The journal
   replays to a consistent tip; never hand-edit the data dir.
3. If the height after restart is lower than before the crash, stop and resync
   from a snapshot rather than trusting the local DB.
4. Rehearsed by `harness/resource-limits.sh both` — run it on a spare box before
   trusting this procedure.
