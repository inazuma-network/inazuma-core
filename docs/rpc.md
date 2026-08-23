# JSON-RPC & WebSocket API

Endpoint: `POST https://rpc.inazuma.network` (JSON-RPC 2.0). CORS is open. All amounts
are strings so JavaScript never loses precision. `GET /health` returns `{ ok, height }`.

```bash
curl -s https://rpc.inazuma.network \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"inaz_chainInfo","params":{}}'
```

## Chain & blocks

| Method | Params | Returns |
| --- | --- | --- |
| `inaz_chainInfo` | — | chain id, height, supply, staked, mempool, producer |
| `inaz_blockNumber` | — | tip height |
| `inaz_getBlockByNumber` | `{ height }` | block with transactions |
| `inaz_latestBlocks` | `{ limit }` | newest blocks first |
| `inaz_nodeStatus` | — | role (validator/replica), sync state, lag |
| `inaz_netInfo` | — | node key, peers, whether channels are encrypted |

## Accounts & transactions

| Method | Params | Returns |
| --- | --- | --- |
| `inaz_getAccount` / `inaz_getBalance` | `{ address }` | balance, staked, nonce, pendingNonce |
| `inaz_getTransaction` | `{ hash }` | transaction + block reference |
| `inaz_sendTransaction` | `{ tx }` | `{ hash, status }` |
| `inaz_signatureStatuses` | `{ signatures: [...] }` | per-hash confirmation state |
| `inaz_simulateTransaction` | `{ tx }` | `ok`, `signatureValid`, `expectedNonce`, `feeFloor`, `totalDebit`, `balanceAfter` |
| `inaz_priorityFee` | — | current fee floor and suggested priority fee |

## Tokens

`inaz_tokens`, `inaz_getToken` (with top holders), `inaz_tokenBalance`,
`inaz_tokenHoldings`.

## Staking & slashing

`inaz_validators`, `inaz_slashing`, `inaz_previewSlash`, `inaz_reportEquivocation`.

## State proofs

The state is a sparse Merkle tree (depth 128) from block **200,000**, so a light client
can verify a balance without trusting the node that served it.

| Method | Params | Returns |
| --- | --- | --- |
| `inaz_getProof` | `{ address, height? }` | value + sibling path + state root |
| `inaz_verifyProof` | `{ proof }` | `{ valid }` |

## WebSocket subscriptions

Polling makes a fast chain feel slow. Connect to `wss://rpc.inazuma.network:9955` and
subscribe; one socket carries every subscription plus ordinary JSON-RPC. Limit is 64
subscriptions per connection. Slow consumers are dropped rather than waited on, so no
client can slow down block production.

```json
{"jsonrpc":"2.0","id":1,"method":"inaz_subscribe",
 "params":{"channel":"account","address":"<ADDRESS>"}}
```

Channels: `heads`, `finality`, `mempool`, `signature`, `account`, `logs`.
Unsubscribe with `inaz_unsubscribe` and the returned id.

## Rate limits

| Tier | Budget | How |
| --- | --- | --- |
| Anonymous | 25 req/s per IP, burst 100 | no header |
| Key | 300 req/s on its own budget | `Authorization: Bearer <KEY>` or `x-api-key` |
| Stake-weighted key | up to 8× base, by share of bonded stake | key bound to a staked account |
| Admin | operator methods | admin key |

Cost is weighted per method: a state proof counts 5, a 5,000-transaction batch counts
100. Transaction admission is additionally throttled per signing account (50 tx/s, 64
pending), so one account cannot flood the mempool from a thousand IPs. Connections cap
at 32 per host and 512 in total. Call `inaz_rpcLimits` to read your own budget.

## Transaction format

Signed over canonical bytes, never over JSON:

```
inazuma-tx|<chainId>|<kind>|<fromPubkey>|<to>|<amount>|<fee>|<nonce>
```

`kind` is one of `transfer`, `stake`, `unstake`, `token-create`, `token-send`,
`token-mint`, `token-burn`.

## Monitoring endpoints

Both are plain `GET`, no API key, and never expose peer addresses or node keys.

| Path | Returns |
| --- | --- |
| `/health` | `{"ok":true,"height":<n>}` — liveness probe |
| `/metrics` | Prometheus text format: height, finalized height, finality lag, peers, mempool, validators, accounts, tx counter, tokens, contracts, pruned floor, halted flag, base fee, supply, total staked, plus `inazuma_state_root_info{height,state_root,tip_hash,chain_id}` for cross-node fork detection |

Scrape config, alert rules and a Grafana dashboard live in `ops/`.
